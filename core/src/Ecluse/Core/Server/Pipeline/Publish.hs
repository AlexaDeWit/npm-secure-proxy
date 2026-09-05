-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The serve path behind the first-party publish route: @PUT \/{pkg}@.

The publish flow runs in order:

* validate edge authentication
* apply the anti-shadowing first-party guard, so the package name is one this deployment owns
* bound the request body at the per-request size cap
* check body-name agreement between the URL path and the publish document
* relay the request to the upstream publication target with the publisher's credential

A declared over-cap length fails closed up front, and a counted read bounds a chunked
body. Both answer @413@.
-}
module Ecluse.Core.Server.Pipeline.Publish (
    PublishReplies (..),

    -- * The first-party publish handler
    servePublish,
) where

import Data.ByteString.Lazy qualified as LBS

import Network.HTTP.Types (ResponseHeaders, Status, mkStatus, status401, status403, status405, status413, status500, status502)
import Network.Wai (Request, RequestBodyLength (ChunkedBody, KnownLength), ResponseReceived, getRequestBodyChunk, requestBodyLength)

import Ecluse.Core.Credential (ClientCredential, bareCredential)
import Ecluse.Core.Package (PackageName, renderPackageName)
import Ecluse.Core.Registry (FetchFault (FetchBoundExceeded, FetchTransport, FetchUrlUnformable), PublishRelayResponse (PublishRelayResponse))
import Ecluse.Core.Registry.Adapter.Capability (AdapterPublish (publishDeclaredNames, publishRelay))
import Ecluse.Core.Registry.Origin (originClient)
import Ecluse.Core.Security (Limits (maxBodyBytes), boundedRead)
import Ecluse.Core.Server.Admission.Bytes (withByteAdmission)
import Ecluse.Core.Server.Context (
    Handler,
    MountBinding (bindingPublishDeps),
    PublishDeps (..),
    ServeRuntime (srMetrics, srPrivateManager),
    ctxMount,
    ctxRuntime,
 )
import Ecluse.Core.Server.Pipeline.Shared
import Ecluse.Core.Server.Response (appendHelp)

{- | The route-owned ways the publish pipeline may answer. The configured target may
return any status, so npm supplies these constructors from an explicit OpenAPI @default@
contract whose media type stays @application/json@.
-}
data PublishReplies response = PublishReplies
    { publishRelayed :: Status -> ResponseHeaders -> LByteString -> response
    -- ^ Relay the publication target's status and bytes.
    , publishError :: Status -> ResponseHeaders -> Text -> response
    -- ^ Emit an ecosystem-shaped local error.
    }

servePublish ::
    PublishReplies response ->
    PackageName ->
    Request ->
    (response -> IO ResponseReceived) ->
    Handler ResponseReceived
servePublish replies name request respond = do
    mount <- asks ctxMount
    case bindingPublishDeps mount of
        Nothing -> liftIO (respond (publishDisabled replies))
        Just deps -> publishWithDeps replies deps (forwardedCredential mount request) name request respond

-- The edge gate, the anti-shadowing first-party guard, and the body-name agreement check all run
-- before any write. The relay then carries the publisher's forwarded credential.
publishWithDeps ::
    PublishReplies response ->
    PublishDeps ->
    Maybe ClientCredential ->
    PackageName ->
    Request ->
    (response -> IO ResponseReceived) ->
    Handler ResponseReceived
publishWithDeps replies deps clientToken name request respond
    | not (edgeTokenMatches (pubInboundToken deps) clientToken) =
        liftIO (respond (publishError replies status401 [] unauthorisedMessage))
    | not (pubAllowed deps name) =
        liftIO (respond (outOfScope replies deps name))
    | overDeclaredCap =
        -- A declared Content-Length over the cap fails closed before a byte is read, with no
        -- reservation and no relay. A chunked body declares none, so the counted read caps it.
        liftIO (respond (publishTooLarge replies deps))
    | otherwise = do
        rt <- asks ctxRuntime
        -- The admission is acquired only after the edge gate and the first-party guard admitted
        -- the request, so a refused publish reserves nothing. The weight is the declared
        -- Content-Length, and a chunked body reserves the per-request cap pessimistically.
        outcome <- withByteAdmission (srMetrics rt) (pubBodyBudget deps) bodyWeight $ do
            -- 'boundedRead' caps this counted read and returns the breach as a value: a
            -- fail-closed 413, never a truncated body and never a throw across the perimeter.
            liftIO (boundedRead requestBodyLimits (getRequestBodyChunk request)) >>= \case
                -- 'boundedRead' reports only 'BodyTooLarge', so any breach of the
                -- request cap is the 413.
                Left _ -> pure (publishTooLarge replies deps)
                -- The body-name agreement leg of the anti-shadowing guard. A crafted body could
                -- otherwise write a name the guard never saw. Refuse before the relay.
                Right body -> case bodyNameDisagreement (publishDeclaredNames (pubAdapter deps)) (pubProjectName deps) name (LBS.fromStrict body) of
                    Just declared -> pure (bodyNameMismatch replies deps name declared)
                    -- The relay reports failures as the typed 'FetchFault' value, so the
                    -- render below is total and nothing is caught here.
                    Nothing ->
                        renderRelay replies deps
                            <$> liftIO (publishRelay (pubAdapter deps) (publicationTarget rt) name body)
        liftIO (respond (fromMaybe (bodyBudgetShed replies deps) outcome))
  where
    -- The publication target as one origin. The posture is passthrough: the publisher's own
    -- token rides, and the static fallback applies only when the client presented none.
    publicationTarget rt =
        originClient
            (pubLimits deps)
            (srPrivateManager rt)
            (pubTargetUrl deps)
            (clientToken <|> (bareCredential <$> pubStaticToken deps))

    -- The per-request body cap as a 'boundedRead' bound. 'boundedRead' consults only
    -- 'maxBodyBytes', so the response budget's other 'Limits' fields do not matter here.
    requestBodyLimits = (pubLimits deps){maxBodyBytes = pubMaxRequestBytes deps}

    -- Whether the request declares a Content-Length already over the per-request cap.
    overDeclaredCap = case requestBodyLength request of
        KnownLength n -> n > fromIntegral (pubMaxRequestBytes deps)
        ChunkedBody -> False

    bodyWeight = case requestBodyLength request of
        KnownLength n -> fromIntegral n
        ChunkedBody -> pubMaxRequestBytes deps

{- Render the relay outcome. On success the publisher sees the publication target's own
status and body, so the registry's own @409@ or @403@ reaches the client unchanged. -}
renderRelay ::
    PublishReplies response ->
    PublishDeps ->
    Either FetchFault PublishRelayResponse ->
    response
renderRelay replies deps = \case
    Right (PublishRelayResponse code relayed) ->
        publishRelayed replies (mkStatus code "") [] relayed
    -- An unformable target URL is this proxy's own misconfiguration, so it answers 500. The
    -- other two are the target's failure to answer, so they answer 502.
    Left (FetchUrlUnformable _urlErr) ->
        publishError replies status500 [] (appendHelp (pubHelp deps) "the publication target URL is misconfigured")
    Left (FetchTransport _fault) ->
        publishError replies status502 [] (appendHelp (pubHelp deps) "the publication target could not be reached")
    Left (FetchBoundExceeded _limit) ->
        publishError replies status502 [] (appendHelp (pubHelp deps) "the publication target could not be reached")

-- A @503@ for a publish shed at the aggregate body-byte budget: server capacity, not client
-- rate, so not a @429@. Same wait-then-shed timing and @Retry-After@ hint as the read path.
bodyBudgetShed :: PublishReplies response -> PublishDeps -> response
bodyBudgetShed replies deps =
    publishError replies shedStatus [shedRetryAfter] (appendHelp (pubHelp deps) "the server is at its publish-body capacity; retry shortly")

-- A @413@ for a publish body over the per-request size cap ('pubMaxRequestBytes', the
-- client-to-proxy request-body limit). The refusal happens before any upstream write.
publishTooLarge :: PublishReplies response -> PublishDeps -> response
publishTooLarge replies deps =
    publishError replies status413 [] (appendHelp (pubHelp deps) "the publish body exceeds the maximum accepted request size")

-- A @405@ for a publish on a mount with no publication target configured. The @Allow@
-- header advertises the read methods the package route does serve.
publishDisabled :: PublishReplies response -> response
publishDisabled replies =
    publishError replies status405 [("Allow", "GET, HEAD")] message
  where
    -- The remediation stays ecosystem-neutral, because this pipeline serves every
    -- ecosystem: it names no client's own commands or configuration keys.
    message :: Text
    message =
        "publishing is not enabled on this proxy (no publication target is configured); \
        \publish directly to the registry you intend to publish to"

-- A @403@ for a publish whose name is outside the mount's first-party namespaces: the
-- anti-shadowing guard, refused before any upstream write.
outOfScope :: PublishReplies response -> PublishDeps -> PackageName -> response
outOfScope replies deps name =
    publishError replies status403 [] (appendHelp (pubHelp deps) message)
  where
    message :: Text
    message =
        "refusing to publish '"
            <> renderPackageName name
            <> "': its name is outside the first-party namespaces this deployment declares (the anti-shadowing guard against publishing a name that shadows a public package)"

-- A @403@ for a publish whose body declares a package name that disagrees with the requested
-- name the first-party guard authorised, refused before any upstream write.
bodyNameMismatch :: PublishReplies response -> PublishDeps -> PackageName -> Text -> response
bodyNameMismatch replies deps name declared =
    publishError replies status403 [] (appendHelp (pubHelp deps) message)
  where
    message :: Text
    message =
        "refusing to publish '"
            <> renderPackageName name
            <> "': the document body declares the name '"
            <> declared
            <> "', which disagrees with the requested package name the first-party guard authorised (the anti-shadowing guard against publishing a name the guard never saw)"

{- The first declared body name that disagrees with the URL-path name. A relay keyed off the
body could otherwise write a name the scope guard never authorised. Each declared name is
canonicalised and compared by 'PackageName' equality, so an encoding variant cannot disagree
silently. An absent name is not a claim and not a disagreement, so the target's own
validation decides. -}
bodyNameDisagreement :: (LByteString -> [Text]) -> (Text -> Maybe PackageName) -> PackageName -> LByteString -> Maybe Text
bodyNameDisagreement declaredNames canonicalise name body =
    find disagrees (declaredNames body)
  where
    disagrees :: Text -> Bool
    disagrees declared = case canonicalise declared of
        Just declaredName -> declaredName /= name
        Nothing -> True
