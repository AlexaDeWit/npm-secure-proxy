-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

-- | HTTP request shaping and streaming response classification for artifact handlers.
module Ecluse.Core.Server.Pipeline.Tarball.Relay (
    -- * Serve mode
    ArtifactServe (..),

    -- * Shaping the upstream artifact request
    withMethod,
    withValidators,

    -- * Relaying the upstream response
    relayUpstreamWhen,
    acceptArtifact,
    relayUnjudged,
    relayJudged,

    -- * Judging the public relay
    RelayVerdict (..),
    relayVerdict,
    observeRelayAnomaly,
) where

import Network.HTTP.Client (Manager)
import Network.HTTP.Client qualified as HTTP
import Network.HTTP.Types (RequestHeaders, ResponseHeaders, Status, hContentType, methodHead, statusCode, statusIsSuccessful)

import Data.ByteString qualified as BS
import Ecluse.Core.Package (PackageName, renderPackageName)
import Ecluse.Core.Server.Conditional (isNotModified)
import Ecluse.Core.Server.Stream (RelayResponder, UpstreamBody (NoBody, StreamBody), withUpstreamWhen)
import Ecluse.Core.Telemetry.Metrics qualified as Metric
import Ecluse.Core.Telemetry.Record (MetricsPort (mpPublicRelayAnomaly))
import Ecluse.Core.Version (Version, renderVersion)
import Katip (KatipContext, Severity (WarningS), katipAddContext, logFM, ls, sl)

-- The artifact serve mode. Threading it through the artifact path keeps GET and HEAD on the
-- same gating and the same upstream-request construction.
data ArtifactServe
    = -- A GET: stream the artifact body through, enqueuing a mirror job on a public
      -- admit (the demand-driven back-fill).
      ServeFull
    | -- A HEAD: probe the upstream as a HEAD and relay the headers with no body,
      -- enqueuing nothing, because it serves no bytes and so has nothing to mirror.
      ServeHead

{- Tag an upstream artifact request with the serve mode's method. 'ServeFull' keeps the request's
default @GET@. -}
withMethod :: ArtifactServe -> HTTP.Request -> HTTP.Request
withMethod = \case
    ServeFull -> id
    ServeHead -> \req -> req{HTTP.method = methodHead}

{- Relay the client's conditional validators ('forwardValidators') onto an upstream artifact
request, so upstream can answer a @304 Not Modified@ instead of resending an unchanged body. -}
withValidators :: RequestHeaders -> HTTP.Request -> HTTP.Request
withValidators validators req =
    req{HTTP.requestHeaders = validators <> HTTP.requestHeaders req}

{- Relay an upstream artifact response in the serve mode. Both modes keep the same recoverable-miss
and committed split, so a HEAD falls through a private miss to the public origin as a GET does. -}
relayUpstreamWhen ::
    ArtifactServe ->
    Manager ->
    HTTP.Request ->
    (Status -> Bool) ->
    (Status -> ResponseHeaders -> IO (Status, ResponseHeaders, verdict)) ->
    RelayResponder response ->
    IO (Maybe (verdict, response))
relayUpstreamWhen mode manager request =
    withUpstreamWhen manager request $ case mode of
        ServeFull -> StreamBody
        ServeHead -> NoBody

-- | A successful artifact response, including a matching conditional validator.
acceptArtifact :: Status -> Bool
acceptArtifact s = statusIsSuccessful s || isNotModified s

{- The trusted leg's pre-commit relay. It judges nothing, so the private hot path pays no
header scan for an anomaly only the public leg can have. -}
relayUnjudged :: Status -> ResponseHeaders -> IO (Status, ResponseHeaders, ())
relayUnjudged status headers = pure (status, forwardedHeaders headers, ())

{- The public leg's pre-commit relay. The verdict is decided before any body moves and rides back
beside the response, so a committed relay always carries exactly one. -}
relayJudged :: Status -> ResponseHeaders -> IO (Status, ResponseHeaders, RelayVerdict)
relayJudged status headers = pure (status, forwardedHeaders headers, relayVerdict status headers)

{- Drop only the hop-by-hop framing headers, which describe the upstream hop rather than the
artifact. The content headers and the @ETag@ pass through, so the client verifies the bytes. -}
forwardedHeaders :: ResponseHeaders -> ResponseHeaders
forwardedHeaders = filter (not . isHopByHop . fst)
  where
    isHopByHop name = name == "Transfer-Encoding" || name == "Connection"

-- | What the public leg relayed, judged at relay time from the status and headers alone.
data RelayVerdict
    = -- | A success whose headers look like the admitted artifact (a relayed @304@ counts: the validators matched, nothing odd).
      RelayedArtifact
    | -- | A success that does not look like an artifact. Carries a bounded reason.
      RelayedOddShape Text
    | -- | A non-success passed through verbatim. Carries the status.
      RelayedNonSuccess Status
    deriving stock (Eq, Show)

-- | Judge one public relay from its status and headers alone.
relayVerdict :: Status -> ResponseHeaders -> RelayVerdict
relayVerdict status headers
    | isNotModified status = RelayedArtifact
    | not (statusIsSuccessful status) = RelayedNonSuccess status
    | Just contentType <- snd <$> find ((== hContentType) . fst) headers
    , textualContentType contentType =
        RelayedOddShape ("a success carrying a non-artifact content type: " <> decodeUtf8 contentType)
    | otherwise = RelayedArtifact
  where
    textualContentType raw =
        "text/" `BS.isPrefixOf` raw || "application/json" `BS.isPrefixOf` raw

{- Observe one public-relay verdict. An anomaly counts on the bounded @ecluse.serve.relay.anomalies@
metric. The unbounded detail stays on the log line, never on a label. -}
observeRelayAnomaly :: forall m. (KatipContext m) => MetricsPort -> PackageName -> Version -> RelayVerdict -> m ()
observeRelayAnomaly metrics name version = \case
    RelayedArtifact -> pass
    RelayedOddShape reason -> record Metric.RelayOddShape ("the public upstream answered a success that does not look like the admitted artifact: " <> reason)
    RelayedNonSuccess status -> record Metric.RelayNonSuccess ("the public upstream answered a non-success, relayed verbatim: HTTP " <> show (statusCode status))
  where
    record :: Metric.RelayAnomaly -> Text -> m ()
    record cls message = do
        liftIO (mpPublicRelayAnomaly metrics cls)
        katipAddContext payload (logFM WarningS (ls message))
    payload =
        sl "module" ("Ecluse.Core.Server.Pipeline.Tarball.Relay" :: Text)
            <> sl "package" (renderPackageName name)
            <> sl "version" (renderVersion version)
