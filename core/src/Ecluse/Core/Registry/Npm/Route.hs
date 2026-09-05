-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT
-- TupleSections: local convenience for pairing a parsed name with its trailing
-- segments in 'takePackage' and 'takeScoped' ((,rest) / (,more)). See STYLE.md §2.
{-# LANGUAGE TupleSections #-}

{- | npm's route table: the list of routes an npm mount serves.

Each entry is one 'Ecluse.Core.Server.Route.Route' record. It carries the method
condition, the path template, what to /do/ on a match, and its prose. Its
'Ecluse.Core.Server.Contract.ResponseContract' admits every response the route can emit.
'npmRouter' folds the list into the mount's router, where the first match wins and no
match is the deny-by-default @404@. 'npmRouteSpecs' projects the same list for the
OpenAPI spec. The routed surface, the emitted responses, and the documented ones
are all readings of one declaration.

Each response body is a codec ('Ecluse.Core.Registry.Npm.Serve.npmErrorCodec' for a
denial) or a named hand-authored schema (the merged packument, the publish document).
The wire body and the documented schema are therefore one source. The package, artifact,
and publish routes name the shared data-plane handlers ("Ecluse.Core.Server.Pipeline").
The meta-routes answer locally through their declared outcome.

A @PUT \/{pkg}@ is the npm __publish__ request, so the method is part of the match. A
@PUT@ over a bare-package path publishes. A __read__ (@GET@, or its bodiless @HEAD@) over
the same path fetches the packument. A @DELETE@ reaches one route only, the dist-tag
removal, and a @POST@ reaches none. A method no route claims denies.

The model is __deny by default__. Three npm-specific facts shape the matching:

* __The table matches reserved meta-routes (@\/-\/…@) first__. A real package name can
  never begin with @\'-\'@, so a leading @"-"@ segment is unambiguously a meta-route.

* __Scoped names arrive in two encodings__. The path is percent-decoded before it reaches
  this table, so a scoped name arrives either as one decoded segment (@\@scope\/pkg@) or
  as two (@\@scope@, @pkg@). This table normalises both to the same 'PackageName'.

* __A tarball path is @\/{pkg}\/-\/{file}.tgz@__. 'tarballCoordinate' is the npm-side
  parse of the artifact coordinate. A basename that does not match the package is a
  __path-confusion__ attempt and denies.

The agnostic web layer handles mount dispatch, prefix-stripping, and the
liveness\/readiness routes (see @docs\/architecture\/web-layer.md@). This table only ever
sees the npm-native request.
-}
module Ecluse.Core.Registry.Npm.Route (
    -- * The mount's router and fallback action
    npmRouter,
    npmNotFound,

    -- * Route-scoped pipeline contracts (exported for direct pipeline specs)
    npmPackumentContract,
    npmPackumentReplies,
    npmTarballContract,
    npmTarballReplies,

    -- * The table, as data
    npmRoutes,
    npmRouteSpecs,

    -- * The leaf parsers (exported for their specs)
    takePackage,
    tarballCoordinate,
) where

import Autodocodec (JSONCodec, object, pureCodec)
import Data.List.NonEmpty qualified as NE
import Data.Text qualified as T
import Network.HTTP.Types (
    Method,
    hContentType,
    status200,
    status304,
    status401,
    status403,
    status404,
    status500,
    status501,
    status502,
    status503,
 )

import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.Package (PackageName, unscopedName)
import Ecluse.Core.Registry.Npm.Project (projectName)
import Ecluse.Core.Registry.Npm.Serve (NpmError (NpmError), npmError, npmErrorCodec)
import Ecluse.Core.Server.Context (
    MountRouter,
    ResponseAction (AnswerLocally, RunPipeline),
    RouteAction (RouteAction),
 )
import Ecluse.Core.Server.Contract (
    BodySchema (SchemaDocumented),
    PassthroughBody (PassthroughBytes, PassthroughEmpty, PassthroughStream),
    PassthroughResponse,
    RequestSpec (RequestSpec),
    ResponseChoice (FirstResponse, SecondResponse),
    ResponseContract,
    ResponseValue,
    VariableResponse,
    chooseContract,
    documentedJsonContract,
    emptyContract,
    encodeBody,
    jsonContract,
    passthroughContract,
    passthroughResponse,
    responseValue,
    variableOpaqueContract,
    variableResponse,
 )
import Ecluse.Core.Server.Path (Filename, mkFilename)
import Ecluse.Core.Server.Pipeline.Packument (PackumentReplies (..), headPackument, servePackument)
import Ecluse.Core.Server.Pipeline.Publish (PublishReplies (..), servePublish)
import Ecluse.Core.Server.Pipeline.Tarball (TarballReplies (..), headTarball, serveTarball)
import Ecluse.Core.Server.Response (mkRefusal, renderRefusal)
import Ecluse.Core.Server.Route (
    Capture (Capture),
    MediaNegotiation (AcceptsAnything),
    MethodMatch (MethodDelete, MethodPut, MethodRead),
    PatternSeg (SegCap, SegLit),
    Route (Route),
    RouteName (RouteName),
    answering,
    isHead,
    routerOf,
    safeSegment,
 )
import Ecluse.Core.Server.RouteSpec (ParamSpec (ParamSpec), RouteSpec, catchAllSpecs, specsOf)
import Ecluse.Core.Version (Version, mkVersion)

{- | npm's mount router. The first route that claims the request decides it, and a request no
route claims takes the deny-by-default @404@ ('npmNotFound').
-}
npmRouter :: MountRouter
npmRouter = routerOf npmNotFound npmRoutes

-- | The deny-by-default @404@ action for a path no route claims.
npmNotFound :: RouteAction
npmNotFound =
    RouteAction
        unsupportedContract
        (AnswerLocally (responseValue [] (NpmError "not found")))

{- | npm's routes, in matching order: the reserved literal meta-routes are tried first. The
security-critical leaf parsing stays in 'takePackage' and 'tarballCoordinate'.
-}
npmRoutes :: [Route NpmCap]
npmRoutes =
    [ pingRoute
    , searchRoute
    , distTagListRoute
    , distTagSetRoute
    , distTagRemoveRoute
    , tarballRoute
    , packumentRoute
    , publishRoute
    ]

-- @GET \/-\/ping@: a liveness probe, answered locally with @200 {}@.
pingRoute :: Route NpmCap
pingRoute =
    Route
        (RouteName "ping")
        MethodRead
        AcceptsAnything
        [SegLit "-", SegLit "ping"]
        (answering pingAnswer)
        "Liveness probe"
        "Answered locally with `200` and an empty object; `npm ping` checks the endpoint it talks \
        \to is up, so there is no reason to round-trip upstream."
        Nothing
        pingContract

-- @GET \/-\/v1\/search@: a documented @501@ boundary. Search is not proxied.
searchRoute :: Route NpmCap
searchRoute =
    Route
        (RouteName "search")
        MethodRead
        AcceptsAnything
        [SegLit "-", SegLit "v1", SegLit "search"]
        (answering searchAnswer)
        "Package search (not supported)"
        "Search is a first-class documented boundary: a discovery convenience, not an install path, \
        \so Écluse returns `501` and points to the public registry's website."
        Nothing
        searchContract

-- @GET \/-\/package\/{package}\/dist-tags@: a documented @501@ boundary.
distTagListRoute :: Route NpmCap
distTagListRoute =
    Route
        (RouteName "distTagList")
        MethodRead
        AcceptsAnything
        [SegLit "-", SegLit "package", SegCap capPackage, SegLit "dist-tags"]
        (answering distTagAnswer)
        "List a package's dist-tags (not supported)"
        "A dist-tag is a mutable named pointer, which Écluse does not implement, so it returns \
        \`501` rather than the `404` an unrouted path takes. The merged packument already carries \
        \the reconciled `dist-tags` map, so a client reads a package's tags from its metadata."
        Nothing
        distTagContract

-- One path template for the tagged dist-tag routes, so the write and the removal cannot drift.
distTagTagSegs :: [PatternSeg NpmCap]
distTagTagSegs = [SegLit "-", SegLit "package", SegCap capPackage, SegLit "dist-tags", SegCap capTag]

-- @PUT \/-\/package\/{package}\/dist-tags\/{tag}@: a documented @501@ boundary.
distTagSetRoute :: Route NpmCap
distTagSetRoute =
    Route
        (RouteName "distTagSet")
        MethodPut
        AcceptsAnything
        distTagTagSegs
        (answering distTagAnswer)
        "Set a package's dist-tag (not supported)"
        "Écluse writes no mutable named pointer, so it returns `501` rather than the `404` an \
        \unrouted path takes. The publication target owns a package's tags, and a publisher sets \
        \them there."
        Nothing
        distTagContract

-- @DELETE \/-\/package\/{package}\/dist-tags\/{tag}@: a documented @501@ boundary.
distTagRemoveRoute :: Route NpmCap
distTagRemoveRoute =
    Route
        (RouteName "distTagRemove")
        MethodDelete
        AcceptsAnything
        distTagTagSegs
        (answering distTagAnswer)
        "Remove a package's dist-tag (not supported)"
        "Écluse holds no mutable named pointer to remove, so it returns `501` rather than the `404` \
        \an unrouted path takes. The publication target owns a package's tags, and a publisher \
        \removes them there."
        Nothing
        distTagContract

-- @GET \/{package}\/-\/{filename}@: a package artifact, streamed.
tarballRoute :: Route NpmCap
tarballRoute =
    Route
        (RouteName "tarball")
        MethodRead
        AcceptsAnything
        [SegCap capPackage, SegLit "-", SegCap capFilename]
        buildTarball
        "Stream a package artifact (tarball)"
        "The artifact bytes are streamed verbatim with bounded memory; the client verifies the bytes \
        \against the packument's preserved integrity digest. Upstream statuses, headers, and media \
        \types are relayed transparently; locally generated refusals use npm's JSON error shape."
        Nothing
        npmTarballContract

-- @GET \/{package}@: the merged, gated packument.
packumentRoute :: Route NpmCap
packumentRoute =
    Route
        (RouteName "packument")
        MethodRead
        AcceptsAnything
        [SegCap capPackage]
        buildPackument
        "Fetch a package's metadata (packument)"
        "Returns Écluse's merged-and-filtered packument: versions merged across upstreams and gated, \
        \each `dist.tarball` rewritten to resolve back through this proxy. With no surviving version \
        \the status follows the most recoverable cause."
        Nothing
        npmPackumentContract

-- @PUT \/{package}@: a first-party publish, relayed after the anti-shadowing guard.
publishRoute :: Route NpmCap
publishRoute =
    Route
        (RouteName "publish")
        MethodPut
        AcceptsAnything
        [SegCap capPackage]
        buildPublish
        "Publish a first-party package"
        "Relays the publish document to the configured publication target after the anti-shadowing \
        \scope guard. Écluse keys the write on the route's package name, never the document's \
        \self-reported name. The target's status and JSON-labelled bytes are relayed transparently."
        (Just publishRequest)
        npmPublishContract

-- The named hand-authored schemas the manifest holds for the documents Écluse builds
-- imperatively rather than round-tripping through a codec.
synthesizedPackumentSchema :: Text
synthesizedPackumentSchema = "SynthesizedPackument"

publishDocumentSchema :: Text
publishDocumentSchema = "PublishDocument"

-- The publish document a @PUT@ accepts, documented by its hand-authored schema.
publishRequest :: RequestSpec
publishRequest =
    RequestSpec
        "The npm publish document (the version manifest plus the base64-encoded tarball in `_attachments`)."
        True
        (SchemaDocumented "application/json" publishDocumentSchema)

-- The empty-object codec: encodes @()@ to @{}@ and documents an empty object schema.
emptyObjectCodec :: JSONCodec ()
emptyObjectCodec = object "EmptyObject" (pureCodec ())

pingContract :: ResponseContract (ResponseValue ())
pingContract = jsonContract status200 "An empty object." emptyObjectCodec

searchContract :: ResponseContract (ResponseValue NpmError)
searchContract = jsonContract status501 "Not implemented: search is not supported." npmErrorCodec

-- No dist-tag operation is implemented, so the read, the write, and the removal share one contract.
distTagContract :: ResponseContract (ResponseValue NpmError)
distTagContract = jsonContract status501 "Not implemented: dist-tags are not supported." npmErrorCodec

unsupportedContract :: ResponseContract (ResponseValue NpmError)
unsupportedContract = jsonContract status404 "Unrecognised path; deny by default." npmErrorCodec

{- | The closed packument response sum. 'npmPackumentReplies' is the only interface the pipeline
receives for selecting one of its constructors.
-}
type NpmPackumentResponse =
    ResponseChoice
        (ResponseValue LByteString)
        ( ResponseChoice
            (ResponseValue ())
            ( ResponseChoice
                (ResponseValue NpmError)
                ( ResponseChoice
                    (ResponseValue NpmError)
                    ( ResponseChoice
                        (ResponseValue NpmError)
                        ( ResponseChoice
                            (ResponseValue NpmError)
                            (ResponseChoice (ResponseValue NpmError) (ResponseValue NpmError))
                        )
                    )
                )
            )
        )

npmPackumentContract :: ResponseContract NpmPackumentResponse
npmPackumentContract =
    chooseContract
        (documentedJsonContract status200 "The synthesized packument." synthesizedPackumentSchema)
        ( chooseContract
            (emptyContract status304 "The client's validator matched the synthesized packument.")
            ( chooseContract
                (jsonContract status401 "Edge authentication failed." npmErrorCodec)
                ( chooseContract
                    (jsonContract status403 "Every version was withheld by policy or admission, and none survived the merge." npmErrorCodec)
                    ( chooseContract
                        (jsonContract status404 "A first-party name the private upstream does not have. It is never fetched from the public upstream." npmErrorCodec)
                        ( chooseContract
                            (jsonContract status500 "A permanent or internal inability to decide." npmErrorCodec)
                            ( chooseContract
                                (jsonContract status502 "A responding upstream returned a packument for a different package." npmErrorCodec)
                                (jsonContract status503 "A transient upstream or advisory condition; retry (see `Retry-After`)." npmErrorCodec)
                            )
                        )
                    )
                )
            )
        )

npmPackumentReplies :: PackumentReplies NpmPackumentResponse
npmPackumentReplies =
    PackumentReplies
        { packumentOk = \headers body -> FirstResponse (responseValue headers body)
        , packumentNotModified = \headers -> SecondResponse (FirstResponse (responseValue headers ()))
        , packumentUnauthorised = \headers message -> SecondResponse (SecondResponse (FirstResponse (responseValue headers (NpmError (renderRefusal message)))))
        , packumentForbidden = \headers message -> SecondResponse (SecondResponse (SecondResponse (FirstResponse (responseValue headers (NpmError (renderRefusal message))))))
        , packumentNotFound = \headers message -> SecondResponse (SecondResponse (SecondResponse (SecondResponse (FirstResponse (responseValue headers (NpmError (renderRefusal message)))))))
        , packumentInternal = \headers message -> SecondResponse (SecondResponse (SecondResponse (SecondResponse (SecondResponse (FirstResponse (responseValue headers (NpmError (renderRefusal message))))))))
        , packumentBadGateway = \headers message -> SecondResponse (SecondResponse (SecondResponse (SecondResponse (SecondResponse (SecondResponse (FirstResponse (responseValue headers (NpmError (renderRefusal message)))))))))
        , packumentUnavailable = \headers message -> SecondResponse (SecondResponse (SecondResponse (SecondResponse (SecondResponse (SecondResponse (SecondResponse (responseValue headers (NpmError (renderRefusal message)))))))))
        }

{- | The tarball is deliberately an open relay: the route can forward any upstream
status, headers, media type, and bytes. The one @default@ document is therefore more
accurate than a closed list that the upstream can escape.
-}
npmTarballContract :: ResponseContract PassthroughResponse
npmTarballContract =
    passthroughContract
        "An upstream-controlled artifact response is relayed transparently. Local authentication, policy, availability, and internal failures use npm's JSON error body under their corresponding status."

npmTarballReplies :: TarballReplies PassthroughResponse
npmTarballReplies =
    TarballReplies
        { tarballError = \status headers message ->
            passthroughResponse
                status
                ((hContentType, "application/json") : headers)
                (PassthroughBytes (encodeBody npmErrorCodec (NpmError (renderRefusal message))))
        , tarballStream = \status headers body -> passthroughResponse status headers (PassthroughStream body)
        , tarballEmpty = \status headers -> passthroughResponse status headers PassthroughEmpty
        }

type NpmPublishResponse = VariableResponse LByteString

npmPublishContract :: ResponseContract NpmPublishResponse
npmPublishContract =
    variableOpaqueContract
        "application/json"
        "The publication target's status and JSON-labelled response bytes are relayed. Local authentication, scope, configuration, transport, and internal failures use npm's JSON error body."

npmPublishReplies :: PublishReplies NpmPublishResponse
npmPublishReplies =
    PublishReplies
        { publishRelayed = variableResponse
        , publishError = \status headers message ->
            variableResponse status headers (encodeBody npmErrorCodec (NpmError message))
        }

-- @\/-\/ping@: answered locally with @200 {}@.
pingAnswer :: ResponseValue ()
pingAnswer = responseValue [] ()

-- @\/-\/v1\/search@: a @501@ pointer, in npm's error surface.
searchAnswer :: ResponseValue NpmError
searchAnswer =
    responseValue [] (npmError Nothing "search is not supported by this proxy; use the public registry's website to discover packages")

-- The dist-tag routes' @501@ pointer, in npm's error surface.
distTagAnswer :: ResponseValue NpmError
distTagAnswer =
    responseValue [] (npmError Nothing "dist-tags are not supported by this proxy; a package's tags are in the metadata document it serves, and a publisher sets them at the publication target")

{- @GET \/{package}@: a bare package unit is a packument read. A @HEAD@ takes the
head-mode handler, which runs the identical gating and merge but withholds the body. -}
buildPackument :: Method -> [NpmCap] -> Maybe (ResponseAction NpmPackumentResponse)
buildPackument method = \case
    [NpmPackage name]
        | isHead method -> Just (RunPipeline perimeterFallback (headPackument npmPackumentReplies name))
        | otherwise -> Just (RunPipeline perimeterFallback (servePackument npmPackumentReplies name))
    _ -> Nothing
  where
    perimeterFallback = packumentInternal npmPackumentReplies [] (mkRefusal Nothing "internal server error")

{- @PUT \/{package}@: a bare package unit under the write method is a publish. -}
buildPublish :: Method -> [NpmCap] -> Maybe (ResponseAction NpmPublishResponse)
buildPublish _method = \case
    [NpmPackage name] ->
        Just
            ( RunPipeline
                (publishError npmPublishReplies status500 [] "internal server error")
                (servePublish npmPublishReplies name)
            )
    _ -> Nothing

{- @GET \/{package}\/-\/{filename}@: an artifact read. 'tarballCoordinate' applies the
__cross-capture__ path-confusion check and reads the version. A mismatched name yields
'Nothing', so the route falls through to the @404@ instead of fabricating a
coordinate. A @HEAD@ takes the head-mode handler, which probes the upstream bodiless. -}
buildTarball :: Method -> [NpmCap] -> Maybe (ResponseAction PassthroughResponse)
buildTarball method = \case
    [NpmPackage name, NpmFilename file] -> do
        (version, filename) <- tarballCoordinate name file
        pure $
            if isHead method
                then RunPipeline perimeterFallback (headTarball npmTarballReplies name version filename)
                else RunPipeline perimeterFallback (serveTarball npmTarballReplies name version filename)
    _ -> Nothing
  where
    perimeterFallback = tarballError npmTarballReplies status500 [] (mkRefusal Nothing "internal server error")

{- | The captured values npm's routes produce: a parsed package unit, or a raw
safety-checked segment (an artifact file name, a dist-tag). Builders consume them positionally.
-}
data NpmCap
    = NpmPackage PackageName
    | NpmFilename Text
    | NpmTag Text

{- | The package capture: one npm package unit, both scoped wire encodings handled by
'takePackage'. It refuses a bare leading @"-"@ on every method, because @\/-\/…@ is the reserved
meta-route prefix and a lone @"-"@ is never a package name.
-}
capPackage :: Capture NpmCap
capPackage =
    Capture
        "package"
        "The package name, URL-encoded; a scoped name is `@scope%2Fname`."
        ( \case
            "-" : _ -> Nothing
            segs -> fmap (first NpmPackage) (takePackage segs)
        )

{- | The artifact-file capture. The coordinate parse (the @.tgz@ basename and the version) is
'tarballCoordinate''s, applied in 'buildTarball'.
-}
capFilename :: Capture NpmCap
capFilename =
    Capture
        "filename"
        "The artifact's on-the-wire file name, e.g. `lodash-4.17.21.tgz`."
        (safeSegment NpmFilename)

{- | The dist-tag capture: one segment, accepted only when 'safeSegment' admits it. Both tagged
routes answer @501@, so nothing downstream reads the tag.
-}
capTag :: Capture NpmCap
capTag =
    Capture
        "tag"
        "The dist-tag name, e.g. `latest`."
        (safeSegment NpmTag)

{- Peel the leading package unit off a path, returning its 'PackageName' and the remaining
segments. The route parses no name of its own: 'projectName' owns the npm name grammar. -}
takePackage :: [Text] -> Maybe (PackageName, [Text])
takePackage [] = Nothing
takePackage (seg : rest)
    | T.isPrefixOf "@" seg = takeScoped seg rest
    | otherwise = (,rest) <$> rightToMaybe (projectName seg)

{- Peel a scoped package unit off the leading @\@…@ segment. Both wire encodings, one decoded
segment or two, join into the one wire name 'projectName' reads. -}
takeScoped :: Text -> [Text] -> Maybe (PackageName, [Text])
takeScoped seg rest
    | T.isInfixOf "/" seg = (,rest) <$> rightToMaybe (projectName seg)
    | otherwise = case rest of
        (base : more) -> (,more) <$> rightToMaybe (projectName (seg <> "/" <> base))
        [] -> Nothing

{- | Parse an npm tarball-slot @file@ into the 'Version' and verbatim 'Filename' it names for
@name@. The npm convention is @{unscoped-name}-{version}.tgz@, and a basename that does not begin
with @{unscoped-name}-@ is a path-confusion attempt, so it yields 'Nothing' and the route denies
it.
-}
tarballCoordinate :: PackageName -> Text -> Maybe (Version, Filename)
tarballCoordinate name file =
    case T.stripSuffix ".tgz" file >>= T.stripPrefix (unscopedName name <> "-") of
        Just version
            | not (T.null version) -> (mkVersion Npm version,) <$> mkFilename file
        _ -> Nothing

{- | npm's routes as data for the __OpenAPI spec__: the 'specsOf' projection of the
same 'npmRoutes' the router runs, plus the synthetic deny-by-default catch-all.
-}
npmRouteSpecs :: NonEmpty RouteSpec
npmRouteSpecs =
    catchAllSpecs unsupportedContract unsupportedParam
        `NE.appendList` concatMap specsOf npmRoutes

unsupportedParam :: ParamSpec
unsupportedParam = ParamSpec "unsupportedPath" "Any path under this mount matched by none of the routes above."
