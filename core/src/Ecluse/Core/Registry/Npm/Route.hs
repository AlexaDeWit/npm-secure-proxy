-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT
-- TupleSections: local convenience for pairing a parsed name with its trailing
-- segments in 'takePackage' and 'takeScoped' ((,rest) / (,more)). See STYLE.md §2.
{-# LANGUAGE TupleSections #-}

{- | The npm router and OpenAPI description share one route table.
Reserved routes take precedence over package captures.
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

    -- * The served artifact URL (rendered from the route that claims it)
    tarballPath,

    -- * The capture values and leaf parsers (exported for their specs)
    NpmCap (..),
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
import Ecluse.Core.Package (PackageName, pkgNamespace, renderPackageName, renderScope, unscopedName)
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
    renderRoute,
    routerOf,
    safeSegment,
 )
import Ecluse.Core.Server.RouteSpec (ParamSpec (ParamSpec), RouteSpec, catchAllSpecs, specsOf)
import Ecluse.Core.Version (Version, mkVersion)

-- | Match the first applicable route, otherwise answer 'npmNotFound'.
npmRouter :: MountRouter
npmRouter = routerOf npmNotFound npmRoutes

-- | The deny-by-default @404@ action for a path no route claims.
npmNotFound :: RouteAction
npmNotFound =
    RouteAction
        unsupportedContract
        (AnswerLocally (responseValue [] (NpmError "not found")))

-- | Try reserved meta-routes before package captures.
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

-- | The closed packument response sum. 'npmPackumentReplies' is the only interface the pipeline receives for selecting one of its constructors.
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
                    (jsonContract status403 "Private access was refused, or no version survived policy and admission." npmErrorCodec)
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

-- | The tarball is deliberately an open relay: the route can forward any upstream status, headers, media type, and bytes.
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

-- | Positional captures distinguish parsed package identities from checked path segments.
data NpmCap
    = NpmPackage PackageName
    | NpmFilename Text
    | NpmTag Text

-- | The package capture: one npm package unit, both scoped wire encodings handled by 'takePackage'.
capPackage :: Capture NpmCap
capPackage =
    Capture
        "package"
        "The package name, URL-encoded; a scoped name is `@scope%2Fname`."
        ( \case
            "-" : _ -> Nothing
            segs -> fmap (first NpmPackage) (takePackage segs)
        )
        renderPackage

-- | The artifact-file capture. The coordinate parse (the @.tgz@ basename and the version) is 'tarballCoordinate''s, applied in 'buildTarball'.
capFilename :: Capture NpmCap
capFilename =
    Capture
        "filename"
        "The artifact's on-the-wire file name, e.g. `lodash-4.17.21.tgz`."
        (safeSegment NpmFilename)
        renderSegment

-- | Accept one checked dist-tag segment. Tag routes remain unsupported.
capTag :: Capture NpmCap
capTag =
    Capture
        "tag"
        "The dist-tag name, e.g. `latest`."
        (safeSegment NpmTag)
        renderSegment

{- The segments a package capture claims, written back out. A scoped name takes the two-segment
encoding, which 'takeScoped' reads back into the one wire name 'projectName' owns. -}
renderPackage :: NpmCap -> [Text]
renderPackage = \case
    NpmPackage name -> case pkgNamespace name of
        Just scope -> [renderScope scope, unscopedName name]
        Nothing -> [renderPackageName name]
    other -> renderSegment other

-- The one segment a raw safety-checked capture claims, written back out.
renderSegment :: NpmCap -> [Text]
renderSegment = \case
    NpmPackage name -> [renderPackageName name]
    NpmFilename file -> [file]
    NpmTag tag -> [tag]

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

-- | Parse an npm tarball-slot @file@ into the 'Version' and verbatim 'Filename' it names for @name@.
tarballCoordinate :: PackageName -> Text -> Maybe (Version, Filename)
tarballCoordinate name file =
    case T.stripSuffix ".tgz" file >>= T.stripPrefix (unscopedName name <> "-") of
        Just version
            | not (T.null version) -> (mkVersion Npm version,) <$> mkFilename file
        _ -> Nothing

-- | Render through the artifact route so generated URLs obey its capture rules.
tarballPath :: PackageName -> Text -> Maybe Text
tarballPath name file = T.intercalate "/" <$> renderRoute tarballRoute [NpmPackage name, NpmFilename file]

-- | Describe the live router and its deny-by-default catch-all for OpenAPI.
npmRouteSpecs :: NonEmpty RouteSpec
npmRouteSpecs =
    catchAllSpecs unsupportedContract unsupportedParam
        `NE.appendList` concatMap specsOf npmRoutes

unsupportedParam :: ParamSpec
unsupportedParam = ParamSpec "unsupportedPath" "Any path under this mount matched by none of the routes above."
