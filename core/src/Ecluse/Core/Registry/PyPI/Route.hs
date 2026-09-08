-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT
-- TupleSections: local convenience for pairing a parsed capture with its trailing
-- segments in 'takeProject' ((,rest)). See docs/style.md §2.
{-# LANGUAGE TupleSections #-}

{- | PyPI route contracts shared by serving and OpenAPI generation.
Project names must be canonical, and distribution filenames must match their project.
-}
module Ecluse.Core.Registry.PyPI.Route (
    -- * The mount's router and fallback action
    pypiRouter,
    pypiNotFound,

    -- * Route-scoped pipeline contracts (exported for direct pipeline specs)
    pypiIndexContract,
    pypiIndexReplies,
    pypiArtifactContract,
    pypiArtifactReplies,

    -- * The table, as data
    pypiRoutes,
    pypiRouteSpecs,

    -- * The served file URL (rendered from the route that claims it)
    distributionPath,

    -- * The capture values and leaf parsers (exported for their specs)
    PyPICap (..),
    takeProject,
    artifactCoordinate,
) where

import Data.List.NonEmpty qualified as NE
import Data.Text qualified as T
import Network.HTTP.Types (
    Method,
    ResponseHeaders,
    Status,
    status200,
    status304,
    status401,
    status403,
    status404,
    status405,
    status406,
    status500,
    status502,
    status503,
 )

import Ecluse.Core.Ecosystem (Ecosystem (PyPI))
import Ecluse.Core.Package (PackageName)
import Ecluse.Core.Registry.PyPI.Project (FileCoordinate (fcVersionKey), canonicalName, fileCoordinate, isCanonicalName, projectName)
import Ecluse.Core.Registry.PyPI.Wire (simpleIndexMediaType)
import Ecluse.Core.Server.Context (
    MountRouter,
    ResponseAction (AnswerRefusal, RunPipeline),
    RouteAction (RouteAction),
 )
import Ecluse.Core.Server.Contract (
    BodySchema (SchemaDocumented, SchemaText),
    PassthroughBody (PassthroughBytes, PassthroughEmpty, PassthroughStream),
    PassthroughResponse,
    ResponseChoice (FirstResponse, SecondResponse),
    ResponseContract,
    ResponseValue,
    chooseContract,
    emptyContract,
    mediaContract,
    optionalBodyContract,
    passthroughContract,
    passthroughResponse,
    responseValue,
 )
import Ecluse.Core.Server.Path (Filename, mkFilename)
import Ecluse.Core.Server.Pipeline.Packument (PackumentReplies (..), headPackument, servePackument)
import Ecluse.Core.Server.Pipeline.Tarball (TarballReplies (..), headTarball, serveTarball)
import Ecluse.Core.Server.Response (HelpMessage, Refusal, mkRefusal, refusalHelp)
import Ecluse.Core.Server.Route (
    Capture (Capture),
    MediaNegotiation (AcceptsAnything, AcceptsOnly),
    MethodMatch (MethodPost, MethodRead),
    PatternSeg (SegCap, SegLit),
    Route (Route),
    RouteName (RouteName),
    isHead,
    refusing,
    renderRoute,
    routerOf,
    safeSegment,
 )
import Ecluse.Core.Server.RouteSpec (ParamSpec (ParamSpec), RouteSpec, catchAllSpecs, specsOf)
import Ecluse.Core.Version (Version, mkVersion)

-- | Match the first applicable route, otherwise answer 'pypiNotFound'.
pypiRouter :: MountRouter
pypiRouter = routerOf pypiNotFound pypiRoutes

-- | Refuse unmatched paths with 404.
pypiNotFound :: RouteAction
pypiNotFound = RouteAction unsupportedContract (AnswerRefusal (declaredRefusal "no route claims this path" []))

-- | PyPI's routes, in matching order.
pypiRoutes :: [Route PyPICap]
pypiRoutes =
    [ artifactRoute
    , simpleIndexRoute
    , uploadRoute
    ]

-- @GET \/simple\/{project}\/{file}@: a distribution file, streamed.
artifactRoute :: Route PyPICap
artifactRoute =
    Route
        (RouteName "distribution")
        MethodRead
        AcceptsAnything
        [SegLit "simple", SegCap capProject, SegCap capFile]
        buildArtifact
        "Stream a distribution file (wheel or sdist)"
        "The file's bytes are streamed verbatim with bounded memory, so the client verifies them \
        \against the `sha256` the served index advertised. `/simple/{project}/{file}` is the one \
        \spelling every rewritten file URL agrees with. Upstream statuses, headers, and media \
        \types are relayed transparently; a locally generated refusal is a bare status."
        Nothing
        pypiArtifactContract

-- @GET \/simple\/{project}@: the filtered PEP 691 JSON index.
simpleIndexRoute :: Route PyPICap
simpleIndexRoute =
    Route
        (RouteName "simpleIndex")
        MethodRead
        (AcceptsOnly (simpleIndexMediaType :| []) (notAcceptable []))
        [SegLit "simple", SegCap capProject]
        buildIndex
        "Fetch a project's Simple index"
        "Returns Écluse's merged-and-filtered PEP 691 JSON index: files merged across upstreams \
        \and gated, each file URL rewritten to resolve back through this proxy. \
        \`/simple/{project}/` and `/simple/{project}` both match, because the router strips a \
        \trailing empty segment. A non-canonical (non-PEP-503) project name matches no route and \
        \takes the `404`, with no redirect. A client that requires HTML and admits no JSON gets \
        \`406`: Écluse serves the JSON form alone."
        Nothing
        pypiIndexContract

-- @POST \/legacy@: the documented upload refusal.
uploadRoute :: Route PyPICap
uploadRoute =
    Route
        (RouteName "upload")
        MethodPost
        AcceptsAnything
        [SegLit "legacy"]
        (refusing (declaredRefusal "publishing is not enabled on this mount" []))
        "Upload a first-party distribution (not supported)"
        "A PyPI mount registers no publish capability, so an upload is answered `405` rather \
        \than relayed. The route is declared so the refusal is the documented one rather than \
        \the deny-by-default `404` an unrouted path takes."
        Nothing
        pypiUploadContract

-- The named hand-authored schema the manifest holds for the index Écluse assembles.
simpleIndexSchema :: Text
simpleIndexSchema = "PyPISimpleIndex"

-- | The closed Simple-index response sum. 'pypiIndexReplies' is the only interface the pipeline receives for selecting one of its constructors.
type PyPIIndexResponse =
    ResponseChoice
        (ResponseValue LByteString)
        ( ResponseChoice
            (ResponseValue ())
            ( ResponseChoice
                (ResponseValue (Maybe LByteString))
                ( ResponseChoice
                    (ResponseValue (Maybe LByteString))
                    ( ResponseChoice
                        (ResponseValue (Maybe LByteString))
                        ( ResponseChoice
                            (ResponseValue (Maybe LByteString))
                            ( ResponseChoice
                                (ResponseValue (Maybe LByteString))
                                (ResponseChoice (ResponseValue (Maybe LByteString)) (ResponseValue (Maybe LByteString)))
                            )
                        )
                    )
                )
            )
        )

pypiIndexContract :: ResponseContract PyPIIndexResponse
pypiIndexContract =
    chooseContract
        (mediaContract status200 "The filtered Simple index." (SchemaDocumented simpleIndexMediaType simpleIndexSchema))
        ( chooseContract
            (emptyContract status304 "The client's validator matched the assembled index.")
            ( chooseContract
                (refusalContract status401 "Edge authentication failed.")
                ( chooseContract
                    (refusalContract status403 "Private access was refused, or no release survived policy and admission.")
                    ( chooseContract
                        (refusalContract status404 "A first-party project the private upstream does not have. It is never fetched from the public upstream.")
                        ( chooseContract
                            (refusalContract status406 "The request requires a representation this index does not serve; only the PEP 691 JSON form exists.")
                            ( chooseContract
                                (refusalContract status500 "A permanent or internal inability to decide.")
                                ( chooseContract
                                    (refusalContract status502 "A responding upstream returned an index for a different project.")
                                    (refusalContract status503 "A transient upstream or advisory condition; retry (see `Retry-After`).")
                                )
                            )
                        )
                    )
                )
            )
        )

-- | A refusal has no body unless operator help text is configured.
refusalContract :: Status -> Text -> ResponseContract (ResponseValue (Maybe LByteString))
refusalContract status description =
    optionalBodyContract status (description <> " The body is empty unless `server.helpMessage` is configured.") (SchemaText "text/plain")

pypiIndexReplies :: PackumentReplies PyPIIndexResponse
pypiIndexReplies =
    PackumentReplies
        { packumentOk = \headers body -> FirstResponse (responseValue headers body)
        , packumentNotModified = \headers -> SecondResponse (FirstResponse (responseValue headers ()))
        , packumentUnauthorised = \headers refusal -> SecondResponse (SecondResponse (FirstResponse (helpBody headers refusal)))
        , packumentForbidden = \headers refusal -> SecondResponse (SecondResponse (SecondResponse (FirstResponse (helpBody headers refusal))))
        , packumentNotFound = \headers refusal -> SecondResponse (SecondResponse (SecondResponse (SecondResponse (FirstResponse (helpBody headers refusal)))))
        , packumentInternal = \headers refusal -> SecondResponse (SecondResponse (SecondResponse (SecondResponse (SecondResponse (SecondResponse (FirstResponse (helpBody headers refusal)))))))
        , packumentBadGateway = \headers refusal -> SecondResponse (SecondResponse (SecondResponse (SecondResponse (SecondResponse (SecondResponse (SecondResponse (FirstResponse (helpBody headers refusal))))))))
        , packumentUnavailable = \headers refusal -> SecondResponse (SecondResponse (SecondResponse (SecondResponse (SecondResponse (SecondResponse (SecondResponse (SecondResponse (helpBody headers refusal))))))))
        }

-- The @406@ arm, which the router selects before any handler runs.
notAcceptable :: ResponseHeaders -> Maybe HelpMessage -> PyPIIndexResponse
notAcceptable headers help =
    SecondResponse (SecondResponse (SecondResponse (SecondResponse (SecondResponse (FirstResponse (declaredRefusal "no representation this index serves is acceptable" headers help))))))

-- | Permit upstream-controlled artifact responses and local refusals through one open response contract.
pypiArtifactContract :: ResponseContract PassthroughResponse
pypiArtifactContract =
    passthroughContract
        "An upstream-controlled distribution response is relayed transparently. Local authentication, policy, availability, and internal failures answer a bare status under their own code."

pypiArtifactReplies :: TarballReplies PassthroughResponse
pypiArtifactReplies =
    TarballReplies
        { tarballError = \status headers refusal -> passthroughResponse status headers (artifactRefusalBody refusal)
        , tarballStream = \status headers body -> passthroughResponse status headers (PassthroughStream body)
        , tarballEmpty = \status headers -> passthroughResponse status headers PassthroughEmpty
        }

pypiUploadContract :: ResponseContract (ResponseValue (Maybe LByteString))
pypiUploadContract = refusalContract status405 "Publishing is not enabled on this mount."

unsupportedContract :: ResponseContract (ResponseValue (Maybe LByteString))
unsupportedContract = refusalContract status404 "Unrecognised path; deny by default."

-- Écluse's own wording stays off the wire: PyPI's refusal is a bare status, so the body is the
-- operator help message alone and nothing at all when none is configured.
helpBody :: ResponseHeaders -> Refusal -> ResponseValue (Maybe LByteString)
helpBody headers refusal = responseValue headers (helpBytes refusal)

{- The body of a refusal the route table decides rather than the pipeline, rendered through
'helpBody' too so a configured help message reaches every arm alike. -}
declaredRefusal :: Text -> ResponseHeaders -> Maybe HelpMessage -> ResponseValue (Maybe LByteString)
declaredRefusal reason headers help = helpBody headers (mkRefusal help reason)

-- The artifact relay's refusal, which is the same body under the transparent-relay contract.
artifactRefusalBody :: Refusal -> PassthroughBody
artifactRefusalBody refusal = maybe PassthroughEmpty PassthroughBytes (helpBytes refusal)

-- The operator help message as body bytes, absent when none is configured.
helpBytes :: Refusal -> Maybe LByteString
helpBytes = fmap (fromStrict . encodeUtf8) . refusalHelp

{- @GET \/simple\/{project}@: a project unit is an index read. A @HEAD@ takes the head-mode
handler, which runs the identical gating and merge but withholds the body. -}
buildIndex :: Method -> [PyPICap] -> Maybe (ResponseAction PyPIIndexResponse)
buildIndex method = \case
    [PyPIProject name]
        | isHead method -> Just (RunPipeline perimeterFallback (headPackument pypiIndexReplies name))
        | otherwise -> Just (RunPipeline perimeterFallback (servePackument pypiIndexReplies name))
    _ -> Nothing
  where
    perimeterFallback = packumentInternal pypiIndexReplies [] (mkRefusal Nothing "internal server error")

-- 'artifactCoordinate' applies the cross-capture path-confusion check, so a file naming another
-- project falls through to the @404@ rather than having a coordinate fabricated for it.
buildArtifact :: Method -> [PyPICap] -> Maybe (ResponseAction PassthroughResponse)
buildArtifact method = \case
    [PyPIProject name, PyPIFile file] -> do
        (version, filename) <- artifactCoordinate name file
        pure $
            if isHead method
                then RunPipeline perimeterFallback (headTarball pypiArtifactReplies name version filename)
                else RunPipeline perimeterFallback (serveTarball pypiArtifactReplies name version filename)
    _ -> Nothing
  where
    perimeterFallback = tarballError pypiArtifactReplies status500 [] (mkRefusal Nothing "internal server error")

-- | Positional captures distinguish parsed projects from checked distribution filenames.
data PyPICap
    = PyPIProject PackageName
    | PyPIFile Text

-- | Render project captures canonically so the parser can read them back.
renderCapture :: PyPICap -> [Text]
renderCapture = \case
    PyPIProject name -> [canonicalName name]
    PyPIFile file -> [file]

-- | Accept canonical projects only. Non-canonical spellings receive 404 rather than redirects.
capProject :: Capture PyPICap
capProject =
    Capture
        "project"
        "The project name in PEP 503 canonical form, e.g. `zope-interface`."
        (fmap (first PyPIProject) . takeProject)
        renderCapture

-- | The distribution-file capture. The coordinate parse (the release and the archive form) is 'artifactCoordinate''s, applied in 'buildArtifact'.
capFile :: Capture PyPICap
capFile =
    Capture
        "file"
        "The distribution file's on-the-wire name, e.g. `requests-2.34.2-py3-none-any.whl`."
        (safeSegment PyPIFile)
        renderCapture

-- | Reject project spellings that an index would redirect outside the matched route.
takeProject :: [Text] -> Maybe (PackageName, [Text])
takeProject = \case
    seg : rest | isCanonicalName seg -> (,rest) <$> rightToMaybe (projectName seg)
    _ -> Nothing

-- | Require the file's project identity to match the requested package.
artifactCoordinate :: PackageName -> Text -> Maybe (Version, Filename)
artifactCoordinate name file = do
    coordinate <- fileCoordinate name file
    (mkVersion PyPI (fcVersionKey coordinate),) <$> mkFilename file

-- | Render through the distribution route so generated URLs obey its capture rules.
distributionPath :: PackageName -> Text -> Maybe Text
distributionPath name file = T.intercalate "/" <$> renderRoute artifactRoute [PyPIProject name, PyPIFile file]

-- | Describe the live router and its deny-by-default catch-all for OpenAPI.
pypiRouteSpecs :: NonEmpty RouteSpec
pypiRouteSpecs =
    catchAllSpecs unsupportedContract unsupportedParam
        `NE.appendList` concatMap specsOf pypiRoutes

unsupportedParam :: ParamSpec
unsupportedParam = ParamSpec "unsupportedPath" "Any path under this mount matched by none of the routes above."
