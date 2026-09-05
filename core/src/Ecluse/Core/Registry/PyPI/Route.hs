-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT
-- TupleSections: local convenience for pairing a parsed capture with its trailing
-- segments in 'takeProject' ((,rest)). See STYLE.md §2.
{-# LANGUAGE TupleSections #-}

{- | PyPI's route table: the list of routes a PyPI mount serves.

Each entry is one 'Ecluse.Core.Server.Route.Route' record carrying the method condition, the
media types it serves, the path template, what to /do/ on a match, and its prose. 'pypiRouter'
folds the list into the mount's router, where the first match wins and no match is the
deny-by-default @404@. 'pypiRouteSpecs' projects the same list for the OpenAPI spec.

The surface is three URLs. @\/simple\/{project}@ serves the PEP 691 JSON index,
@\/simple\/{project}\/{file}@ serves a distribution file and is the one spelling every rewritten
file URL agrees with, and a @POST@ names the upload endpoint. There is no JSON-API route, no
PEP 658 sidecar route, and no removal arm: PyPI spells no public wire endpoint for a client
yank.

Four PyPI-specific facts shape the matching:

* __The index serves JSON only__. The index route declares
  @application\/vnd.pypi.simple.v1+json@, so a client that requires HTML and admits no JSON
  takes a @406@ decided from the record before any upstream work. No PEP 503 HTML renderer
  exists to fall back to, and the client floor is pip 22.2, uv, and Poetry 1.5.

* __A template is written without a terminal slash__. The router strips trailing empty segments
  for every mount, so @\/simple\/{project}\/@ and @\/simple\/{project}@ both match one template.

* __Only the canonical project name routes__. A non-PEP-503 spelling falls through to the
  structural @404@. Écluse speaks no canonicalisation redirect, because a client that follows
  one would then be resolving against a URL Écluse did not gate.

* __A file name is cross-checked against the project__. 'Ecluse.Core.Registry.PyPI.Project.fileCoordinate'
  is the one reader of a distribution name, so the route, the projection, and the served index
  agree on which release a file belongs to. A name that belongs to another project is a
  path-confusion attempt and denies.

A refusal is a bare status with an empty body, matching upstream. With @server.helpMessage@
configured the body is that message as @text\/plain@, through the same response leaf.
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

    -- * The capture values and leaf parsers (exported for their specs)
    PyPICap (..),
    takeProject,
    artifactCoordinate,
) where

import Data.List.NonEmpty qualified as NE
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
import Ecluse.Core.Registry.PyPI.Project (FileCoordinate (fcVersionKey), fileCoordinate, isCanonicalName, projectName)
import Ecluse.Core.Server.Context (
    MountRouter,
    ResponseAction (AnswerLocally, RunPipeline),
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
import Ecluse.Core.Server.Response (Refusal, mkRefusal, refusalHelp)
import Ecluse.Core.Server.Route (
    Capture (Capture),
    MediaNegotiation (AcceptsAnything, AcceptsOnly),
    MethodMatch (MethodPost, MethodRead),
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

{- | PyPI's mount router. The first route that claims the request decides it, and a request no
route claims takes the deny-by-default @404@ ('pypiNotFound').
-}
pypiRouter :: MountRouter
pypiRouter = routerOf pypiNotFound pypiRoutes

{- | The deny-by-default @404@ action for a path no route claims: a bare status, matching what
an unknown project gets from the index itself.
-}
pypiNotFound :: RouteAction
pypiNotFound = RouteAction unsupportedContract (AnswerLocally (bareRefusal []))

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
        (answering (bareRefusal []))
        "Upload a first-party distribution (not supported)"
        "A PyPI mount registers no publish capability, so an upload is answered `405` rather \
        \than relayed. The route is declared so the refusal is the documented one rather than \
        \the deny-by-default `404` an unrouted path takes."
        Nothing
        pypiUploadContract

-- The media type the Simple index is served under, and the one form this mount negotiates.
simpleIndexMediaType :: ByteString
simpleIndexMediaType = "application/vnd.pypi.simple.v1+json"

-- The named hand-authored schema the manifest holds for the index Écluse assembles.
simpleIndexSchema :: Text
simpleIndexSchema = "PyPISimpleIndex"

{- | The closed Simple-index response sum. 'pypiIndexReplies' is the only interface the pipeline
receives for selecting one of its constructors.
-}
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
                    (refusalContract status403 "Every release was withheld by policy or admission, and none survived the merge.")
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

{- | Every refusal shares one shape: a bare status, or that status carrying the operator help
message as @text\/plain@ when one is configured.
-}
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
notAcceptable :: ResponseHeaders -> PyPIIndexResponse
notAcceptable headers =
    SecondResponse (SecondResponse (SecondResponse (SecondResponse (SecondResponse (FirstResponse (bareRefusal headers))))))

{- | The artifact route is deliberately an open relay: it forwards any upstream status, headers,
media type, and bytes, so one @default@ document is more accurate than a closed list.
-}
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

-- A refusal with no body: the shape an upstream index answers, and the default here.
bareRefusal :: ResponseHeaders -> ResponseValue (Maybe LByteString)
bareRefusal headers = responseValue headers Nothing

{- A refusal body: the operator help message alone, and nothing at all when no operator
configured one. Écluse's own wording stays off the wire, because PyPI's refusal is a bare status
and a client reads no envelope here. -}
helpBody :: ResponseHeaders -> Refusal -> ResponseValue (Maybe LByteString)
helpBody headers refusal = responseValue headers (helpBytes refusal)

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

{- @GET \/simple\/{project}\/{file}@: a distribution read. 'artifactCoordinate' applies the
__cross-capture__ path-confusion check and reads the release. A file naming another project
yields 'Nothing', so the route falls through to the @404@ instead of fabricating a coordinate. -}
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

{- | The captured values PyPI's routes produce: a parsed project unit, or a raw safety-checked
distribution file name. Builders consume them positionally.
-}
data PyPICap
    = PyPIProject PackageName
    | PyPIFile Text

{- | The project capture: one PEP 503 canonical project name. A non-canonical spelling matches
no route, so it takes the structural @404@ rather than a redirect.
-}
capProject :: Capture PyPICap
capProject =
    Capture
        "project"
        "The project name in PEP 503 canonical form, e.g. `zope-interface`."
        (fmap (first PyPIProject) . takeProject)

{- | The distribution-file capture. The coordinate parse (the release and the archive form) is
'artifactCoordinate''s, applied in 'buildArtifact'.
-}
capFile :: Capture PyPICap
capFile =
    Capture
        "file"
        "The distribution file's on-the-wire name, e.g. `requests-2.34.2-py3-none-any.whl`."
        (safeSegment PyPIFile)

{- | Peel the leading project unit off a path, returning its 'PackageName' and the remaining
segments. The route parses no name of its own: 'projectName' owns the PyPI name grammar, and
'isCanonicalName' is what keeps a spelling the index would redirect off this mount.
-}
takeProject :: [Text] -> Maybe (PackageName, [Text])
takeProject = \case
    seg : rest | isCanonicalName seg -> (,rest) <$> rightToMaybe (projectName seg)
    _ -> Nothing

{- | Parse a distribution-file slot into the 'Version' and verbatim 'Filename' it names for
@name@. A file naming another project is a path-confusion attempt, so it yields 'Nothing' and
the route denies it.
-}
artifactCoordinate :: PackageName -> Text -> Maybe (Version, Filename)
artifactCoordinate name file = do
    coordinate <- fileCoordinate name file
    (mkVersion PyPI (fcVersionKey coordinate),) <$> mkFilename file

{- | PyPI's routes as data for the __OpenAPI spec__: the 'specsOf' projection of the same
'pypiRoutes' the router runs, plus the synthetic deny-by-default catch-all.
-}
pypiRouteSpecs :: NonEmpty RouteSpec
pypiRouteSpecs =
    catchAllSpecs unsupportedContract unsupportedParam
        `NE.appendList` concatMap specsOf pypiRoutes

unsupportedParam :: ParamSpec
unsupportedParam = ParamSpec "unsupportedPath" "Any path under this mount matched by none of the routes above."
