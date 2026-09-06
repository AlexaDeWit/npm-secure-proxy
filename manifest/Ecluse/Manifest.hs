-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT
{-# LANGUAGE DerivingVia #-}

{- | The OpenAPI spec: a pure assembly of Écluse's OpenAPI 3 document from
the closed serve-route enumeration and the configured mounts.

The manifest is a __capability statement__, not a client-integration contract.
Registry clients (npm, pnpm, yarn) hardcode the registry protocol and never read an
API description. This document exists to say, for a human, /which registry protocols
this one server speaks and exactly what is, and is not, supported/, per ecosystem.
It is __statically generated__ from a fixed canonical source and published as static
content. It is __not served__, and there is no route or WAI wiring for it.

The document is __rendered from the mounted adapters' route grammar__. Each
configured ecosystem's 'Ecluse.Core.Registry.Adapter.Types.RegistryAdapter' carries
its serve surface as data ('Ecluse.Core.Registry.Adapter.Types.serveRoutes', a
'RouteSpec' per served 'Route'), the same grammar the server's
'Ecluse.Core.Server.Route.Classifier' routes on. This module walks those specs into
OpenAPI paths and marries each to its owned documentation. The described surface is
therefore a projection of how the server mounts routes, not a hand-kept parallel
copy. The owned response bodies carry code-first schemas, and the module
distinguishes three kinds of surface:

* Écluse authors the __owned__ bodies, so this module models them in full: the
  error\/denial envelope (a codec, rendered from the same
  'Ecluse.Core.Registry.Npm.Serve.npmErrorCodec' the serve path emits) and the
  merged-and-filtered packument ('synthesizedPackumentSchema').
* __Opaque pass-through__, the artifact bytes, is described as a streamed media
  type and links out rather than reproducing the upstream protocol.
* __Unsupported__, @search@, the dist-tag routes, and any unrecognised path, are
  first-class documented boundaries (a @501@ and the deny-by-default @404@), so a reader
  learns the limit from the manifest, not from an error reply.

== Determinism

The rendered bytes must be __byte-stable__ across runs and machines, so the
published artifact yields a meaningful line-level diff on every contract change.
'renderManifest' pins object-key ordering (sorted), and 'buildOpenApi' is a pure
function of an explicit 'ManifestSource'. Generate from 'canonicalManifestSource'
(fixed mounts and base URL), never from a live or environment-derived configuration,
or the output churns on per-deployment values.

== Schema strategy

A response body is either a codec or a hand-authored schema, and the route's declared
'Ecluse.Core.Server.Contract.Outcome's say which. A __codec body__ (npm's error
envelope) carries one @autodocodec@ codec in core. The serve path encodes the wire
body from it, and this tier renders the /same/ codec to the documented schema. The
emitted body and its documentation are one source and cannot diverge.

A __documented body__ (the merged packument, the publish document) is one Écluse
builds imperatively rather than round-tripping through a type. It carries a
hand-written schema here, registered as a named component, and a validation check
binds it to the emitted bytes. npm's /inbound/ wire decoding stays lenient
hand-rolled @aeson@ ("Ecluse.Core.Registry.Npm.Wire"): codecs are for what Écluse owns
and emits, not for tolerantly parsing someone else's loose document.
-}
module Ecluse.Manifest (
    -- * Inputs
    ManifestSource (..),
    canonicalManifestSource,

    -- * Assembly and rendering
    buildOpenApi,
    renderManifest,
    routePathKey,

    -- * Owned schemas
    SynthesizedPackument,
    synthesizedPackumentSchema,
    synthesizedPackumentSchemaName,
    publishDocumentSchemaName,
    simpleIndexSchemaName,
) where

import Data.Aeson.Encode.Pretty qualified as Pretty
import Data.HashMap.Strict.InsOrd qualified as InsOrd
import Data.HashSet.InsOrd qualified as InsOrdSet
import Data.Text qualified as T

import Autodocodec (JSONCodec)
import Autodocodec.OpenAPI (declareNamedSchemaVia)
import Data.List (nubBy)
import Data.OpenApi (
    AdditionalProperties (AdditionalPropertiesAllowed, AdditionalPropertiesSchema),
    Components (_componentsSchemas),
    Info (_infoDescription, _infoTitle, _infoVersion),
    MediaTypeObject (_mediaTypeObjectSchema),
    NamedSchema (NamedSchema),
    OpenApi (_openApiComponents, _openApiInfo, _openApiPaths, _openApiServers, _openApiTags),
    OpenApiItems (OpenApiItemsObject),
    OpenApiType (OpenApiArray, OpenApiObject, OpenApiString),
    Operation (_operationDescription, _operationOperationId, _operationRequestBody, _operationResponses, _operationSummary, _operationTags),
    Param (_paramDescription, _paramIn, _paramName, _paramRequired, _paramSchema),
    ParamLocation (ParamPath),
    PathItem (
        _pathItemDelete,
        _pathItemGet,
        _pathItemHead,
        _pathItemOptions,
        _pathItemParameters,
        _pathItemPatch,
        _pathItemPost,
        _pathItemPut,
        _pathItemTrace
    ),
    Reference (Reference),
    Referenced (Inline, Ref),
    RequestBody (_requestBodyContent, _requestBodyDescription, _requestBodyRequired),
    Response (_responseContent, _responseDescription),
    Responses (_responsesDefault, _responsesResponses),
    Schema (_schemaAdditionalProperties, _schemaDescription, _schemaFormat, _schemaItems, _schemaProperties, _schemaRequired, _schemaTitle, _schemaType),
    Server (Server, _serverDescription, _serverUrl, _serverVariables),
    Tag (Tag),
    ToSchema (declareNamedSchema),
 )
import Data.OpenApi.Declare (undeclare)
import Network.HTTP.Media (MediaType)
import Network.HTTP.Types.Method (StdMethod (..))
import Network.HTTP.Types.Status (statusCode)

import Ecluse.Core.Ecosystem (Ecosystem (Npm, PyPI, RubyGems), ecosystemName, prefixFor)
import Ecluse.Core.Registry.Adapter (adapterFor)
import Ecluse.Core.Registry.Adapter.Types (AdapterServe (serveRoutes), RegistryAdapter (adapterServe))
import Ecluse.Core.Server.Contract (
    BodySchema (SchemaDocumented, SchemaEmpty, SchemaJson, SchemaOpaque, SchemaPassthrough, SchemaText),
    RequestSpec (reqDescription, reqRequired, reqSchema),
    ResponseDoc (responseBodySchema, responseDescription, responseStatus),
    ResponseStatus (DefaultResponse, ExactResponse),
 )
import Ecluse.Core.Server.Route (RouteName, unRouteName)
import Ecluse.Core.Server.RouteSpec (
    ParamSpec (psDescription, psName),
    PathSeg (Lit, Param),
    RouteSpec (rsDescription, rsMethod, rsName, rsOutcomes, rsPattern, rsRequest, rsSummary),
 )

{- | The explicit inputs the manifest is a pure function of: the base URL and mounted ecosystems.
It excludes credentials, upstreams, and policy, so assembly stays total and deterministic.
-}
data ManifestSource = ManifestSource
    { manifestBaseUrl :: Text
    -- ^ The proxy's externally-reachable base URL (the @servers@ entry).
    , manifestEcosystems :: NonEmpty Ecosystem
    -- ^ The mounted ecosystems, each contributing a tag and its route grammar.
    }
    deriving stock (Eq, Show)

{- | The fixed canonical source the build-time generator runs against. Its placeholder base URL
keeps the generated artifact byte-reproducible across machines.
-}
canonicalManifestSource :: ManifestSource
canonicalManifestSource =
    ManifestSource
        { manifestBaseUrl = "https://registry.ecluse.example"
        , manifestEcosystems = Npm :| [PyPI]
        }

-- | Assemble the OpenAPI 3 document, a __pure__ function of the source.
buildOpenApi :: ManifestSource -> OpenApi
buildOpenApi src =
    (mempty :: OpenApi)
        { _openApiInfo = manifestInfo
        , _openApiServers = [server]
        , _openApiPaths = pathsFrom (concatMap ecosystemRouteSpecs (toList (manifestEcosystems src)))
        , _openApiComponents = (mempty :: Components){_componentsSchemas = componentSchemas}
        , _openApiTags = InsOrdSet.fromList (map ecosystemTag (toList (manifestEcosystems src)))
        }
  where
    componentSchemas = InsOrd.fromList (concatMap ownedSchemas (toList (manifestEcosystems src)))

    server =
        Server
            { _serverUrl = manifestBaseUrl src
            , _serverDescription = Just "The proxy's externally-reachable base URL; served artifact URLs resolve against it."
            , _serverVariables = mempty
            }

manifestInfo :: Info
manifestInfo =
    (mempty :: Info)
        { _infoTitle = "Écluse OpenAPI spec"
        , _infoVersion = "0.1.0"
        , _infoDescription =
            Just
                "Which registry protocols this Écluse server speaks, and exactly what is and is not \
                \supported, per ecosystem. An OpenAPI spec for operators and contributors -- \
                \not a client-integration contract: registry clients hardcode the protocol and never \
                \read this document. Generated statically from the closed serve-route enumeration; \
                \it is not served."
        }

{- | The hand-authored component schemas an ecosystem's documented bodies name. The rendered
components carry the mounted ecosystems' entries and no others.
-}
ownedSchemas :: Ecosystem -> [(Text, Schema)]
ownedSchemas = \case
    Npm ->
        [ (synthesizedPackumentSchemaName, synthesizedPackumentSchema)
        , (publishDocumentSchemaName, publishDocumentSchema)
        ]
    PyPI -> [(simpleIndexSchemaName, simpleIndexSchema)]
    RubyGems -> []

-- | The tag for an ecosystem (the manifest groups operations by mount).
ecosystemTag :: Ecosystem -> Tag
ecosystemTag eco = Tag (ecosystemName eco) (Just (ecosystemName eco <> " registry protocol coverage")) Nothing

{- | The (path key, spec) entries an ecosystem's adapter declares in 'serveRoutes'. An ecosystem
with no adapter contributes nothing, rather than documenting a route the server cannot serve.
-}
ecosystemRouteSpecs :: Ecosystem -> [(Ecosystem, FilePath, RouteSpec)]
ecosystemRouteSpecs eco =
    case adapterFor eco of
        Nothing -> []
        Just adapter ->
            [ (eco, toString (routePathKey (prefixFor eco) spec), spec)
            | spec <- toList (serveRoutes (adapterServe adapter))
            ]

{- | Fold the entries into the paths map. Specs that render to the same key (the packument @GET@
and the publish @PUT@ on @\/{package}@) merge, and their path parameters de-duplicate by name.
-}
pathsFrom :: [(Ecosystem, FilePath, RouteSpec)] -> InsOrd.InsOrdHashMap FilePath PathItem
pathsFrom entries =
    InsOrd.fromList
        [ (key, item{_pathItemParameters = paramsFor key})
        | (key, item) <- InsOrd.toList operations
        ]
  where
    operations = foldl' addOperation InsOrd.empty entries
    addOperation acc (eco, key, spec) =
        InsOrd.insertWith (<>) key (methodItem (rsMethod spec) (operationFrom eco spec)) acc

    parameters = foldl' addParams InsOrd.empty entries
    -- Accumulate a key's parameters in first-seen order (@old <> new@) before the
    -- by-name de-duplication in 'paramsFor'.
    addParams acc (_eco, key, spec) = InsOrd.insertWith (flip (<>)) key (specParams spec) acc
    paramsFor key =
        map (Inline . toParam) (nubBy sameName (fromMaybe [] (InsOrd.lookup key parameters)))
    sameName a b = psName a == psName b

{- | The full path-template key for a route under a mount prefix, e.g.
@\/npm\/{package}\/-\/{filename}@. Routes that share a key render to the same string, so they merge.
-}
routePathKey :: NonEmpty Text -> RouteSpec -> Text
routePathKey prefix spec =
    "/" <> T.intercalate "/" (toList prefix <> map renderSeg (rsPattern spec))
  where
    renderSeg = \case
        Lit s -> s
        Param p -> "{" <> psName p <> "}"

-- | The path parameters a route's template carries, in template order.
specParams :: RouteSpec -> [ParamSpec]
specParams spec = [p | Param p <- rsPattern spec]

{- | Place an operation on the 'PathItem' field its HTTP method names. Total over 'StdMethod'.
The unreachable @CONNECT@ branch is the sanctioned @error@ escape hatch (STYLE.md section 10).
-}

{- HLINT ignore methodItem "Avoid restricted function" -}
methodItem :: StdMethod -> Operation -> PathItem
methodItem method op = case method of
    GET -> (mempty :: PathItem){_pathItemGet = Just op}
    PUT -> (mempty :: PathItem){_pathItemPut = Just op}
    POST -> (mempty :: PathItem){_pathItemPost = Just op}
    DELETE -> (mempty :: PathItem){_pathItemDelete = Just op}
    HEAD -> (mempty :: PathItem){_pathItemHead = Just op}
    PATCH -> (mempty :: PathItem){_pathItemPatch = Just op}
    OPTIONS -> (mempty :: PathItem){_pathItemOptions = Just op}
    TRACE -> (mempty :: PathItem){_pathItemTrace = Just op}
    -- CONNECT has no OpenAPI operation slot, and no served route uses it.
    CONNECT -> error "Ecluse.Manifest: OpenAPI has no CONNECT operation"

{- | Interpret a route's __documentation__ into an OpenAPI operation.

The ecosystem qualifies the route's name to form OpenAPI's @operationId@, which must be unique
across the whole document, and only here is every mount in view.
-}
operationFrom :: Ecosystem -> RouteSpec -> Operation
operationFrom eco spec =
    (mempty :: Operation)
        { _operationTags = InsOrdSet.fromList [ecosystemName eco]
        , _operationOperationId = Just (operationIdFor eco (rsName spec))
        , _operationSummary = Just (rsSummary spec)
        , _operationDescription = Just (rsDescription spec)
        , _operationRequestBody = Inline . requestBodyFrom <$> rsRequest spec
        , _operationResponses =
            (mempty :: Responses)
                { _responsesDefault = responseFrom <$> find isDefault (rsOutcomes spec)
                , _responsesResponses = InsOrd.fromList (mapMaybe exactResponseFrom (rsOutcomes spec))
                }
        }
  where
    isDefault doc = responseStatus doc == DefaultResponse

{- | A route's globally unique @operationId@: its ecosystem-local name, qualified by the
mount it is served under (@packument@ under the npm mount is @npm.packument@).
-}
operationIdFor :: Ecosystem -> RouteName -> Text
operationIdFor eco name = ecosystemName eco <> "." <> unRouteName name

-- | The request body a write route accepts.
requestBodyFrom :: RequestSpec -> RequestBody
requestBodyFrom req =
    (mempty :: RequestBody)
        { _requestBodyDescription = Just (reqDescription req)
        , _requestBodyRequired = Just (reqRequired req)
        , _requestBodyContent = bodyContent (reqSchema req)
        }

-- | One exact documented response, omitted when the document is OpenAPI's default.
exactResponseFrom :: ResponseDoc -> Maybe (Int, Referenced Response)
exactResponseFrom doc = case responseStatus doc of
    ExactResponse status -> Just (statusCode status, responseFrom doc)
    DefaultResponse -> Nothing

-- | Render one response document independently of how its status is keyed.
responseFrom :: ResponseDoc -> Referenced Response
responseFrom doc =
    Inline
        (mempty :: Response)
            { _responseDescription = responseDescription doc
            , _responseContent = bodyContent (responseBodySchema doc)
            }

{- | The OpenAPI content behind a body's 'BodySchema'. Each arm renders the media type, and a
codec body the schema, that the serve path itself uses, so the document cannot drift from the wire.
-}
bodyContent :: BodySchema -> InsOrd.InsOrdHashMap MediaType MediaTypeObject
bodyContent = \case
    SchemaEmpty -> mempty
    SchemaOpaque media -> mediaContent (mediaTypeOf media) (Inline binarySchema)
    SchemaText media -> mediaContent (mediaTypeOf media) (Inline (stringSchema Nothing))
    SchemaJson media c -> mediaContent (mediaTypeOf media) (Inline (schemaViaCodec c))
    SchemaDocumented media name -> mediaContent (mediaTypeOf media) (Ref (Reference name))
    SchemaPassthrough -> mediaContent "*/*" (Inline binarySchema)

mediaTypeOf :: ByteString -> MediaType
mediaTypeOf media = fromString (decodeUtf8 media :: String)

{- | Render an @autodocodec@ 'JSONCodec' to its OpenAPI schema (this tier only). The codec bodies
Écluse owns are flat, so the declared definitions are empty and the schema inlines.
-}
schemaViaCodec :: JSONCodec a -> Schema
schemaViaCodec c =
    let NamedSchema _ s = undeclare (declareNamedSchemaVia c Proxy)
     in s

-- | Render a route's 'ParamSpec' as an OpenAPI path parameter.
toParam :: ParamSpec -> Param
toParam p = pathParam (psName p) (psDescription p)

pathParam :: Text -> Text -> Param
pathParam name description =
    (mempty :: Param)
        { _paramName = name
        , _paramIn = ParamPath
        , _paramRequired = Just True
        , _paramDescription = Just description
        , _paramSchema = Just (Inline (stringSchema Nothing))
        }

mediaContent :: MediaType -> Referenced Schema -> InsOrd.InsOrdHashMap MediaType MediaTypeObject
mediaContent mediaType ref = InsOrd.singleton mediaType ((mempty :: MediaTypeObject){_mediaTypeObjectSchema = Just ref})

{- | A type-level handle for the synthesized packument's hand-written schema. It has no values:
the npm serve path builds the served packument, and no single Haskell type decodes it.
-}
data SynthesizedPackument

instance ToSchema SynthesizedPackument where
    declareNamedSchema _ = pure (NamedSchema (Just synthesizedPackumentSchemaName) synthesizedPackumentSchema)

-- | The @components.schemas@ name the synthesized packument is registered under.
synthesizedPackumentSchemaName :: Text
synthesizedPackumentSchemaName = "SynthesizedPackument"

{- | The __partial__ schema of the served packument: the documented __trust boundary__.

It models only the fields Écluse reads and transforms, and stays open everywhere else. A valid
instance is __not__ a proof that every @dist-tags@ target is a surviving @versions@ key, because
that cross-field coherence is not schema-expressible.
-}
synthesizedPackumentSchema :: Schema
synthesizedPackumentSchema =
    (mempty :: Schema)
        { _schemaTitle = Just "Synthesized packument"
        , _schemaType = Just OpenApiObject
        , _schemaDescription =
            Just
                "Écluse's merged-and-filtered view of a package's metadata. Versions are merged across \
                \upstreams and gated (private versions trusted, public versions admitted only by policy), \
                \and each version's `dist.tarball` is rewritten to resolve back through this proxy. Only \
                \the fields Écluse reads and transforms are modelled; every other field is relayed unchanged \
                \from the contributing upstream (the private upstream wins on a collision)."
        , _schemaRequired = ["name", "versions"]
        , _schemaProperties =
            InsOrd.fromList
                [ ("name", Inline (stringSchema (Just "The package name.")))
                , ("dist-tags", Inline distTagsSchema)
                , ("versions", Inline versionsSchema)
                , ("time", Inline timeSchema)
                ]
        , _schemaAdditionalProperties = Just (AdditionalPropertiesAllowed True)
        }
  where
    distTagsSchema =
        (mempty :: Schema)
            { _schemaType = Just OpenApiObject
            , _schemaDescription = Just "Tag to version string. `latest` is repointed to the newest surviving version after the gate."
            , _schemaAdditionalProperties = Just (AdditionalPropertiesSchema (Inline (stringSchema Nothing)))
            }
    versionsSchema =
        (mempty :: Schema)
            { _schemaType = Just OpenApiObject
            , _schemaDescription = Just "Surviving versions, keyed by version string."
            , _schemaAdditionalProperties = Just (AdditionalPropertiesSchema (Inline versionManifestSchema))
            }
    versionManifestSchema =
        (mempty :: Schema)
            { _schemaType = Just OpenApiObject
            , _schemaDescription = Just "A single version's manifest. Only the fields Écluse reads or transforms are modelled; the rest are relayed unchanged."
            , _schemaRequired = ["name", "version", "dist"]
            , _schemaProperties =
                InsOrd.fromList
                    [ ("name", Inline (stringSchema Nothing))
                    , ("version", Inline (stringSchema Nothing))
                    , ("dist", Inline distSchema)
                    ]
            , _schemaAdditionalProperties = Just (AdditionalPropertiesAllowed True)
            }
    distSchema =
        (mempty :: Schema)
            { _schemaType = Just OpenApiObject
            , _schemaDescription = Just "The artifact descriptor. `tarball` is rewritten to resolve through the proxy; `integrity`/`shasum` are preserved byte-for-byte so the client's own check still holds."
            , _schemaRequired = ["tarball"]
            , _schemaProperties =
                InsOrd.fromList
                    [ ("tarball", Inline (stringSchema (Just "Rewritten artifact URL, under this mount's prefix.")))
                    , ("integrity", Inline (stringSchema (Just "Subresource-Integrity string, preserved from upstream.")))
                    , ("shasum", Inline (stringSchema (Just "Legacy SHA-1 digest, preserved from upstream.")))
                    ]
            , _schemaAdditionalProperties = Just (AdditionalPropertiesAllowed True)
            }
    timeSchema =
        (mempty :: Schema)
            { _schemaType = Just OpenApiObject
            , _schemaDescription = Just "Publish timestamps: `created`, `modified`, and one entry per version."
            , _schemaAdditionalProperties = Just (AdditionalPropertiesSchema (Inline dateTimeSchema))
            }
    dateTimeSchema = (mempty :: Schema){_schemaType = Just OpenApiString, _schemaFormat = Just "date-time"}

stringSchema :: Maybe Text -> Schema
stringSchema description = (mempty :: Schema){_schemaType = Just OpenApiString, _schemaDescription = description}

binarySchema :: Schema
binarySchema =
    (mempty :: Schema)
        { _schemaType = Just OpenApiString
        , _schemaFormat = Just "binary"
        , _schemaDescription = Just "Opaque artifact bytes, streamed verbatim."
        }

publishDocumentSchema :: Schema
publishDocumentSchema =
    (mempty :: Schema)
        { _schemaType = Just OpenApiObject
        , _schemaAdditionalProperties = Just (AdditionalPropertiesAllowed True)
        , _schemaDescription = Just "The npm publish document, relayed to the publication target (its full shape is npm's, not re-specified here)."
        }

-- | The @components.schemas@ name the publish document is registered under.
publishDocumentSchemaName :: Text
publishDocumentSchemaName = "PublishDocument"

{- | Render the document to __byte-stable__ JSON. Sorted keys make the output independent of
insertion order, so the generated file is reproducible across runs and machines.
-}
renderManifest :: OpenApi -> LByteString
renderManifest =
    Pretty.encodePretty'
        Pretty.Config
            { Pretty.confIndent = Pretty.Spaces 2
            , Pretty.confCompare = compare
            , Pretty.confNumFormat = Pretty.Generic
            , Pretty.confTrailingNewline = True
            }

-- | The name PyPI's route records reference the filtered Simple index by.
simpleIndexSchemaName :: Text
simpleIndexSchemaName = "PyPISimpleIndex"

{- | The filtered PEP 691 Simple index a @pypi@ mount serves. Only the keys Écluse reads or
rewrites are modelled, and every other key relays unchanged from the contributing upstream.
-}
simpleIndexSchema :: Schema
simpleIndexSchema =
    (mempty :: Schema)
        { _schemaTitle = Just "Filtered Simple index"
        , _schemaType = Just OpenApiObject
        , _schemaDescription =
            Just
                "Écluse's merged-and-filtered view of a project's distribution files (PEP 691). Releases are \
                \merged across upstreams and gated (private releases trusted, public releases admitted only by \
                \policy), files that do not clear the integrity floor or that name an authority this mount does \
                \not honour are dropped, and each surviving file's `url` is rewritten to resolve back through \
                \this proxy. The PEP 658 `core-metadata` and `data-dist-info-metadata` keys are omitted, \
                \because Écluse serves no `.metadata` companion."
        , _schemaRequired = ["name", "files"]
        , _schemaProperties =
            InsOrd.fromList
                [ ("meta", Inline metaSchema)
                , ("name", Inline (stringSchema (Just "The project name in PEP 503 canonical form.")))
                , ("versions", Inline versionsSchema)
                , ("files", Inline filesSchema)
                ]
        , _schemaAdditionalProperties = Just (AdditionalPropertiesAllowed True)
        }
  where
    metaSchema =
        (mempty :: Schema)
            { _schemaType = Just OpenApiObject
            , _schemaDescription = Just "The index's own metadata, relayed from the contributing upstream so `_last-serial` still lets a mirror revalidate cheaply."
            , _schemaAdditionalProperties = Just (AdditionalPropertiesAllowed True)
            }
    versionsSchema =
        (mempty :: Schema)
            { _schemaType = Just OpenApiArray
            , _schemaDescription = Just "The surviving releases (PEP 700), in canonical PEP 440 form. A release the gate withheld does not appear."
            , _schemaItems = Just (OpenApiItemsObject (Inline (stringSchema Nothing)))
            }
    filesSchema =
        (mempty :: Schema)
            { _schemaType = Just OpenApiArray
            , _schemaDescription = Just "The surviving distribution files. A file the integrity floor or the artifact-host policy refused does not appear, and the served listing and the download gate therefore agree file by file."
            , _schemaItems = Just (OpenApiItemsObject (Inline fileSchema))
            }
    fileSchema =
        (mempty :: Schema)
            { _schemaType = Just OpenApiObject
            , _schemaRequired = ["filename", "url"]
            , _schemaProperties =
                InsOrd.fromList
                    [ ("filename", Inline (stringSchema (Just "The distribution file name, which encodes the project, the release, and a wheel's tags.")))
                    , ("url", Inline (stringSchema (Just "The file's location, rewritten under this mount so the bytes are fetched back through the gate.")))
                    ]
            , _schemaAdditionalProperties = Just (AdditionalPropertiesAllowed True)
            }
