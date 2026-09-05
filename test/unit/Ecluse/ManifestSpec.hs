-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.ManifestSpec (spec) where

import Prelude hiding (universe)

import Data.Aeson (Value (Object), decode)
import Data.Aeson.KeyMap qualified as KeyMap
import Data.HashMap.Strict.InsOrd qualified as InsOrd
import Data.HashSet.InsOrd qualified as InsOrdSet
import Data.List (nub)
import Data.Text qualified as T
import Data.Universe.Class (Universe (universe))

import Data.OpenApi (
    Components (_componentsSchemas),
    OpenApi (_openApiComponents, _openApiInfo, _openApiPaths, _openApiServers),
    Operation (_operationResponses, _operationTags),
    PathItem,
    Referenced (Inline),
    Response (_responseContent),
    Responses (_responsesDefault, _responsesResponses),
    _infoTitle,
    _pathItemDelete,
    _pathItemGet,
    _pathItemHead,
    _pathItemPost,
    _pathItemPut,
 )
import Network.HTTP.Types.Method (StdMethod (DELETE, GET, HEAD, POST, PUT), renderStdMethod)
import Test.Hspec

import Ecluse.Core.Ecosystem (Ecosystem (Npm), ecosystemName, prefixFor)
import Ecluse.Core.Registry.Adapter (adapterFor)
import Ecluse.Core.Registry.Adapter.Types (AdapterServe (serveRoutes), RegistryAdapter (adapterServe))
import Ecluse.Core.Registry.Npm.Route (npmRoutes)
import Ecluse.Core.Server.Contract (ResponseDoc (responseStatus))
import Ecluse.Core.Server.Route (matchRoute)
import Ecluse.Core.Server.RouteSpec (RouteSpec (rsMethod, rsOutcomes))
import Ecluse.Manifest (
    ManifestSource (manifestEcosystems),
    buildOpenApi,
    canonicalManifestSource,
    publishDocumentSchemaName,
    renderManifest,
    routePathKey,
    synthesizedPackumentSchemaName,
 )

spec :: Spec
spec = do
    describe "buildOpenApi (canonical npm mount)" $ do
        it "renders a well-formed OpenAPI document (openapi/info/paths present)" $
            case decode (renderManifest doc) :: Maybe Value of
                Just (Object o) -> do
                    KeyMap.member "openapi" o `shouldBe` True
                    KeyMap.member "info" o `shouldBe` True
                    KeyMap.member "paths" o `shouldBe` True
                _ -> expectationFailure "the manifest did not render as a JSON object"

        it "carries a non-empty title and a server entry" $ do
            _infoTitle (_openApiInfo doc) `shouldNotBe` ""
            _openApiServers doc `shouldNotSatisfy` null

        it "registers the owned hand-authored schemas in components" $ do
            let schemas = _componentsSchemas (_openApiComponents doc)
            InsOrd.member synthesizedPackumentSchemaName schemas `shouldBe` True
            InsOrd.member publishDocumentSchemaName schemas `shouldBe` True

        it "emits top-level keys in sorted order (deterministic key ordering)" $ do
            let rendered = decodeUtf8 (renderManifest doc) :: Text
                topKeys = ["components", "info", "openapi", "paths", "servers", "tags"]
                marker k = "\n  \"" <> k <> "\":"
                offsetOf k = T.length (fst (T.breakOn (marker k) rendered))
            all (\k -> marker k `T.isInfixOf` rendered) topKeys `shouldBe` True
            -- Ascending offsets prove confCompare = compare is in effect, so the output
            -- does not depend on insertion order.
            map offsetOf topKeys `shouldBe` sort (map offsetOf topKeys)

    -- The manifest's specs are the documentation projection ('specsOf') of the same route
    -- records the classifier routes on, so paths and methods agree by construction. These
    -- cases assert that the projection reaches the rendered document, for every adapter this
    -- build registers rather than for npm alone.
    describe "documented routes correspond to the live classifier" $ do
        for_ registeredEcosystems agreesWithClassifier

        it "the manifest's path keys are exactly the rendered route templates" $
            sort (InsOrd.keys (_openApiPaths agreementDoc))
                `shouldBe` sort (ordNub (concatMap renderedKeys (toList registeredEcosystems)))

    describe "documented statuses and boundaries" $ do
        it "a path claimed by no documented route denies by default" $
            -- The catch-all the manifest documents is real: no route in the table claims
            -- this path, so the router answers it with the deny-by-default 404.
            isJust (matchRoute npmRoutes (renderStdMethod GET) [] ["not", "a", "known", "route"]) `shouldBe` False
        it "Search carries 501" $
            (statusCodes <$> getOp "/npm/-/v1/search") `shouldBe` Just [501]
        it "the dist-tag read, write, and removal all carry 501" $ do
            (statusCodes <$> getOp "/npm/-/package/{package}/dist-tags") `shouldBe` Just [501]
            (statusCodes <$> putOp "/npm/-/package/{package}/dist-tags/{tag}") `shouldBe` Just [501]
            (statusCodes <$> deleteOp "/npm/-/package/{package}/dist-tags/{tag}") `shouldBe` Just [501]
        it "the deny-by-default catch-all carries 404" $
            (statusCodes <$> getOp "/npm/{unsupportedPath}") `shouldBe` Just [404]
        it "the packument GET documents the gate statuses" $
            (statusCodes <$> getOp "/npm/{package}") `shouldBe` Just [200, 304, 401, 403, 404, 500, 502, 503]
        it "the derived packument HEAD documents the same statuses with no bodies" $
            case headOp "/npm/{package}" of
                Nothing -> expectationFailure "packument HEAD was not rendered"
                Just op -> do
                    statusCodes op `shouldBe` [200, 304, 401, 403, 404, 500, 502, 503]
                    responsesAreBodiless op `shouldBe` True
        it "the tarball GET honestly documents its transparent upstream relay" $
            (defaultMediaTypes <$> getOp "/npm/{package}/-/{filename}")
                `shouldBe` Just ["*/*"]
        it "the publish PUT honestly documents arbitrary JSON-labelled target replies" $
            (defaultMediaTypes <$> putOp "/npm/{package}")
                `shouldBe` Just ["application/json"]
        it "operations are tagged by ecosystem (npm)" $
            (InsOrdSet.member "npm" . _operationTags <$> getOp "/npm/{package}") `shouldBe` Just True
  where
    doc :: OpenApi
    doc = buildOpenApi canonicalManifestSource

    getOp :: FilePath -> Maybe Operation
    getOp p = InsOrd.lookup p (_openApiPaths doc) >>= _pathItemGet

    headOp :: FilePath -> Maybe Operation
    headOp p = InsOrd.lookup p (_openApiPaths doc) >>= _pathItemHead

    putOp :: FilePath -> Maybe Operation
    putOp p = InsOrd.lookup p (_openApiPaths doc) >>= _pathItemPut

    deleteOp :: FilePath -> Maybe Operation
    deleteOp p = InsOrd.lookup p (_openApiPaths doc) >>= _pathItemDelete

    statusCodes :: Operation -> [Int]
    statusCodes = sort . InsOrd.keys . _responsesResponses . _operationResponses

    defaultMediaTypes :: Operation -> [String]
    defaultMediaTypes =
        maybe [] responseMediaTypes . _responsesDefault . _operationResponses

    responseMediaTypes :: Referenced Response -> [String]
    responseMediaTypes = \case
        Inline resp -> sort (map show (InsOrd.keys (_responseContent resp)))
        _ -> []

    responsesAreBodiless :: Operation -> Bool
    responsesAreBodiless op =
        all (null . responseMediaTypes) exact
            && maybe True (null . responseMediaTypes) (_responsesDefault responses)
      where
        responses = _operationResponses op
        exact = InsOrd.elems (_responsesResponses responses)

{- | The agreement cases for one registered ecosystem, generic in it so a second adapter is held
to the same agreement the day it registers.
-}
agreesWithClassifier :: Ecosystem -> Spec
agreesWithClassifier eco =
    describe (toString (ecosystemName eco)) $ do
        it "exposes a route grammar" $
            null specs `shouldBe` False

        it "each documented route is rendered under its declared method" $
            for_ specs $ \rs ->
                (lookupPath rs >>= operationForMethod (rsMethod rs)) `shouldSatisfy` isJust

        it "each operation has one document per response key" $
            for_ specs $ \rs -> do
                let keys = map responseStatus (rsOutcomes rs)
                keys `shouldBe` nub keys
  where
    specs = specsFor eco
    lookupPath rs = InsOrd.lookup (renderedKeyFor eco rs) (_openApiPaths agreementDoc)

{- | Every ecosystem this build registers an adapter for. npm heads the list because 'adapterFor'
answers for it unconditionally, which keeps the value non-empty without a partial construction.
-}
registeredEcosystems :: NonEmpty Ecosystem
registeredEcosystems = Npm :| filter registeredBeside universe
  where
    registeredBeside eco = eco /= Npm && isJust (adapterFor eco)

{- | The document the agreement cases read: the canonical source widened to every registered
adapter, so a newly registered one is checked before the canonical mount list catches up.
-}
agreementDoc :: OpenApi
agreementDoc = buildOpenApi canonicalManifestSource{manifestEcosystems = registeredEcosystems}

-- An ecosystem's declarative route grammar, through the same registry the composition root mounts.
specsFor :: Ecosystem -> [RouteSpec]
specsFor eco = maybe [] (toList . serveRoutes . adapterServe) (adapterFor eco)

-- An ecosystem's manifest path keys, rendered the way the manifest renders them.
renderedKeys :: Ecosystem -> [FilePath]
renderedKeys eco = map (renderedKeyFor eco) (specsFor eco)

renderedKeyFor :: Ecosystem -> RouteSpec -> FilePath
renderedKeyFor eco = toString . routePathKey (prefixFor eco)

operationForMethod :: StdMethod -> PathItem -> Maybe Operation
operationForMethod = \case
    GET -> _pathItemGet
    HEAD -> _pathItemHead
    POST -> _pathItemPost
    PUT -> _pathItemPut
    DELETE -> _pathItemDelete
    _ -> const Nothing
