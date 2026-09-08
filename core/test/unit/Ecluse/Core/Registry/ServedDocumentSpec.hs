-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

-- | Shared document contracts and artifact dropping through npm and PyPI assembly.
module Ecluse.Core.Registry.ServedDocumentSpec (spec) where

import Data.Aeson (Value (Array, Number, Object, String), object, (.=))
import Data.Aeson.Key (Key)
import Data.Aeson.KeyMap qualified as KeyMap
import Data.Map.Strict qualified as Map
import Data.Text qualified as T
import Hedgehog (forAll, (===))
import Hedgehog.Gen qualified as Gen
import Hedgehog.Range qualified as Range
import Test.Hspec
import Test.Hspec.Hedgehog (hedgehog)

import Ecluse.Core.Ecosystem (Ecosystem (Npm, PyPI))
import Ecluse.Core.Package (InvalidEntry (invalidKey, invalidKind), InvalidEntryKind (InvalidIndexFile, InvalidVersionManifest), PackageInfo (infoInvalidEntries), mkPackageName)
import Ecluse.Core.Package.Filter (enforceArtifactLocations)
import Ecluse.Core.Package.Merge (MergePlan (..), Provenance (GatedSource), SourceId, mergePackuments)
import Ecluse.Core.Registry.Npm.Filter (assembleMergedPackument)
import Ecluse.Core.Registry.Npm.Project (parsePackageInfoFromValue)
import Ecluse.Core.Registry.PyPI.Filter (assembleSimpleIndex)
import Ecluse.Core.Registry.PyPI.Project (projectSimpleIndexFromValue)
import Ecluse.Core.Registry.ServedDocument (overlaySurvivors, rebaseArtifactUrl, safeDocumentName)
import Ecluse.Core.Registry.WireSupport (Projection (NameMismatch, Projected))
import Ecluse.Core.Security (ecosystemArtifactAuthorities)
import Ecluse.Test.Registry.Npm qualified as Npm
import Ecluse.Test.Registry.PyPI (simpleFile, withFileKeys)
import Ecluse.Test.Support (expectRight)

-- | Pin source selection, name gates, and artifact rebasing after location admission.
spec :: Spec
spec = do
    overlaySpec
    nameGateSpec
    rebaseSpec
    droppedArtifactSpec

droppedArtifactSpec :: Spec
droppedArtifactSpec = describe "served artifact filename refusals" $
    for_ ["a\\..\\..\\x", ".", "..", ""] $ \filename -> do
        it ("drops and records an npm version whose URL ends in " <> show filename) $ do
            let version = Npm.versionValue (Npm.versionSpec "lodash" "1.0.0" ("https://registry.npmjs.org/" <> filename))
                source = Npm.packumentValue "lodash" "1.0.0" [("1.0.0", version)] [] []
            info <- projectedInfo =<< expectRight (parsePackageInfoFromValue (mkPackageName Npm Nothing "lodash") source)
            let kept = enforceArtifactLocations (ecosystemArtifactAuthorities []) "https://registry.npmjs.org" info
            map invalidKind (infoInvalidEntries kept) `shouldBe` [InvalidVersionManifest]
            map invalidKey (infoInvalidEntries kept) `shouldBe` ["1.0.0"]
            case mergePackuments [(GatedSource, kept)] of
                Nothing -> expectationFailure "expected a merge plan for the empty listing"
                Just plan ->
                    field "versions" (assembleMergedPackument "https://ecluse.test/npm" (Map.singleton 0 source) plan source)
                        `shouldBe` Just (Object mempty)

        for_ [False, True] $ \keepSibling ->
            it ("drops and records a PyPI file whose URL ends in " <> show filename <> ", sibling=" <> show keepSibling) $ do
                let refusedName = "requests-1.0.0.tar.gz"
                    siblingName = "requests-1.0.0-py3-none-any.whl"
                    refused = withFileKeys [("url", String ("https://files.pythonhosted.org/" <> filename))] (simpleFile refusedName)
                    files = refused : [simpleFile siblingName | keepSibling]
                    source = object ["name" .= ("requests" :: Text), "meta" .= object ["api-version" .= ("1.0" :: Text)], "files" .= files]
                    index = Map.fromList [(refusedName, "1.0.0"), (siblingName, "1.0.0")]
                info <- projectedInfo =<< expectRight (projectSimpleIndexFromValue (mkPackageName PyPI Nothing "requests") source)
                let kept = enforceArtifactLocations (ecosystemArtifactAuthorities ["https://files.pythonhosted.org"]) "https://pypi.org" info
                map invalidKind (infoInvalidEntries kept) `shouldBe` [if keepSibling then InvalidIndexFile else InvalidVersionManifest]
                map invalidKey (infoInvalidEntries kept) `shouldBe` [if keepSibling then refusedName else "1.0.0"]
                case mergePackuments [(GatedSource, kept)] of
                    Nothing -> expectationFailure "expected a merge plan for the listing"
                    Just plan -> do
                        let served = assembleSimpleIndex "https://ecluse.test/pypi" (Map.singleton 0 (source, index)) plan source
                            sibling = withFileKeys [("url", String ("https://ecluse.test/pypi/simple/requests/" <> siblingName))] (simpleFile siblingName)
                        field "files" served `shouldBe` Just (Array (fromList [sibling | keepSibling]))
                        field "versions" served `shouldBe` Just (Array (fromList [String "1.0.0" | keepSibling]))

projectedInfo :: Projection a -> IO a
projectedInfo = \case
    Projected info -> pure info
    NameMismatch name -> fail ("unexpected name mismatch: " <> toString name)

field :: Key -> Value -> Maybe Value
field key = \case
    Object o -> KeyMap.lookup key o
    _ -> Nothing

overlaySpec :: Spec
overlaySpec = describe "overlaySurvivors" $ do
    it "takes each survivor's entry from the source that won it" $
        overlay [(0, sourceOf [("1.0.0", "private"), ("2.0.0", "private")]), (1, sourceOf [("1.0.0", "public"), ("2.0.0", "public")])] [("1.0.0", 0), ("2.0.0", 1)]
            `shouldBe` [("1.0.0", "private"), ("2.0.0", "public")]

    it "yields survivors in key order, so the assembly is deterministic" $
        overlay [(0, sourceOf [("1.0.0", "a"), ("2.0.0", "a"), ("10.0.0", "a")])] [("2.0.0", 0), ("10.0.0", 0), ("1.0.0", 0)]
            `shouldBe` [("1.0.0", "a"), ("10.0.0", "a"), ("2.0.0", "a")]

    it "drops a survivor whose winning source holds no entry for it, never fabricating one" $
        overlay [(0, sourceOf [("1.0.0", "a")])] [("1.0.0", 0), ("2.0.0", 0)]
            `shouldBe` [("1.0.0", "a")]

    it "drops a survivor whose winning source is absent from the map" $
        overlay [(0, sourceOf [("1.0.0", "a")])] [("1.0.0", 0), ("2.0.0", 7)]
            `shouldBe` [("1.0.0", "a")]

    it "yields nothing for a plan with no survivors" $
        overlay [(0, sourceOf [("1.0.0", "a")])] [] `shouldBe` []

    it "resolves every survivor one source won, at any size" $
        hedgehog $ do
            count <- forAll (Gen.int (Range.linear 1 40))
            let versions = [show n | n <- [1 .. count :: Int]]
                survivors = [(v, 0 :: SourceId) | v <- versions]
            length (overlay [(0, sourceOf [(v, v) | v <- versions])] survivors) === count

nameGateSpec :: Spec
nameGateSpec = describe "safeDocumentName" $ do
    it "reads the name a document claims for itself when the parser admits it" $
        safeDocumentName parseName (documentNamed (String "lodash")) `shouldBe` Just "LODASH"

    it "refuses a name the parser rejects, so nothing interpolates it" $
        safeDocumentName parseName (documentNamed (String "../etc")) `shouldBe` Nothing

    it "refuses a document whose name is not a string" $
        safeDocumentName parseName (documentNamed (Number 1)) `shouldBe` Nothing

    it "refuses a document that claims no name at all" $
        safeDocumentName parseName KeyMap.empty `shouldBe` Nothing

    it "reads the parser the caller supplies, not a grammar of its own" $
        safeDocumentName (const (Nothing :: Maybe Text)) (documentNamed (String "lodash")) `shouldBe` Nothing

rebaseSpec :: Spec
rebaseSpec = describe "rebaseArtifactUrl" $ do
    it "declines a location the renderer will not render" $
        rebaseArtifactUrl (const Nothing) "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
            `shouldBe` (Nothing :: Maybe Text)

    it "points an upstream location back through the mount, keeping the file name verbatim" $
        rebaseArtifactUrl mountUrl "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
            `shouldBe` Just "https://ecluse.test/npm/lodash/-/lodash-4.17.21.tgz"

    it "reads the file name past a query string a signed location carries" $
        rebaseArtifactUrl mountUrl "https://cdn.test/a/lodash-4.17.21.tgz?sig=abc"
            `shouldBe` Just "https://ecluse.test/npm/lodash/-/lodash-4.17.21.tgz"

    it "leaves a location that names no file, rather than pointing it somewhere wrong" $ do
        rebaseArtifactUrl mountUrl "https://registry.npmjs.org/lodash/" `shouldBe` Nothing
        rebaseArtifactUrl mountUrl "" `shouldBe` Nothing

    for_ ["a\\..\\..\\x", ".", ".."] $ \filename ->
        it ("refuses to rebase " <> show filename) $
            rebaseArtifactUrl mountUrl ("https://registry.npmjs.org/" <> filename) `shouldBe` Nothing

    it "is idempotent: rebasing an already-rebased URL yields the same URL" $
        hedgehog $ do
            file <- forAll (Gen.text (Range.linear 1 20) Gen.alphaNum)
            let once = rebaseArtifactUrl mountUrl ("https://upstream.test/x/" <> file <> ".tgz")
            (once >>= rebaseArtifactUrl mountUrl) === once

overlay :: [(SourceId, Value)] -> [(Text, SourceId)] -> [(Text, Value)]
overlay sources survivors =
    overlaySurvivors versionIn (Map.fromList sources) (planOver (Map.fromList survivors))
  where
    versionIn source version = case source of
        Object o | Just (Object vs) <- KeyMap.lookup "versions" o -> KeyMap.lookup (fromString (toString version)) vs
        _ -> Nothing

sourceOf :: [(Text, Text)] -> Value
sourceOf entries = object ["versions" .= object [(fromString (toString version), String marker) | (version, marker) <- entries]]

planOver :: Map Text SourceId -> MergePlan
planOver survivors =
    MergePlan
        { mpName = mkPackageName Npm Nothing "lodash"
        , mpSurvivors = survivors
        , mpArtifacts = Map.map (const ("x.tgz" :| [])) survivors
        , mpDistTags = Map.empty
        , mpTime = Map.empty
        , mpDivergences = mempty
        }

documentNamed :: Value -> KeyMap.KeyMap Value
documentNamed = KeyMap.singleton "name"

parseName :: Text -> Maybe Text
parseName raw = do
    guard (not (T.null raw) && T.all (`elem` ("abcdefghijklmnopqrstuvwxyz-." :: String)) raw && not (T.isInfixOf ".." raw))
    pure (T.toUpper raw)

mountUrl :: Text -> Maybe Text
mountUrl file = Just ("https://ecluse.test/npm/lodash/-/" <> file)
