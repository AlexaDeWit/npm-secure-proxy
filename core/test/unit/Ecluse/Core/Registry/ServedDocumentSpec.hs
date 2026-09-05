-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Core.Registry.ServedDocumentSpec (spec) where

import Data.Aeson (Value (Number, Object, String), object, (.=))
import Data.Aeson.KeyMap qualified as KeyMap
import Data.Map.Strict qualified as Map
import Data.Text qualified as T
import Hedgehog (forAll, (===))
import Hedgehog.Gen qualified as Gen
import Hedgehog.Range qualified as Range
import Test.Hspec
import Test.Hspec.Hedgehog (hedgehog)

import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.Package (mkPackageName)
import Ecluse.Core.Package.Merge (MergePlan (..), SourceId)
import Ecluse.Core.Registry.ServedDocument (overlaySurvivors, rebaseArtifactUrl, safeDocumentName)

spec :: Spec
spec = do
    overlaySpec
    nameGateSpec
    rebaseSpec

overlaySpec :: Spec
overlaySpec = describe "overlaySurvivors" $ do
    it "takes each survivor's entry from the source that won it" $
        overlay [(0, sourceOf [("1.0.0", "private"), ("2.0.0", "private")]), (1, sourceOf [("1.0.0", "public"), ("2.0.0", "public")])] [("1.0.0", 0), ("2.0.0", 1)]
            `shouldBe` [("1.0.0", "private"), ("2.0.0", "public")]

    it "yields survivors in ascending version order, so the assembly is deterministic" $
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
    it "reads the name a document claims for itself when the grammar admits it" $
        safeDocumentName npmName (documentNamed (String "lodash")) `shouldBe` Just "lodash"

    it "refuses a name the grammar rejects, so nothing interpolates it" $
        safeDocumentName npmName (documentNamed (String "../etc")) `shouldBe` Nothing

    it "refuses a document whose name is not a string" $
        safeDocumentName npmName (documentNamed (Number 1)) `shouldBe` Nothing

    it "refuses a document that claims no name at all" $
        safeDocumentName npmName KeyMap.empty `shouldBe` Nothing

    it "reads the grammar the caller supplies, not one of its own" $
        -- The gate is shared; which names are legal is each ecosystem's to say.
        safeDocumentName (const False) (documentNamed (String "lodash")) `shouldBe` Nothing

rebaseSpec :: Spec
rebaseSpec = describe "rebaseArtifactUrl" $ do
    it "points an upstream location back through the mount, keeping the file name verbatim" $
        rebaseArtifactUrl mountUrl "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
            `shouldBe` Just "https://ecluse.test/npm/lodash/-/lodash-4.17.21.tgz"

    it "reads the file name past a query string a signed location carries" $
        rebaseArtifactUrl mountUrl "https://cdn.test/a/lodash-4.17.21.tgz?sig=abc"
            `shouldBe` Just "https://ecluse.test/npm/lodash/-/lodash-4.17.21.tgz"

    it "leaves a location that names no file, rather than pointing it somewhere wrong" $ do
        rebaseArtifactUrl mountUrl "https://registry.npmjs.org/lodash/" `shouldBe` Nothing
        rebaseArtifactUrl mountUrl "" `shouldBe` Nothing

    it "is idempotent: rebasing an already-rebased URL yields the same URL" $
        hedgehog $ do
            file <- forAll (Gen.text (Range.linear 1 20) Gen.alphaNum)
            let once = rebaseArtifactUrl mountUrl ("https://upstream.test/x/" <> file <> ".tgz")
            (once >>= rebaseArtifactUrl mountUrl) === once

-- | Run 'overlaySurvivors' over sources and a survivor map, with the versions object as index.
overlay :: [(SourceId, Value)] -> [(Text, SourceId)] -> [(Text, Value)]
overlay sources survivors =
    overlaySurvivors versionIn (Map.fromList sources) (planOver (Map.fromList survivors))
  where
    versionIn source version = case source of
        Object o | Just (Object vs) <- KeyMap.lookup "versions" o -> KeyMap.lookup (fromString (toString version)) vs
        _ -> Nothing

-- | A source document holding one entry per version, each a distinguishable marker.
sourceOf :: [(Text, Text)] -> Value
sourceOf entries = object ["versions" .= object [(fromString (toString version), String marker) | (version, marker) <- entries]]

-- | A merge plan carrying only the survivor map these examples exercise.
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

-- | A document claiming the given value as its own name.
documentNamed :: Value -> KeyMap.KeyMap Value
documentNamed = KeyMap.singleton "name"

-- | A grammar standing in for an ecosystem's: a safe path component of ASCII letters.
npmName :: Text -> Bool
npmName raw = not (T.null raw) && T.all (`elem` ("abcdefghijklmnopqrstuvwxyz-." :: String)) raw && not (T.isInfixOf ".." raw)

-- | The mount-local URL a rebased file resolves to.
mountUrl :: Text -> Text
mountUrl file = "https://ecluse.test/npm/lodash/-/" <> file
