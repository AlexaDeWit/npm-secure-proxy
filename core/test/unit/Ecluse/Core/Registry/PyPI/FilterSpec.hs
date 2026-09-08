-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

-- | PyPI assembly preserves admitted entries and refuses locations it cannot rebase.
module Ecluse.Core.Registry.PyPI.FilterSpec (spec) where

import Data.Aeson (Value (Array, Number, Object, String), object, toJSON, (.=))
import Data.Aeson.KeyMap qualified as KeyMap
import Data.Map.Strict qualified as Map
import Test.Hspec

import Ecluse.Core.Ecosystem (Ecosystem (PyPI))
import Ecluse.Core.Package (PackageName, mkPackageName)
import Ecluse.Core.Package.Merge (MergePlan (..), SourceId)
import Ecluse.Core.Registry.PyPI.Filter (assembleSimpleIndex)
import Ecluse.Test.Package (validSha256)
import Ecluse.Test.Registry.PyPI (simpleFile, withFileKeys)

-- | Pin PyPI source selection, artifact rebasing, and sidecar removal.
spec :: Spec
spec = do
    relaySpec
    survivorSpec
    rebaseSpec
    sidecarSpec

relaySpec :: Spec
relaySpec = describe "what the assembly relays from the base document" $ do
    it "keeps meta, so a mirror still reads the serial it revalidates against" $
        field "meta" (assembleOne allFiles)
            `shouldBe` Just (object ["api-version" .= ("1.4" :: Text), "_last-serial" .= (37059094 :: Int)])

    it "keeps the project name the winning document reported" $
        field "name" (assembleOne allFiles) `shouldBe` Just (String "requests")

    it "keeps a top-level key this build does not model" $
        field "tracks" (assembleOne allFiles) `shouldBe` Just (Array mempty)

    it "keeps every modelled key on a served file entry, verbatim" $ do
        let entry = servedEntry (assembleOne allFiles) "requests-2.34.2-py3-none-any.whl"
        (entry >>= KeyMap.lookup "upload-time") `shouldBe` Just (String "2026-05-14T19:25:26Z")
        (entry >>= KeyMap.lookup "requires-python") `shouldBe` Just (String ">=3.10")
        (entry >>= KeyMap.lookup "size") `shouldBe` Just (Number 73075)
        (entry >>= KeyMap.lookup "yanked") `shouldBe` Just (String "withdrawn")
        (entry >>= KeyMap.lookup "hashes") `shouldBe` Just (object ["sha256" .= validSha256])

    it "keeps an unmodelled key on a served file entry too" $
        (servedEntry (assembleOne allFiles) "requests-2.34.2-py3-none-any.whl" >>= KeyMap.lookup "provenance")
            `shouldBe` Just (String "https://pypi.org/integrity/x/provenance")

    it "yields an object even for a base document that is not one" $
        assembleSimpleIndex mountBase (Map.singleton 0 (indexOf allFiles, fileIndex)) (planOver [("2.34.2", 0)] [("2.34.2", ["requests-2.34.2.tar.gz"])]) (String "not an index")
            `shouldSatisfy` isObject

survivorSpec :: Spec
survivorSpec = describe "which releases and files the assembly serves" $ do
    it "names the surviving releases in the PEP 700 versions array, and no others" $
        field "versions" (assembleOne allFiles) `shouldBe` Just (Array (fromList [String "2.34.2"]))

    it "omits a release the plan did not keep, files and all" $
        servedNames (assembleOne allFiles) `shouldNotContain` ["requests-2.34.1.tar.gz"]

    it "omits a file the per-artifact partition dropped from a surviving release" $ do
        let served = assemble [("2.34.2", 0)] [("2.34.2", ["requests-2.34.2-py3-none-any.whl"])]
        servedNames served `shouldBe` ["requests-2.34.2-py3-none-any.whl"]

    it "takes each release's files from the source that won it" $ do
        let served =
                assembleSources
                    [(0, (indexNamed "requests" [privateFile], privateIndex)), (1, (indexOf allFiles, fileIndex))]
                    [("2.34.2", 0)]
                    [("2.34.2", ["requests-2.34.2-private.tar.gz"])]
        servedNames served `shouldBe` ["requests-2.34.2-private.tar.gz"]

    it "drops a named file the winning source does not hold, never fabricating one" $
        servedNames (assemble [("2.34.2", 0)] [("2.34.2", ["requests-2.34.2-absent.whl"])]) `shouldBe` []

    it "serves nothing at all for a plan with no survivors" $ do
        let served = assemble [] []
        field "versions" served `shouldBe` Just (Array mempty)
        servedNames served `shouldBe` []

rebaseSpec :: Spec
rebaseSpec = describe "where a served file points" $ do
    for_ [String "https://files.pythonhosted.org/a\\..\\x", String "https://files.pythonhosted.org/%2e%2e", String "https://files.pythonhosted.org/a%2fb", String "https://files.pythonhosted.org/.. ", Number 1] $ \url ->
        it ("omits a duplicate named entry whose URL cannot be rebased: " <> show url) $ do
            let filename = "requests-2.34.2.tar.gz"
                valid = simpleFile filename
                refused = withFileKeys [("url", url)] valid
                expected = withFileKeys [("url", String (mountBase <> "/simple/requests/" <> filename))] valid
            servedFiles (assembleOne [refused, valid]) `shouldBe` [expected]
            servedFiles (assembleOne [valid, refused]) `shouldBe` [expected]

    it "omits a duplicate named entry with no URL" $ do
        let filename = "requests-2.34.2.tar.gz"
            missing = object ["filename" .= filename]
        servedFiles (assembleOne [missing, simpleFile filename])
            `shouldBe` servedFiles (assembleOne [simpleFile filename])

    it "rebases a file location onto this mount under the artifact route's own spelling" $
        (servedEntry (assembleOne allFiles) "requests-2.34.2-py3-none-any.whl" >>= KeyMap.lookup "url")
            `shouldBe` Just (String "https://ecluse.test/pypi/simple/requests/requests-2.34.2-py3-none-any.whl")

    it "rebases under the requested project, not the spelling the document reported" $ do
        let served =
                assembleSimpleIndex
                    mountBase
                    (Map.singleton 0 (zopeIndex, Map.singleton zopeFile "7.2"))
                    (planFor zopeInterface [("7.2", 0)] [("7.2", [zopeFile])])
                    zopeIndex
        (servedEntry served zopeFile >>= KeyMap.lookup "url")
            `shouldBe` Just (String ("https://ecluse.test/pypi/simple/zope-interface/" <> zopeFile))

sidecarSpec :: Spec
sidecarSpec = describe "the PEP 658 sidecar keys" $
    it "drops both spellings, because Écluse serves no .metadata companion" $ do
        let entry = servedEntry (assembleOne allFiles) "requests-2.34.2-py3-none-any.whl"
        (entry >>= KeyMap.lookup "core-metadata") `shouldBe` Nothing
        (entry >>= KeyMap.lookup "data-dist-info-metadata") `shouldBe` Nothing

mountBase :: Text
mountBase = "https://ecluse.test/pypi"

assembleOne :: [Value] -> Value
assembleOne files =
    assembleSources [(0, (indexOf files, fileIndex))] [("2.34.2", 0)] [("2.34.2", ["requests-2.34.2.tar.gz", "requests-2.34.2-py3-none-any.whl"])]

assemble :: [(Text, SourceId)] -> [(Text, [Text])] -> Value
assemble = assembleSources [(0, (indexOf allFiles, fileIndex))]

assembleSources :: [(SourceId, (Value, Map Text Text))] -> [(Text, SourceId)] -> [(Text, [Text])] -> Value
assembleSources sources survivors kept =
    assembleSimpleIndex mountBase (Map.fromList sources) (planOver survivors kept) (fst (snd (headSource sources)))
  where
    headSource = \case
        source : _ -> source
        [] -> (0, (Object mempty, mempty))

planOver :: [(Text, SourceId)] -> [(Text, [Text])] -> MergePlan
planOver = planFor (mkPackageName PyPI Nothing "requests")

planFor :: PackageName -> [(Text, SourceId)] -> [(Text, [Text])] -> MergePlan
planFor name survivors kept =
    MergePlan
        { mpName = name
        , mpSurvivors = Map.fromList survivors
        , mpArtifacts = Map.fromList [(version, fromList files) | (version, files) <- kept, not (null files)]
        , mpDistTags = Map.empty
        , mpTime = Map.empty
        , mpDivergences = mempty
        }

indexOf :: [Value] -> Value
indexOf = indexNamed "requests"

indexNamed :: Text -> [Value] -> Value
indexNamed name files =
    object
        [ "name" .= name
        , "meta" .= object ["api-version" .= ("1.4" :: Text), "_last-serial" .= (37059094 :: Int)]
        , "tracks" .= Array mempty
        , "files" .= files
        ]

allFiles :: [Value]
allFiles =
    [ fileNamed "requests-2.34.2.tar.gz"
    , fileNamed "requests-2.34.2-py3-none-any.whl"
    , fileNamed "requests-2.34.1.tar.gz"
    ]

privateFile :: Value
privateFile = fileNamed "requests-2.34.2-private.tar.gz"

zopeInterface :: PackageName
zopeInterface = mkPackageName PyPI Nothing "zope-interface"

zopeIndex :: Value
zopeIndex = indexNamed "Zope.Interface" [fileNamed zopeFile]

zopeFile :: Text
zopeFile = "zope_interface-7.2-py3-none-any.whl"

fileIndex :: Map Text Text
fileIndex =
    Map.fromList
        [ ("requests-2.34.2.tar.gz", "2.34.2")
        , ("requests-2.34.2-py3-none-any.whl", "2.34.2")
        , ("requests-2.34.1.tar.gz", "2.34.1")
        ]

privateIndex :: Map Text Text
privateIndex = Map.singleton "requests-2.34.2-private.tar.gz" "2.34.2"

fileNamed :: Text -> Value
fileNamed filename =
    withFileKeys
        [ ("size", toJSON (73075 :: Int))
        , ("yanked", toJSON ("withdrawn" :: Text))
        , ("core-metadata", object ["sha256" .= sidecarDigest])
        , ("data-dist-info-metadata", object ["sha256" .= sidecarDigest])
        ]
        (simpleFile filename)

sidecarDigest :: Text
sidecarDigest = "8c384ba3"

field :: Text -> Value -> Maybe Value
field key = \case
    Object o -> KeyMap.lookup (fromString (toString key)) o
    _ -> Nothing

servedFiles :: Value -> [Value]
servedFiles served = case field "files" served of
    Just (Array files) -> toList files
    _ -> []

servedNames :: Value -> [Text]
servedNames = mapMaybe name . servedFiles
  where
    name = \case
        Object entry | Just (String filename) <- KeyMap.lookup "filename" entry -> Just filename
        _ -> Nothing

servedEntry :: Value -> Text -> Maybe (KeyMap.KeyMap Value)
servedEntry served filename = listToMaybe [entry | Object entry <- servedFiles served, KeyMap.lookup "filename" entry == Just (String filename)]

isObject :: Value -> Bool
isObject = \case
    Object _ -> True
    _ -> False
