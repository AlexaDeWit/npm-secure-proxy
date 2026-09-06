-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

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
        -- The partition keeps a release while dropping the files of it that could not be
        -- gated, so the listing must name the survivors alone.
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
    it "rebases a file location onto this mount under the artifact route's own spelling" $
        (servedEntry (assembleOne allFiles) "requests-2.34.2-py3-none-any.whl" >>= KeyMap.lookup "url")
            `shouldBe` Just (String "https://ecluse.test/pypi/simple/requests/requests-2.34.2-py3-none-any.whl")

    it "rebases under the requested project, not the spelling the document reported" $ do
        -- An index may report the published spelling of a name whose canonical form the request
        -- used. Agreement is checked before the assembly, so the location renders under the
        -- canonical name the distribution route claims rather than one it would 404.
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

-- | The mount every example serves under.
mountBase :: Text
mountBase = "https://ecluse.test/pypi"

-- | Assemble from one public source holding the given files, keeping @2.34.2@ entire.
assembleOne :: [Value] -> Value
assembleOne files =
    assembleSources [(0, (indexOf files, fileIndex))] [("2.34.2", 0)] [("2.34.2", ["requests-2.34.2.tar.gz", "requests-2.34.2-py3-none-any.whl"])]

-- | Assemble from the standard one-source index with the given survivors and kept files.
assemble :: [(Text, SourceId)] -> [(Text, [Text])] -> Value
assemble = assembleSources [(0, (indexOf allFiles, fileIndex))]

-- | Assemble from explicit sources, survivors, and kept files.
assembleSources :: [(SourceId, (Value, Map Text Text))] -> [(Text, SourceId)] -> [(Text, [Text])] -> Value
assembleSources sources survivors kept =
    assembleSimpleIndex mountBase (Map.fromList sources) (planOver survivors kept) (fst (snd (headSource sources)))
  where
    headSource = \case
        source : _ -> source
        [] -> (0, (Object mempty, mempty))

-- | A merge plan for @requests@, carrying the survivors and the files the partition kept.
planOver :: [(Text, SourceId)] -> [(Text, [Text])] -> MergePlan
planOver = planFor (mkPackageName PyPI Nothing "requests")

-- | 'planOver' for a project of the caller's choosing.
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

-- | The index every example reads, under the canonical project name.
indexOf :: [Value] -> Value
indexOf = indexNamed "requests"

-- | An index reporting the given name, with a @meta@ object and an unmodelled top-level key.
indexNamed :: Text -> [Value] -> Value
indexNamed name files =
    object
        [ "name" .= name
        , "meta" .= object ["api-version" .= ("1.4" :: Text), "_last-serial" .= (37059094 :: Int)]
        , "tracks" .= Array mempty
        , "files" .= files
        ]

-- | The files the standard index offers: two of @2.34.2@ and one of a release that did not survive.
allFiles :: [Value]
allFiles =
    [ fileNamed "requests-2.34.2.tar.gz"
    , fileNamed "requests-2.34.2-py3-none-any.whl"
    , fileNamed "requests-2.34.1.tar.gz"
    ]

-- | The file the private source offers for @2.34.2@.
privateFile :: Value
privateFile = fileNamed "requests-2.34.2-private.tar.gz"

{- | A project published under a non-canonical spelling, with the index reporting that spelling
for itself as a real one does.
-}
zopeInterface :: PackageName
zopeInterface = mkPackageName PyPI Nothing "zope-interface"

zopeIndex :: Value
zopeIndex = indexNamed "Zope.Interface" [fileNamed zopeFile]

zopeFile :: Text
zopeFile = "zope_interface-7.2-py3-none-any.whl"

-- | Which release each file of the standard index belongs to.
fileIndex :: Map Text Text
fileIndex =
    Map.fromList
        [ ("requests-2.34.2.tar.gz", "2.34.2")
        , ("requests-2.34.2-py3-none-any.whl", "2.34.2")
        , ("requests-2.34.1.tar.gz", "2.34.1")
        ]

-- | Which release the private source's file belongs to.
privateIndex :: Map Text Text
privateIndex = Map.singleton "requests-2.34.2-private.tar.gz" "2.34.2"

{- | The shared entry with the keys this module's examples add: the two the assembly must drop,
the two it must relay, and a size.
-}
fileNamed :: Text -> Value
fileNamed filename =
    withFileKeys
        [ ("size", toJSON (73075 :: Int))
        , ("yanked", toJSON ("withdrawn" :: Text))
        , ("core-metadata", object ["sha256" .= sidecarDigest])
        , ("data-dist-info-metadata", object ["sha256" .= sidecarDigest])
        ]
        (simpleFile filename)

-- | The digest a PEP 658 sidecar entry carries, which no served entry keeps.
sidecarDigest :: Text
sidecarDigest = "8c384ba3"

-- | One top-level key of an assembled index.
field :: Text -> Value -> Maybe Value
field key = \case
    Object o -> KeyMap.lookup (fromString (toString key)) o
    _ -> Nothing

-- | The served file entries, in the order the assembly placed them.
servedFiles :: Value -> [Value]
servedFiles served = case field "files" served of
    Just (Array files) -> toList files
    _ -> []

-- | The names of the served file entries.
servedNames :: Value -> [Text]
servedNames = mapMaybe name . servedFiles
  where
    name = \case
        Object entry | Just (String filename) <- KeyMap.lookup "filename" entry -> Just filename
        _ -> Nothing

-- | The served entry under the given file name.
servedEntry :: Value -> Text -> Maybe (KeyMap.KeyMap Value)
servedEntry served filename = listToMaybe [entry | Object entry <- servedFiles served, KeyMap.lookup "filename" entry == Just (String filename)]

-- | Whether an assembled document is a JSON object.
isObject :: Value -> Bool
isObject = \case
    Object _ -> True
    _ -> False
