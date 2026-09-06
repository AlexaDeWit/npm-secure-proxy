-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Core.Registry.PyPI.SelectiveDecodeSpec (spec) where

import Data.Aeson (Value (Object, String), encode, object, (.=))
import Data.Aeson.KeyMap qualified as KeyMap
import Data.ByteString.Lazy qualified as BL
import Data.Text qualified as T
import Test.Hspec

import Ecluse.Test.Registry.PyPI (simpleFile)

import Ecluse.Core.Registry.PyPI.SelectiveDecode (
    SelectedFiles (sfFileCount, sfFiles, sfName),
    SelectiveError (SelectiveTooDeeplyNested, SelectiveUndecodable),
    selectFilesFromIndex,
 )

spec :: Spec
spec = do
    selectionSpec
    volumeSpec
    faithfulnessSpec

selectionSpec :: Spec
selectionSpec = describe "selectFilesFromIndex" $ do
    it "materialises the files of the requested release and no others" $ do
        selected <- shouldSelect (belongsTo "2.34.2") (indexOf ["requests-2.34.2.tar.gz", "requests-2.34.2-py3-none-any.whl", "requests-2.34.1.tar.gz"])
        selectedNames selected `shouldBe` ["requests-2.34.2.tar.gz", "requests-2.34.2-py3-none-any.whl"]

    it "reads the index's self-reported name, the anti-shadowing authority" $ do
        selected <- shouldSelect (belongsTo "2.34.2") (indexOf ["requests-2.34.2.tar.gz"])
        sfName selected `shouldBe` Just (String "requests")

    it "counts every entry of the array, not only the ones it kept" $ do
        selected <- shouldSelect (belongsTo "2.34.2") (indexOf ["requests-2.34.2.tar.gz", "requests-2.34.1.tar.gz", "requests-2.34.0.tar.gz"])
        sfFileCount selected `shouldBe` 3

    it "keeps a selected entry whole, unmodelled keys and all" $ do
        selected <- shouldSelect (belongsTo "2.34.2") (indexOf ["requests-2.34.2.tar.gz"])
        (entryKey "provenance" =<< listToMaybe (sfFiles selected)) `shouldBe` Just (String "https://pypi.org/integrity/x/provenance")

    it "selects nothing for a release the index does not carry" $ do
        selected <- shouldSelect (belongsTo "9.9.9") (indexOf ["requests-2.34.2.tar.gz"])
        sfFiles selected `shouldBe` []

    it "skips an entry that declares no readable name, rather than guessing at one" $ do
        selected <- shouldSelect (const True) (rawIndex [object ["url" .= ("https://files.test/x" :: Text)]])
        sfFiles selected `shouldBe` []
        sfFileCount selected `shouldBe` 1

    it "reads an index that lists no files at all" $ do
        selected <- shouldSelect (const True) (rawIndex [])
        sfFiles selected `shouldBe` []
        sfFileCount selected `shouldBe` 0

    it "keeps the first files array when a hostile document repeats the key" $ do
        -- aeson resolves a duplicate key first-occurrence-wins, so the selective walk must too,
        -- or the two decode paths would disagree about what the upstream said.
        selected <- shouldSelect (const True) duplicateFilesIndex
        selectedNames selected `shouldBe` ["first.tar.gz"]

volumeSpec :: Spec
volumeSpec = describe "decode volume" $
    it "materialises one entry per matching file, whatever the size of the array" $ do
        -- A public project carries hundreds of files across its history. The gate consults one
        -- release, so what it materialises must scale with that release, not with the project.
        selected <- shouldSelect (belongsTo "1.0.0") manyFileIndex
        length (sfFiles selected) `shouldBe` 2
        sfFileCount selected `shouldBe` 400

faithfulnessSpec :: Spec
faithfulnessSpec = describe "faithful to a whole-document decode" $ do
    it "refuses malformed JSON inside an entry it would have skipped" $
        -- The lexer reaches the offending bytes whether or not they sit in the requested
        -- release, so the walk refuses exactly what a whole-document decode refuses.
        selectFilesFromIndex 64 (belongsTo "2.34.2") "{\"name\":\"requests\",\"files\":[{\"filename\":\"other-1.0.tar.gz\",}]}"
            `shouldBe` Left SelectiveUndecodable

    it "refuses trailing non-whitespace after the top-level object" $
        selectFilesFromIndex 64 (const True) (BL.toStrict (encode (rawIndexValue [])) <> "junk")
            `shouldBe` Left SelectiveUndecodable

    it "refuses a body that is not a JSON object" $
        selectFilesFromIndex 64 (const True) "[]" `shouldBe` Left SelectiveUndecodable

    it "refuses a value nested past the budget, wherever it sits" $
        selectFilesFromIndex 3 (const True) (indexOf ["requests-2.34.2.tar.gz"])
            `shouldBe` Left SelectiveTooDeeplyNested

    it "refuses the document outright when the budget cannot hold the object itself" $
        selectFilesFromIndex 0 (const True) (indexOf ["requests-2.34.2.tar.gz"])
            `shouldBe` Left SelectiveTooDeeplyNested

-- | Run the walk at the default depth budget, failing the example on a refusal.
shouldSelect :: (Text -> Bool) -> ByteString -> IO SelectedFiles
shouldSelect belongs = either (fail . show) pure . selectFilesFromIndex 64 belongs

{- | Whether a distribution file name names the given release, standing in for the PyPI
coordinate reader the production caller supplies.
-}
belongsTo :: Text -> Text -> Bool
belongsTo version filename = T.isInfixOf ("-" <> version <> ".") filename || T.isInfixOf ("-" <> version <> "-") filename

-- | An index for @requests@ offering one complete entry per file name.
indexOf :: [Text] -> ByteString
indexOf = rawIndex . map simpleFile

-- | An index offering the given raw entries.
rawIndex :: [Value] -> ByteString
rawIndex = BL.toStrict . encode . rawIndexValue

rawIndexValue :: [Value] -> Value
rawIndexValue files = object ["name" .= ("requests" :: Text), "meta" .= object ["api-version" .= ("1.4" :: Text)], "files" .= files]

-- | An index whose @files@ key appears twice, the second carrying a different entry.
duplicateFilesIndex :: ByteString
duplicateFilesIndex =
    "{\"name\":\"requests\",\"files\":[" <> entry "first.tar.gz" <> "],\"files\":[" <> entry "second.tar.gz" <> "]}"
  where
    entry :: Text -> ByteString
    entry name = "{\"filename\":\"" <> encodeUtf8 name <> "\",\"url\":\"https://files.test/" <> encodeUtf8 name <> "\"}"

-- | An index of 400 entries, two of which belong to the release under test.
manyFileIndex :: ByteString
manyFileIndex = indexOf (["requests-1.0.0.tar.gz", "requests-1.0.0-py3-none-any.whl"] <> [T.pack ("requests-2." <> show n <> ".0.tar.gz") | n <- [1 .. 398 :: Int]])

-- | The names of the selected entries, in index order.
selectedNames :: SelectedFiles -> [Text]
selectedNames selected = mapMaybe stringOf (mapMaybe (entryKey "filename") (sfFiles selected))
  where
    stringOf = \case
        String s -> Just s
        _ -> Nothing

-- | One key of a selected file entry.
entryKey :: Text -> Value -> Maybe Value
entryKey key = \case
    Object entry -> KeyMap.lookup (fromString (toString key)) entry
    _ -> Nothing
