-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Core.Registry.PyPI.WireSpec (spec) where

import Data.Aeson (Value, eitherDecodeStrict, encode, object, (.=))
import Data.Aeson.Key (Key)
import Data.Map.Strict qualified as Map
import Data.Time (UTCTime (UTCTime), fromGregorian, secondsToDiffTime)
import Test.Hspec

import Ecluse.Core.Package (
    InvalidEntry (invalidKey, invalidKind),
    InvalidEntryKind (InvalidIndexFile, InvalidVersionListing),
 )
import Ecluse.Core.Registry.PyPI.Wire (
    IndexFile (..),
    SimpleIndex (..),
    YankState (FileOffered, FileWithdrawn),
 )

spec :: Spec
spec = do
    indexSpec
    fileSpec
    yankSpec
    apiVersionSpec

indexSpec :: Spec
indexSpec = describe "SimpleIndex" $ do
    it "decodes the project name and its files" $ do
        index <- shouldDecode (indexWith [wheelEntry])
        siName index `shouldBe` "requests"
        map ifFilename (siFiles index) `shouldBe` ["requests-2.34.2-py3-none-any.whl"]

    it "reads an absent name as empty, which the projection refuses" $ do
        index <- shouldDecode (object ["files" .= ([] :: [Value])])
        siName index `shouldBe` ""

    it "drops a malformed file entry and records it under its declared name" $ do
        index <- shouldDecode (indexWith [wheelEntry, namedButLocationless])
        map ifFilename (siFiles index) `shouldBe` ["requests-2.34.2-py3-none-any.whl"]
        map invalidKind (siInvalidEntries index) `shouldBe` [InvalidIndexFile]
        map invalidKey (siInvalidEntries index) `shouldBe` ["broken-1.0.tar.gz"]

    it "records a file entry that declares no name under its position in the array" $ do
        index <- shouldDecode (indexWith [object []])
        map invalidKey (siInvalidEntries index) `shouldBe` ["0"]

    it "drops a versions-listing entry that is not a version string" $ do
        index <- shouldDecode (object ["name" .= ("requests" :: Text), "versions" .= [object []]])
        map invalidKind (siInvalidEntries index) `shouldBe` [InvalidVersionListing]

    it "tolerates an index that lists no files at all" $ do
        index <- shouldDecode (object ["name" .= ("requests" :: Text)])
        siFiles index `shouldBe` []
        siInvalidEntries index `shouldBe` []

fileSpec :: Spec
fileSpec = describe "IndexFile" $ do
    it "decodes every field the rules and the serving path decide on" $ do
        file <- shouldDecodeFile wheelEntry
        ifUrl file `shouldBe` "https://files.pythonhosted.org/packages/a0/requests-2.34.2-py3-none-any.whl"
        ifHashes file `shouldBe` Map.singleton "sha256" sha256Digest
        ifRequiresPython file `shouldBe` Just ">=3.10"
        ifSize file `shouldBe` Just 73075
        ifUploadTime file `shouldBe` Just uploadedAt
        ifProvenance file `shouldBe` Just "https://pypi.org/integrity/requests/2.34.2/x/provenance"

    it "reads an advisory size that is not a whole number as absent" $ do
        file <- shouldDecodeFile (fileEntry ["size" .= (1.5 :: Double)])
        ifSize file `shouldBe` Nothing

    it "reads an undecodable upload instant as absent, which fails the age quarantine" $ do
        file <- shouldDecodeFile (fileEntry ["upload-time" .= ("last tuesday" :: Text)])
        ifUploadTime file `shouldBe` Nothing

    it "ignores a key it does not model, the PEP 658 sidecar included" $ do
        file <- shouldDecodeFile (fileEntry ["core-metadata" .= object ["sha256" .= ("8c384ba3" :: Text)]])
        ifFilename file `shouldBe` "requests-2.34.2-py3-none-any.whl"

    it "refuses a file that names no location, which could be neither gated nor served" $
        (eitherDecodeStrict (encodeValue namedButLocationless) :: Either String IndexFile)
            `shouldSatisfy` isLeft

yankSpec :: Spec
yankSpec = describe "yanked" $ do
    it "reads an absent marker as offered" $ do
        file <- shouldDecodeFile (fileEntry [])
        ifYanked file `shouldBe` FileOffered

    it "reads false as offered" $ do
        file <- shouldDecodeFile (fileEntry ["yanked" .= False])
        ifYanked file `shouldBe` FileOffered

    it "reads true as withdrawn with no stated reason" $ do
        file <- shouldDecodeFile (fileEntry ["yanked" .= True])
        ifYanked file `shouldBe` FileWithdrawn Nothing

    it "reads a string as withdrawn with that reason" $ do
        file <- shouldDecodeFile (fileEntry ["yanked" .= ("broken sdist" :: Text)])
        ifYanked file `shouldBe` FileWithdrawn (Just "broken sdist")

apiVersionSpec :: Spec
apiVersionSpec = describe "meta.api-version" $ do
    it "accepts the major version this decoder speaks" $
        shouldDecode (metaIndex "1.4") `shouldReturn` emptyIndex

    it "accepts an index that declares no API version, as a private index may" $
        shouldDecode (object []) `shouldReturn` emptyIndex

    it "refuses a major version it does not speak, as PEP 691 requires of a client" $
        (eitherDecodeStrict (encodeValue (metaIndex "2.0")) :: Either String SimpleIndex)
            `shouldSatisfy` isLeft

-- | Decode a value as the type under test, failing the example with the decoder's own message.
shouldDecode :: Value -> IO SimpleIndex
shouldDecode = either fail pure . eitherDecodeStrict . encodeValue

-- | 'shouldDecode' for one file entry.
shouldDecodeFile :: Value -> IO IndexFile
shouldDecodeFile = either fail pure . eitherDecodeStrict . encodeValue

-- | Re-encode a built value as the bytes a decoder reads.
encodeValue :: Value -> ByteString
encodeValue = toStrict . encode

-- | An index carrying the given file entries under a fixed project name.
indexWith :: [Value] -> Value
indexWith files = object ["name" .= ("requests" :: Text), "files" .= files]

-- | An index that declares only the given @meta.api-version@.
metaIndex :: Text -> Value
metaIndex apiVersion = object ["meta" .= object ["api-version" .= apiVersion]]

-- | What 'metaIndex' and a bare object both decode to: a nameless index offering nothing.
emptyIndex :: SimpleIndex
emptyIndex = SimpleIndex{siName = "", siFiles = [], siInvalidEntries = []}

-- | A complete wheel entry, the shape public PyPI serves.
wheelEntry :: Value
wheelEntry = fileEntry []

{- | 'wheelEntry' with the given keys added or overridden, so an example names only the axis it
is about.
-}
fileEntry :: [(Key, Value)] -> Value
fileEntry overrides = object (baseKeys <> overrides)
  where
    baseKeys =
        [ "filename" .= ("requests-2.34.2-py3-none-any.whl" :: Text)
        , "url" .= ("https://files.pythonhosted.org/packages/a0/requests-2.34.2-py3-none-any.whl" :: Text)
        , "hashes" .= object ["sha256" .= sha256Digest]
        , "requires-python" .= (">=3.10" :: Text)
        , "size" .= (73075 :: Int)
        , "upload-time" .= ("2026-05-14T19:25:26.443Z" :: Text)
        , "provenance" .= ("https://pypi.org/integrity/requests/2.34.2/x/provenance" :: Text)
        ]

-- | A well-formed sha256 digest, which the projection's validating builder accepts.
sha256Digest :: Text
sha256Digest = "2a0d60c100000000000000000000000000000000000000000000000000000000"

-- | A file entry that names itself but no location: undecodable, and recorded under its name.
namedButLocationless :: Value
namedButLocationless = object ["filename" .= ("broken-1.0.tar.gz" :: Text)]

-- | The instant 'wheelEntry' declares it was uploaded at.
uploadedAt :: UTCTime
uploadedAt = UTCTime (fromGregorian 2026 5 14) (secondsToDiffTime (19 * 3600 + 25 * 60 + 26) + 0.443)
