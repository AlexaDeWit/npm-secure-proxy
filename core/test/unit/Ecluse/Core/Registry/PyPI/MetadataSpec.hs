-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Pure-projection tests for the PyPI Simple-index read, pinning the 'MetadataError' each
failure maps to and holding the two decode paths against each other. The body-size bound is
enforced over the HTTP body by the fetch, so the data-plane tests cover that instead.
-}
module Ecluse.Core.Registry.PyPI.MetadataSpec (spec) where

import Data.Aeson (Value (Object), encode, object, (.=))
import Data.ByteString.Lazy qualified as BL
import Data.Map.Strict qualified as Map
import Data.Text qualified as T
import Test.Hspec

import Ecluse.Core.Ecosystem (Ecosystem (PyPI))
import Ecluse.Core.Package (
    Artifact (artFilename),
    PackageDetails (pkgArtifacts),
    PackageInfo (infoName, infoVersions),
    PackageName,
    mkPackageName,
    renderPackageName,
 )
import Ecluse.Core.Registry.Metadata (
    MetadataError (MetadataBoundExceeded, MetadataNameMismatch, MetadataUndecodable),
 )
import Ecluse.Core.Registry.PyPI.Metadata (projectPyPIIndex, projectPyPIVersion)
import Ecluse.Core.Security (
    LimitError (TooManyVersions),
    Limits (maxVersionCount),
    defaultLimits,
 )
import Ecluse.Core.Version (Version, mkVersion)

spec :: Spec
spec = do
    indexSpec
    versionSpec
    paritySpec

indexSpec :: Spec
indexSpec = describe "projectPyPIIndex" $ do
    it "projects a well-formed index into the manifest paired with its raw document" $
        case projectPyPIIndex defaultLimits requests (indexOf ["requests-2.34.2.tar.gz", "requests-2.34.1.tar.gz"]) of
            Right (info, raw) -> do
                renderPackageName (infoName info) `shouldBe` "requests"
                Map.keys (infoVersions info) `shouldBe` ["2.34.1", "2.34.2"]
                raw `shouldSatisfy` isObject
            other -> expectationFailure ("expected a projection, got: " <> show other)

    it "reports an undecodable body" $
        projectPyPIIndex defaultLimits requests "{not json" `shouldBe` Left MetadataUndecodable

    it "reports an absent top-level name as undecodable" $
        projectPyPIIndex defaultLimits requests (bytes (object ["files" .= ([] :: [Value])]))
            `shouldBe` Left MetadataUndecodable

    it "reports an index self-reporting another project as a name mismatch, not a decode failure" $
        -- The anti-shadowing distinction: a responding upstream serving the wrong project is a
        -- `502`, never a `404` that would read as the project not existing.
        projectPyPIIndex defaultLimits requests (indexNamed "urllib3" [])
            `shouldBe` Left (MetadataNameMismatch "urllib3")

    it "reports a release count past the bound as a bound breach" $
        projectPyPIIndex defaultLimits{maxVersionCount = 1} requests (indexOf ["requests-2.34.2.tar.gz", "requests-2.34.1.tar.gz"])
            `shouldBe` Left (MetadataBoundExceeded (TooManyVersions 2 1))

versionSpec :: Spec
versionSpec = describe "projectPyPIVersion" $ do
    it "projects one release's files out of an index carrying several" $
        artifactNames (projectPyPIVersion defaultLimits requests (release "2.34.2") (indexOf ["requests-2.34.2.tar.gz", "requests-2.34.2-py3-none-any.whl", "requests-2.34.1.tar.gz"]))
            `shouldBe` Right (Just ["requests-2.34.2.tar.gz", "requests-2.34.2-py3-none-any.whl"])

    it "yields nothing for a release a sound index does not carry, a forwarded miss" $
        artifactNames (projectPyPIVersion defaultLimits requests (release "9.9.9") (indexOf ["requests-2.34.2.tar.gz"]))
            `shouldBe` Right Nothing

    it "reports an undecodable body" $
        artifactNames (projectPyPIVersion defaultLimits requests (release "2.34.2") "{not json")
            `shouldBe` Left MetadataUndecodable

    it "reports an index self-reporting another project as a name mismatch" $
        artifactNames (projectPyPIVersion defaultLimits requests (release "2.34.2") (indexNamed "urllib3" ["urllib3-2.34.2.tar.gz"]))
            `shouldBe` Left (MetadataNameMismatch "urllib3")

    it "reports a file count past the bound as a bound breach" $
        artifactNames (projectPyPIVersion defaultLimits{maxVersionCount = 1} requests (release "2.34.2") (indexOf ["requests-2.34.2.tar.gz", "requests-2.34.1.tar.gz"]))
            `shouldBe` Left (MetadataBoundExceeded (TooManyVersions 2 1))

paritySpec :: Spec
paritySpec = describe "the two decode paths agree on what they serve" $
    for_ ["2.34.2", "2.34", "1.0.post1"] $ \version ->
        it ("resolves " <> toString version <> " to the same files as the whole-index path") $ do
            -- The selective walk is a memory bound, not a shortcut past the projection: the
            -- release it resolves must be the release selected out of a full projection.
            let body = indexOf ["requests-2.34.2.tar.gz", "requests-2.34.2-py3-none-any.whl", "requests-2.34.tar.gz", "requests-1.0-1.tar.gz"]
            artifactNames (projectPyPIVersion defaultLimits requests (release version) body)
                `shouldBe` Right (wholeIndexArtifacts version body)

-- | The project every example reads.
requests :: PackageName
requests = mkPackageName PyPI Nothing "requests"

-- | The release an example asks for, keyed as the projection keys it.
release :: Text -> Version
release = mkVersion PyPI

-- | The artifact names a single-release projection resolved.
artifactNames :: Either MetadataError (Maybe PackageDetails) -> Either MetadataError (Maybe [Text])
artifactNames = fmap (fmap (map artFilename . toList . pkgArtifacts))

-- | The artifact names the whole-index path resolves for one release.
wholeIndexArtifacts :: Text -> ByteString -> Maybe [Text]
wholeIndexArtifacts version body = case projectPyPIIndex defaultLimits requests body of
    Right (info, _) -> map artFilename . toList . pkgArtifacts <$> Map.lookup version (infoVersions info)
    Left _ -> Nothing

-- | An index for @requests@ offering one entry per file name.
indexOf :: [Text] -> ByteString
indexOf = indexNamed "requests"

-- | An index reporting the given name and offering one entry per file name.
indexNamed :: Text -> [Text] -> ByteString
indexNamed name files = bytes (object ["name" .= name, "files" .= map fileNamed files])

-- | A file entry complete enough to project: a name, a location, and a well-formed digest.
fileNamed :: Text -> Value
fileNamed filename =
    object
        [ "filename" .= filename
        , "url" .= ("https://files.pythonhosted.org/packages/a0/" <> filename)
        , "hashes" .= object ["sha256" .= T.replicate 64 "a"]
        , "upload-time" .= ("2026-05-14T19:25:26Z" :: Text)
        ]

bytes :: Value -> ByteString
bytes = BL.toStrict . encode

isObject :: Value -> Bool
isObject = \case
    Object _ -> True
    _ -> False
