-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

-- | PyPI coordinate compatibility, projection, and allocation growth regressions.
module Ecluse.Core.Registry.PyPI.ProjectSpec (spec) where

import Data.Aeson (Value, object, toJSON, (.=))
import Data.Map.Strict qualified as Map
import Data.Text qualified as T
import GHC.Conc (getAllocationCounter)
import Test.Hspec
import UnliftIO (evaluate)

import Ecluse.Core.Ecosystem (Ecosystem (PyPI))
import Ecluse.Core.Package (
    Artifact (..),
    ArtifactKind (Sdist, Wheel),
    Availability (Available, Yanked),
    CodeExecSignal (CodeExecUnknown, NoCodeOnInstall, RunsCodeOnInstall),
    Hash,
    HashAlg (SHA256),
    InvalidEntry (invalidKey, invalidKind, invalidValue),
    InvalidEntryKind (InvalidIndexFile),
    PackageDetails (..),
    PackageInfo (..),
    PackageName,
    hashAlg,
    hashValue,
    mkPackageName,
    renderPackageName,
 )
import Ecluse.Core.Registry.PyPI.Project (
    FileCoordinate (..),
    fileCoordinate,
    fileVersionKey,
    isCanonicalName,
    projectName,
    projectSimpleIndexFromValue,
 )
import Ecluse.Core.Registry.WireSupport (Projection (NameMismatch, Projected))
import Ecluse.Core.Version (renderVersion)
import Ecluse.Test.Package (validSha256)
import Ecluse.Test.Registry.PyPI (separatorHeavySdist, simpleFile, withFileKeys)

spec :: Spec
spec = do
    projectNameSpec
    canonicalNameSpec
    coordinateSpec
    allocationSpec
    projectionSpec
    versionFoldSpec

projectNameSpec :: Spec
projectNameSpec = describe "projectName" $ do
    it "parses a canonical project name" $
        renderPackageName <$> projectName "requests" `shouldBe` Right "requests"

    it "keeps the published spelling while matching on the canonical key" $ do
        parsed <- shouldParse (projectName "Zope.Interface")
        renderPackageName parsed `shouldBe` "Zope.Interface"
        parsed `shouldBe` mkPackageName PyPI Nothing "zope-interface"

    it "refuses an empty name" $
        projectName "" `shouldSatisfy` isLeft

    it "refuses a non-ASCII name, which renders two projects as one" $
        projectName "requ\1077sts" `shouldSatisfy` isLeft

    it "refuses a name that is not a safe path component" $
        projectName "../etc" `shouldSatisfy` isLeft

    it "refuses a name that opens or closes on a separator" $ do
        projectName "-requests" `shouldSatisfy` isLeft
        projectName "requests." `shouldSatisfy` isLeft

    it "refuses a name carrying a character outside PEP 508's grammar" $
        projectName "req~uests" `shouldSatisfy` isLeft

    it "refuses a name over PyPI's own cap" $
        projectName (T.replicate 101 "a") `shouldSatisfy` isLeft

canonicalNameSpec :: Spec
canonicalNameSpec = describe "isCanonicalName" $ do
    it "admits a PEP 503 canonical name" $
        isCanonicalName "zope-interface" `shouldBe` True

    it "refuses a spelling the route would have to redirect" $ do
        isCanonicalName "Zope.Interface" `shouldBe` False
        isCanonicalName "typing_extensions" `shouldBe` False

coordinateSpec :: Spec
coordinateSpec = describe "fileCoordinate" $ do
    it "reads a wheel's release and compatibility tag" $
        fileCoordinate requests "requests-2.34.2-py3-none-any.whl"
            `shouldBe` Just (FileCoordinate "2.34.2" (Wheel "py3-none-any"))

    it "reads a wheel carrying a build tag" $
        fileCoordinate requests "requests-2.34.2-1-py3-none-any.whl"
            `shouldBe` Just (FileCoordinate "2.34.2" (Wheel "py3-none-any"))

    it "cross-normalises a wheel's underscored name onto the PEP 503 canonical key" $
        fileCoordinate azureStorageBlob "azure_storage_blob-12.14.0-py3-none-any.whl"
            `shouldBe` Just (FileCoordinate "12.14" (Wheel "py3-none-any"))

    it "reads a source distribution's release" $
        fileCoordinate requests "requests-2.34.2.tar.gz"
            `shouldBe` Just (FileCoordinate "2.34.2" Sdist)

    it "takes the longest name part, so a project whose name carries a separator resolves" $
        fileCoordinate azureStorageBlob "azure-storage-blob-12.14.0.tar.gz"
            `shouldBe` Just (FileCoordinate "12.14" Sdist)

    it "reads a source distribution whose version carries a separator" $
        fileCoordinate requests "requests-2.34.2-1.tar.gz"
            `shouldBe` Just (FileCoordinate "2.34.2.post1" Sdist)

    it "preserves mixed separators, ignored edge runs, and every supported archive" $
        forM_ [".tar.gz", ".tgz", ".zip", ".tar.bz2", ".tar.xz"] $ \suffix ->
            fileCoordinate azureStorageBlob ("__Azure..Storage_-Blob---12.14.0" <> suffix)
                `shouldBe` Just (FileCoordinate "12.14" Sdist)

    it "rejects missing boundaries and incomplete project names" $
        forM_ ["azure-storage-blob.tar.gz", "azure-storage-.tar.gz", "azure-storage-other-1.tar.gz"] $ \file ->
            fileCoordinate azureStorageBlob file `shouldBe` Nothing

    it "retains the canonicaliser's empty-name behaviour for domain values outside the project grammar" $ do
        let emptyName = mkPackageName PyPI Nothing ""
        fileCoordinate emptyName "___1.tar.gz" `shouldBe` Just (FileCoordinate "1" Sdist)
        fileCoordinate emptyName "1.tar.gz" `shouldBe` Nothing

    it "canonicalises the release, so two spellings of it key alike" $
        fileVersionKey requests "requests-2.34.tar.gz" `shouldBe` fileVersionKey requests "requests-2.34.0.tar.gz"

    it "refuses a file naming another project, which on the artifact route is path confusion" $
        fileCoordinate requests "urllib3-2.0.0.tar.gz" `shouldBe` Nothing

    it "refuses a file whose name only starts like this project's" $
        fileCoordinate requests "requests_toolbelt-1.0.0.tar.gz" `shouldBe` Nothing

    it "refuses a version that is not PEP 440, which no resolver could install" $
        fileCoordinate requests "requests-nightly.tar.gz" `shouldBe` Nothing

    it "refuses an archive form a Python index does not serve" $
        fileCoordinate requests "requests-2.34.2.egg" `shouldBe` Nothing

    it "refuses a wheel with too few tag parts to be one" $
        fileCoordinate requests "requests-2.34.2-py3.whl" `shouldBe` Nothing

allocationSpec :: Spec
allocationSpec = describe "filename allocation growth" $
    it "keeps malformed rejection below quadratic growth as separators double" $ do
        allocations <- forM [1000, 2000, 4000, 8000] $ \count -> do
            files <- evaluate (force [separatorHeavySdist "requests" count (show repetition) | repetition <- [1 :: Int .. 5]])
            before <- getAllocationCounter
            rejected <- evaluate (length (filter (isNothing . fileCoordinate requests) files))
            after <- getAllocationCounter
            rejected `shouldBe` length files
            pure (before - after)
        -- Each window has two reads accurate to about 4 KiB. Weight both windows by the 3x ratio.
        -- The resulting 32 KiB allowance covers counter granularity without admitting quadratic growth.
        forM_ (zip allocations (drop 1 allocations)) $ \(smaller, larger) ->
            larger `shouldSatisfy` (<= 3 * smaller + 32768)

projectionSpec :: Spec
projectionSpec = describe "projectSimpleIndexFromValue" $ do
    it "drops malformed separator-heavy upstream files while retaining normal releases" $
        forM_ [1000, 2000, 4000, 8000] $ \count -> do
            let filename = separatorHeavySdist "requests" count "projection"
            info <- shouldProject requests (indexOf [sdistFileNamed filename, sdistFile "2.34.2", wheelFile "2.34.2"])
            artifactNames info "2.34.2" `shouldBe` Just ["requests-2.34.2.tar.gz", "requests-2.34.2-py3-none-any.whl"]
            map invalidKey (infoInvalidEntries info) `shouldBe` [filename]

    it "projects one release per canonical version, carrying every file of it" $ do
        info <- shouldProject requests (indexOf [sdistFile "2.34.2", wheelFile "2.34.2", wheelFile "2.34.1"])
        Map.keys (infoVersions info) `shouldBe` ["2.34.1", "2.34.2"]
        artifactNames info "2.34.2" `shouldBe` Just ["requests-2.34.2.tar.gz", "requests-2.34.2-py3-none-any.whl"]

    it "merges two spellings of one release into one entry" $ do
        info <- shouldProject requests (indexOf [wheelFile "2.34", wheelFile "2.34.0"])
        Map.keys (infoVersions info) `shouldBe` ["2.34"]

    it "projects sha256 through the shared hash vocabulary" $ do
        info <- shouldProject requests (indexOf [wheelFile "2.34.2"])
        map (\h -> (hashAlg h, hashValue h)) (artifactHashes info "2.34.2") `shouldBe` [(SHA256, validSha256)]

    it "drops a digest under an algorithm this build does not know" $ do
        info <- shouldProject requests (indexOf [withFileKeys [("hashes", object ["blake2b_256" .= ("ab" :: Text)])] (wheelFile "2.34.2")])
        artifactHashes info "2.34.2" `shouldBe` []

    it "carries requires-python and the yank marker per file" $ do
        info <- shouldProject requests (indexOf [withFileKeys [("yanked", toJSON True)] (wheelFile "2.34.2")])
        map artInterpreter (artifactsOf info "2.34.2") `shouldBe` [Just ">=3.10"]
        map artYanked (artifactsOf info "2.34.2") `shouldBe` [True]

    it "points latest at the highest release, preferring a final over a pre-release" $ do
        info <- shouldProject requests (indexOf [wheelFile "2.34.2", wheelFile "3.0.0rc1"])
        fmap renderVersion (Map.lookup "latest" (infoDistTags info)) `shouldBe` Just "2.34.2"

    it "drops a file naming no release of this project and records it" $ do
        info <- shouldProject requests (indexOf [wheelFile "2.34.2", sdistFileNamed "urllib3-2.0.0.tar.gz"])
        Map.keys (infoVersions info) `shouldBe` ["2.34.2"]
        map invalidKind (infoInvalidEntries info) `shouldBe` [InvalidIndexFile]
        map invalidKey (infoInvalidEntries info) `shouldBe` ["urllib3-2.0.0.tar.gz"]

    it "reduces a dropped file's location to its authority, which reaches a log line" $ do
        info <- shouldProject requests (indexOf [sdistFileNamed "urllib3-2.0.0.tar.gz"])
        map invalidValue (infoInvalidEntries info) `shouldBe` [toJSON ("files.pythonhosted.org:443" :: Text)]

    it "agrees the index's self-reported name with the request through the shared check" $
        projectSimpleIndexFromValue requests (indexNamed "Requests" [wheelFile "2.34.2"])
            `shouldSatisfy` either (const False) isProjected

    it "refuses an index self-reporting another project, carrying the reported name" $
        projectSimpleIndexFromValue requests (indexNamed "urllib3" [])
            `shouldBe` Right (NameMismatch "urllib3")

    it "refuses an index that reports no usable name at all" $
        projectSimpleIndexFromValue requests (indexNamed "" []) `shouldSatisfy` isLeft

versionFoldSpec :: Spec
versionFoldSpec = describe "the version-level folds over a release's files" $ do
    it "runs code on install when any file is a source distribution" $ do
        info <- shouldProject requests (indexOf [wheelFile "2.34.2", sdistFile "2.34.2"])
        pkgInstallCode <$> Map.lookup "2.34.2" (infoVersions info) `shouldSatisfy` maybe False runsCode

    it "runs no code on install for a release offering wheels alone" $ do
        info <- shouldProject requests (indexOf [wheelFile "2.34.2"])
        pkgInstallCode <$> Map.lookup "2.34.2" (infoVersions info) `shouldBe` Just NoCodeOnInstall

    it "ages a release from its newest file, so a late wheel does not shorten the quarantine" $ do
        info <-
            shouldProject
                requests
                ( indexOf
                    [ withFileKeys [("upload-time", toJSON ("2026-01-01T00:00:00Z" :: Text))] (sdistFile "2.34.2")
                    , withFileKeys [("upload-time", toJSON ("2026-06-01T00:00:00Z" :: Text))] (wheelFile "2.34.2")
                    ]
                )
        fmap show (pkgPublishedAt =<< Map.lookup "2.34.2" (infoVersions info))
            `shouldBe` Just ("2026-06-01 00:00:00 UTC" :: Text)

    it "withdraws a release only when every file of it is yanked" $ do
        partly <- shouldProject requests (indexOf [yanked (sdistFile "2.34.2"), wheelFile "2.34.2"])
        pkgAvailability <$> Map.lookup "2.34.2" (infoVersions partly) `shouldBe` Just Available
        wholly <- shouldProject requests (indexOf [yanked (sdistFile "2.34.2"), yanked (wheelFile "2.34.2")])
        pkgAvailability <$> Map.lookup "2.34.2" (infoVersions wholly) `shouldBe` Just (Yanked (Just "withdrawn"))

requests :: PackageName
requests = mkPackageName PyPI Nothing "requests"

azureStorageBlob :: PackageName
azureStorageBlob = mkPackageName PyPI Nothing "azure-storage-blob"

shouldProject :: PackageName -> Value -> IO PackageInfo
shouldProject name value = case projectSimpleIndexFromValue name value of
    Left err -> fail (show err)
    Right (NameMismatch reported) -> fail (toString ("index self-reported " <> reported))
    Right (Projected info) -> pure info

shouldParse :: (Show e) => Either e a -> IO a
shouldParse = either (fail . show) pure

isProjected :: Projection a -> Bool
isProjected = \case
    Projected _ -> True
    NameMismatch _ -> False

runsCode :: CodeExecSignal -> Bool
runsCode = \case
    RunsCodeOnInstall _ -> True
    NoCodeOnInstall -> False
    CodeExecUnknown -> False

artifactsOf :: PackageInfo -> Text -> [Artifact]
artifactsOf info version = maybe [] (toList . pkgArtifacts) (Map.lookup version (infoVersions info))

artifactNames :: PackageInfo -> Text -> Maybe [Text]
artifactNames info version = map artFilename . toList . pkgArtifacts <$> Map.lookup version (infoVersions info)

artifactHashes :: PackageInfo -> Text -> [Hash]
artifactHashes info version = concatMap artHashes (take 1 (artifactsOf info version))

indexOf :: [Value] -> Value
indexOf = indexNamed "requests"

indexNamed :: Text -> [Value] -> Value
indexNamed name files = object ["name" .= name, "files" .= files]

wheelFile :: Text -> Value
wheelFile version = simpleFile ("requests-" <> version <> "-py3-none-any.whl")

sdistFile :: Text -> Value
sdistFile version = simpleFile ("requests-" <> version <> ".tar.gz")

sdistFileNamed :: Text -> Value
sdistFileNamed = simpleFile

yanked :: Value -> Value
yanked = withFileKeys [("yanked", toJSON ("withdrawn" :: Text))]
