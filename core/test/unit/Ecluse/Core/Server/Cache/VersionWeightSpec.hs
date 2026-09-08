-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Field and backing-allocation checks for selected releases.
Cache integration checks live in the parent cache spec.
-}
module Ecluse.Core.Server.Cache.VersionWeightSpec (spec) where

import Data.ByteString qualified as BS
import Data.Text qualified as T
import Data.Time (Day (ModifiedJulianDay), UTCTime (..))
import Test.Hspec

import Ecluse.Core.Ecosystem (Ecosystem (Npm, PyPI, RubyGems))
import Ecluse.Core.Package
import Ecluse.Core.Server.Cache.VersionWeight (weighVersion)
import Ecluse.Core.Version (mkVersion, versionKey)
import Ecluse.Test.Package (sampleArtifact, sampleDetails, thingName, unsafeHash, v1_0_0, validSha256)

spec :: Spec
spec = describe "selected-release accounting" $ do
    it "keeps a cached absence smaller than a present release" $ do
        weighVersion Nothing `shouldBe` 1024
        weighVersion (Just baseline) `shouldSatisfy` (> weighVersion Nothing)

    it "charges each artifact even when its fields share allocations" $ do
        let one = weight baseline{pkgArtifacts = oneArtifact :| []}
            many = weight baseline{pkgArtifacts = oneArtifact :| replicate 99 oneArtifact}
        many `shouldSatisfy` (> one + 99 * 256)

    it "charges a Text slice for the complete retained backing allocation" $ do
        let backing = T.replicate 65536 "x"
            sliced = T.take 1 backing
            copied = T.copy sliced
            withUrl url = baseline{pkgArtifacts = oneArtifact{artUrl = url} :| []}
        weight (withUrl sliced) `shouldSatisfy` (>= weight (withUrl copied) + 65535)

    it "charges UTF-8 bytes rather than character counts" $ do
        let withUrl url = baseline{pkgArtifacts = oneArtifact{artUrl = url} :| []}
        weight (withUrl (T.replicate 1024 "\x1f600"))
            `shouldSatisfy` (>= weight (withUrl (T.replicate 1024 "a")) + 3072)

    for_ retainedFields $ \(label, change) ->
        it ("charges retained " <> label) $
            weight (change baseline) `shouldSatisfy` (> weight baseline)

    for_ parsedVersions $ \(label, ecosystem, raw, minimumParsedGrowth) ->
        it ("reserves parsed representation bytes for " <> label) $ do
            -- Copy both inputs so backing growth equals their encoded length difference.
            let compact = T.copy "1.0.0"
                expanded = T.copy raw
                compactVersion = mkVersion ecosystem compact
                expandedVersion = mkVersion ecosystem expanded
                payloadGrowth = BS.length (encodeUtf8 expanded) - BS.length (encodeUtf8 compact)
                compactWeight = weight baseline{pkgVersion = compactVersion}
                expandedWeight = weight baseline{pkgVersion = expandedVersion}
            versionKey compactVersion `shouldSatisfy` isJust
            versionKey expandedVersion `shouldSatisfy` isJust
            expandedWeight - compactWeight - payloadGrowth `shouldSatisfy` (>= minimumParsedGrowth)

weight :: PackageDetails -> Int
weight = weighVersion . Just

oneArtifact :: Artifact
oneArtifact = sampleArtifact{artHashes = [], artInterpreter = Nothing, artProvenance = Nothing}

baseline :: PackageDetails
baseline = (sampleDetails thingName v1_0_0){pkgArtifacts = oneArtifact :| [], pkgLicenses = [], pkgPublisher = Nothing, pkgTrust = Untrusted}

retainedFields :: [(String, PackageDetails -> PackageDetails)]
retainedFields =
    [ ("canonical, display, and base names", \p -> p{pkgName = mkPackageName Npm Nothing longText})
    , ("scope", \p -> p{pkgName = mkPackageName Npm (Just (mkScope longText)) "name"})
    , ("install reason", \p -> p{pkgInstallCode = RunsCodeOnInstall longText})
    , ("timestamp Integer payload", \p -> p{pkgPublishedAt = Just (UTCTime (ModifiedJulianDay (10 ^ (5000 :: Int))) 0)})
    , ("trust evidence text", \p -> p{pkgTrust = Trusted (OtherEvidence longText :| [])})
    , ("trust evidence nodes", \p -> p{pkgTrust = Trusted (Signed :| [Attested, MfaPublished])})
    , ("deprecation reason", \p -> p{pkgAvailability = Deprecated longText})
    , ("yank reason", \p -> p{pkgAvailability = Yanked (Just longText)})
    , ("licences", \p -> p{pkgLicenses = replicate 100 longText})
    , ("publisher name", \p -> p{pkgPublisher = Just (Person longText Nothing Nothing)})
    , ("publisher email", \p -> p{pkgPublisher = Just (Person "a" (Just longText) Nothing)})
    , ("publisher URL", \p -> p{pkgPublisher = Just (Person "a" Nothing (Just longText))})
    , ("filenames", changeArtifact (\a -> a{artFilename = longText}))
    , ("artifact URLs", changeArtifact (\a -> a{artUrl = longText}))
    , ("wheel tags", changeArtifact (\a -> a{artKind = Wheel longText}))
    , ("gem platforms", changeArtifact (\a -> a{artKind = Gem longText}))
    , ("hash nodes and digest backing allocations", changeArtifact (\a -> a{artHashes = [unsafeHash SHA256 (T.take 64 (validSha256 <> longText))]}))
    , ("interpreter constraints", changeArtifact (\a -> a{artInterpreter = Just longText}))
    , ("provenance URLs", changeArtifact (\a -> a{artProvenance = Just longText}))
    ]

parsedVersions :: [(String, Ecosystem, Text, Int)]
parsedVersions =
    -- A retained list cell uses three eight-byte words on the supported 64-bit targets.
    -- A 900-digit Integer needs over 300 payload bytes, apart from the raw text.
    [ ("npm dense prerelease tokens", Npm, "1.0.0-" <> T.intercalate "." (replicate 200 "a"), 199 * 24)
    , ("PyPI dense release tokens", PyPI, T.intercalate "." (replicate 200 "1"), 199 * 24)
    , ("RubyGems dense numeric and text tokens", RubyGems, T.replicate 100 "1a", 199 * 24)
    , ("npm long numeric prerelease components", Npm, "1.0.0-" <> T.intercalate "." (replicate 50 (T.replicate 18 "9")), 49 * 24)
    , ("PyPI long numeric component", PyPI, T.replicate 900 "9", 300)
    , ("RubyGems long numeric component", RubyGems, T.replicate 900 "9", 300)
    ]

changeArtifact :: (Artifact -> Artifact) -> PackageDetails -> PackageDetails
changeArtifact change details = details{pkgArtifacts = change oneArtifact :| []}

longText :: Text
longText = T.replicate 4096 "x"
