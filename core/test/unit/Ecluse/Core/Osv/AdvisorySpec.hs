-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT
{-# LANGUAGE OverloadedStrings #-}

{- | Advisory decoding and extraction regressions.
Fixtures also exercise bounded streaming and score joins.
-}
module Ecluse.Core.Osv.AdvisorySpec (spec) where

import Conduit
import Data.Aeson (eitherDecodeStrict)
import Data.ByteString qualified as BS
import Katip (closeScribes)
import Test.Hspec (Spec, anyException, describe, it, shouldBe, shouldSatisfy, shouldThrow)

import Data.ByteString.Lazy qualified as LBS
import Data.Text (unpack)
import Data.Text qualified as T
import Ecluse.Core.Ecosystem (Ecosystem (Npm, PyPI))
import Ecluse.Core.Osv.Advisory
import Ecluse.Core.Osv.Epss (EpssScores, mkEpssScores)
import Ecluse.Core.Osv.Stream (
    IngestLimits (..),
    IngestStats (..),
    defaultIngestLimits,
    newOsvIngest,
    parseOsvStream,
    readIngestStats,
    streamOsvUrl,
    systemicDrop,
 )
import Ecluse.Core.Osv.Types (UpperBound (..))
import Ecluse.Test.Log (captureStdout, jsonLogEnv)
import Ecluse.Test.Osv (osvZipOf, runOsvTestM, runOsvTestMWith)
import Ecluse.Test.Stub (stubBaseUrl, withStub)
import Network.HTTP.Types.Status (status200)

-- | An advisory carrying only the severity evidence under test.
advisory :: [OsvSeverityEntry] -> Maybe Text -> OsvAdvisory
advisory entries label =
    OsvAdvisory
        { osvId = "GHSA-test-severity"
        , osvAliases = Nothing
        , osvAffected = Nothing
        , osvSeverity = if null entries then Nothing else Just entries
        , osvDatabaseSpecific = OsvDatabaseSpecific . Just <$> label
        }

-- An empty feed table: extraction then leaves every segment's EPSS score absent.
noScores :: EpssScores
noScores = mkEpssScores []

spec :: Spec
spec = describe "Osv parsing and streaming" $ do
    describe "osvExportUrl" $ do
        it "derives the per-ecosystem export under the base URL" $
            osvExportUrl "https://osv-vulnerabilities.storage.googleapis.com" "npm"
                `shouldBe` "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip"

        it "tolerates a trailing slash on the base URL" $
            osvExportUrl "https://mirror.example.com/osv/" "npm"
                `shouldBe` "https://mirror.example.com/osv/npm/all.zip"

    it "decodes a sample OSV advisory and extracts remediation boundaries" $ do
        fileBytes <- BS.readFile "test/unit/fixtures/osv/sample.json"
        let res = eitherDecodeStrict fileBytes :: Either String OsvAdvisory
        case res of
            Left err -> fail ("Failed to decode: " <> err)
            Right adv -> do
                osvId adv `shouldBe` "GHSA-2234-fmw7-43wr"
                let extracted = extractFromAdvisory noScores adv
                extracted
                    `shouldBe` [ ExtractedOsv
                                    { extPackage = "hono"
                                    , extEcosystem = "npm"
                                    , extCveId = "GHSA-2234-fmw7-43wr"
                                    , extIntroduced = Nothing
                                    , extUpperBound = FixedBefore "4.6.5"
                                    , -- The fixture carries both a CVSS 3.1 vector and the
                                      -- "MODERATE" label. The computed base score wins.
                                      extSeverity = Just 5.9
                                    , -- sample.json aliases CVE-2024-48913, which the empty
                                      -- fixture table does not score.
                                      extEpss = Nothing
                                    }
                               ]

    describe "advisorySeverity" $ do
        it "computes the base score from a CVSS vector and prefers it over the label" $
            advisorySeverity
                (advisory [OsvSeverityEntry "CVSS_V3" "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"] (Just "HIGH"))
                `shouldBe` Just 9.8

        it "takes the highest score when several vectors parse" $
            advisorySeverity
                ( advisory
                    [ OsvSeverityEntry "CVSS_V3" "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:H/A:N" -- 5.9
                    , OsvSeverityEntry "CVSS_V3" "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" -- 9.8
                    ]
                    Nothing
                )
                `shouldBe` Just 9.8

        it "parses a CVSS v4 vector (needs cvss >= 0.3) rather than dropping it" $
            -- A critical v4 vector, no label: it can only score above 8 if the v4
            -- parser is present. On cvss 0.2 the vector is unscored (Nothing).
            advisorySeverity
                (advisory [OsvSeverityEntry "CVSS_V4" "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"] Nothing)
                `shouldSatisfy` maybe False (>= 8.0)

        it "falls back to the qualitative label when no vector parses" $
            advisorySeverity
                (advisory [OsvSeverityEntry "CVSS_V3" "not-a-real-vector"] (Just "CRITICAL"))
                `shouldBe` Just 10.0

        it "yields Nothing for an advisory with no severity evidence at all" $
            advisorySeverity (advisory [] Nothing) `shouldBe` Nothing

    describe "extractFromAdvisory (the EPSS join)" $ do
        let aliased ids =
                OsvAdvisory
                    "GHSA-aliased"
                    (Just ids)
                    (Just [OsvAffected (OsvPackage "aliased-pkg" "npm") Nothing (Just ["1.0.0"])])
                    Nothing
                    Nothing

        it "scores a GHSA-keyed advisory through its CVE alias" $
            map extEpss (extractFromAdvisory (mkEpssScores [("CVE-2026-77777", 0.5)]) (aliased ["CVE-2026-77777"]))
                `shouldBe` [Just 0.5]

        it "takes the highest score when several aliases are scored" $
            map
                extEpss
                ( extractFromAdvisory
                    (mkEpssScores [("CVE-2026-77777", 0.5), ("CVE-2026-88888", 0.75)])
                    (aliased ["CVE-2026-77777", "CVE-2026-88888"])
                )
                `shouldBe` [Just 0.75]

        it "leaves the score absent when the feed scores none of the identifiers" $
            map extEpss (extractFromAdvisory (mkEpssScores [("CVE-2026-99999", 0.5)]) (aliased ["CVE-2026-77777"]))
                `shouldBe` [Nothing]

    describe "extractFromAdvisory (package identity)" $ do
        for_ [("PyPI", "Flask_Thing", "flask-thing"), ("PyPI", "FLASK..__Thing", "flask-thing"), ("PyPI", "flask-thing", "flask-thing"), ("npm", "@Acme/Flask_Thing", "@Acme/Flask_Thing"), ("RubyGems", "Flask_Thing", "Flask_Thing"), ("other", "Flask_Thing", "Flask_Thing")] $ \(eco, raw, expected) ->
            it (toString ("keys " <> eco <> " package " <> raw <> " as " <> expected)) $ do
                let adv = OsvAdvisory "GHSA-name" Nothing (Just [OsvAffected (OsvPackage raw eco) Nothing (Just ["1.0", "2.0"])]) Nothing Nothing
                extractFromAdvisory noScores adv
                    `shouldBe` [ExtractedOsv expected eco "GHSA-name" (Just version) (LastAffected version) Nothing Nothing | version <- ["1.0", "2.0"]]

    describe "extractFromAdvisory (affected-set shapes)" $ do
        it "records an exact enumerated version as a point segment (no ranges)" $ do
            -- The npm malware feed names the single bad version in versions[] with
            -- no ranges.
            let adv = OsvAdvisory "MAL-test" Nothing (Just [OsvAffected (OsvPackage "bad-pkg" "npm") Nothing (Just ["1.0.0"])]) Nothing Nothing
            extractFromAdvisory noScores adv
                `shouldBe` [ExtractedOsv "bad-pkg" "npm" "MAL-test" (Just "1.0.0") (LastAffected "1.0.0") Nothing Nothing]

        it "carries an inclusive last_affected bound distinct from a fix" $ do
            let events = [OsvEvent (Just "0") Nothing Nothing, OsvEvent Nothing Nothing (Just "3.8.8")]
                adv = OsvAdvisory "GHSA-la" Nothing (Just [OsvAffected (OsvPackage "electerm" "npm") (Just [OsvRange "SEMVER" events]) Nothing]) Nothing Nothing
            extractFromAdvisory noScores adv
                `shouldBe` [ExtractedOsv "electerm" "npm" "GHSA-la" Nothing (LastAffected "3.8.8") Nothing Nothing]

        it "ignores a GIT range whose commit-SHA bounds are not versions" $ do
            -- A commit interpreted as an unorderable version bound would deny every release.
            let events = [OsvEvent (Just "0") Nothing Nothing, OsvEvent Nothing (Just "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0") Nothing]
                adv = OsvAdvisory "GHSA-git" Nothing (Just [OsvAffected (OsvPackage "healthy-pkg" "npm") (Just [OsvRange "GIT" events]) Nothing]) Nothing Nothing
            extractFromAdvisory noScores adv `shouldBe` []

        it "leaves a segment unbounded above when no event closes it" $ do
            -- A second introduced closes the open segment, and the last one runs to the
            -- end of the event list. Neither carries an upper bound.
            let events = [OsvEvent (Just "0") Nothing Nothing, OsvEvent (Just "2.0.0") Nothing Nothing]
                adv = OsvAdvisory "GHSA-open" Nothing (Just [OsvAffected (OsvPackage "open-pkg" "npm") (Just [OsvRange "SEMVER" events]) Nothing]) Nothing Nothing
            extractFromAdvisory noScores adv
                `shouldBe` [ ExtractedOsv "open-pkg" "npm" "GHSA-open" Nothing Unbounded Nothing Nothing
                           , ExtractedOsv "open-pkg" "npm" "GHSA-open" (Just "2.0.0") Unbounded Nothing Nothing
                           ]

        it "extracts the version range and drops a co-published GIT range" $ do
            -- OSV advisories often carry a GIT range alongside the ECOSYSTEM/SEMVER
            -- one. Only the version-typed range contributes a segment.
            let semverEvents = [OsvEvent (Just "0") Nothing Nothing, OsvEvent Nothing (Just "2.0.0") Nothing]
                gitEvents = [OsvEvent (Just "0") Nothing Nothing, OsvEvent Nothing (Just "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef") Nothing]
                adv =
                    OsvAdvisory
                        "GHSA-both"
                        Nothing
                        (Just [OsvAffected (OsvPackage "mixed-pkg" "npm") (Just [OsvRange "GIT" gitEvents, OsvRange "ECOSYSTEM" semverEvents]) Nothing])
                        Nothing
                        Nothing
            extractFromAdvisory noScores adv
                `shouldBe` [ExtractedOsv "mixed-pkg" "npm" "GHSA-both" Nothing (FixedBefore "2.0.0") Nothing Nothing]

        it "decodes OSV's \"0\" lower bound to no lower bound at all" $ do
            -- The beginning sentinel must not become an unorderable version bound.
            let events = [OsvEvent (Just "0") Nothing Nothing, OsvEvent Nothing (Just "1.2.3") Nothing]
                adv = OsvAdvisory "MAL-zero" Nothing (Just [OsvAffected (OsvPackage "mal-pkg" "npm") (Just [OsvRange "SEMVER" events]) Nothing]) Nothing Nothing
            extractFromAdvisory noScores adv
                `shouldBe` [ExtractedOsv "mal-pkg" "npm" "MAL-zero" Nothing (FixedBefore "1.2.3") Nothing Nothing]

        it "keeps an exactly enumerated \"0\" as the version it names" $ do
            -- The sentinel reading belongs to a range's lower bound. In versions[] the same
            -- text names a version a package may really carry.
            let adv = OsvAdvisory "MAL-v0" Nothing (Just [OsvAffected (OsvPackage "zero-pkg" "npm") Nothing (Just ["0"])]) Nothing Nothing
            extractFromAdvisory noScores adv
                `shouldBe` [ExtractedOsv "zero-pkg" "npm" "MAL-v0" (Just "0") (LastAffected "0") Nothing Nothing]

    it "extracts multiple packages and ranges from a complex OSV advisory" $ do
        fileBytes <- BS.readFile "test/unit/fixtures/osv/complex.json"
        let res = eitherDecodeStrict fileBytes :: Either String OsvAdvisory
        case res of
            Left err -> fail ("Failed to decode: " <> err)
            Right adv -> do
                osvId adv `shouldBe` "GHSA-multi"
                let extracted = extractFromAdvisory noScores adv
                -- The complex fixture has "database_specific": null, so every
                -- extracted range carries no severity label.
                extracted
                    `shouldBe` [ ExtractedOsv
                                    { extPackage = "multi-pkg"
                                    , extEcosystem = "npm"
                                    , extCveId = "GHSA-multi"
                                    , extIntroduced = Nothing
                                    , extUpperBound = FixedBefore "1.0.0"
                                    , extSeverity = Nothing
                                    , extEpss = Nothing
                                    }
                               , ExtractedOsv
                                    { extPackage = "multi-pkg"
                                    , extEcosystem = "npm"
                                    , extCveId = "GHSA-multi"
                                    , extIntroduced = Just "1.1.0"
                                    , extUpperBound = FixedBefore "1.2.0"
                                    , extSeverity = Nothing
                                    , extEpss = Nothing
                                    }
                               , ExtractedOsv
                                    { extPackage = "multi-pkg"
                                    , extEcosystem = "npm"
                                    , extCveId = "GHSA-multi"
                                    , extIntroduced = Just "2.0.0"
                                    , extUpperBound = FixedBefore "2.1.0"
                                    , extSeverity = Nothing
                                    , extEpss = Nothing
                                    }
                               , ExtractedOsv
                                    { extPackage = "other-pkg"
                                    , extEcosystem = "npm"
                                    , extCveId = "GHSA-multi"
                                    , extIntroduced = Nothing
                                    , extUpperBound = FixedBefore "3.0.0"
                                    , extSeverity = Nothing
                                    , extEpss = Nothing
                                    }
                               ]

    it "streams an OSV zip archive and emits ExtractedOsv elements" $ do
        results <-
            runOsvTestM $ do
                ingest <- newOsvIngest defaultIngestLimits (Just Npm) noScores
                runConduit $
                    sourceFile "test/unit/fixtures/osv/sample.zip"
                        .| parseOsvStream Nothing ingest
                        .| sinkList

        length results `shouldBe` 1
        case results of
            [ext] -> do
                extPackage ext `shouldBe` "hono"
                extEcosystem ext `shouldBe` "npm"
                extCveId ext `shouldBe` "GHSA-2234-fmw7-43wr"
                extUpperBound ext `shouldBe` FixedBefore "4.6.5"
            _ -> fail "Expected exactly 1 result"

    it "handles an empty zip archive gracefully without emitting anything" $ do
        results <-
            runOsvTestM $ do
                ingest <- newOsvIngest defaultIngestLimits (Just Npm) noScores
                runConduit $
                    sourceFile "test/unit/fixtures/osv/empty.zip"
                        .| parseOsvStream Nothing ingest
                        .| sinkList
        results `shouldBe` []

    it "skips malformed JSON files inside a zip archive and logs a warning" $ do
        results <-
            runOsvTestM $ do
                ingest <- newOsvIngest defaultIngestLimits (Just Npm) noScores
                runConduit $
                    sourceFile "test/unit/fixtures/osv/malformed-json.zip"
                        .| parseOsvStream Nothing ingest
                        .| sinkList
        results `shouldBe` []

    it "throws an exception when streaming a non-zip file" $ do
        let action =
                runOsvTestM $ do
                    ingest <- newOsvIngest defaultIngestLimits (Just Npm) noScores
                    runConduit $
                        sourceFile "test/unit/fixtures/osv/not-a-zip.zip"
                            .| parseOsvStream Nothing ingest
                            .| sinkList
        action `shouldThrow` anyException

    it "fetches and streams an OSV zip archive over HTTP" $ do
        zipData <- LBS.readFile "test/unit/fixtures/osv/sample.zip"
        results <- withStub status200 zipData $ \stub -> do
            runOsvTestM $ do
                ingest <- newOsvIngest defaultIngestLimits (Just Npm) noScores
                runConduit $
                    streamOsvUrl Nothing ingest (unpack (stubBaseUrl stub) <> "/sample.zip")
                        .| sinkList
        length results `shouldBe` 1
        case results of
            [ext] -> do
                extPackage ext `shouldBe` "hono"
                extEcosystem ext `shouldBe` "npm"
                extCveId ext `shouldBe` "GHSA-2234-fmw7-43wr"
                extUpperBound ext `shouldBe` FixedBefore "4.6.5"
            _ -> fail "Expected exactly 1 result"

    it "throws an exception if the URL is invalid" $ do
        let action =
                runOsvTestM $ do
                    ingest <- newOsvIngest defaultIngestLimits (Just Npm) noScores
                    runConduit $
                        streamOsvUrl Nothing ingest "not-a-valid-url"
                            .| sinkList
        action `shouldThrow` anyException

    describe "ingest bounds" $ do
        it "drops an over-large advisory and keeps ingesting the entries after it" $ do
            -- Reaching the good entry proves the oversized entry drained to its boundary.
            zipData <-
                osvZipOf
                    [ ("big.json", LBS.replicate 3000 120)
                    , ("good.json", "{\"id\":\"GHSA-good\",\"affected\":[{\"package\":{\"name\":\"good-pkg\",\"ecosystem\":\"npm\"},\"versions\":[\"1.0.0\"]}]}")
                    ]
            let limits = defaultIngestLimits{ilMaxAdvisoryBytes = 2000}
            (results, stats) <-
                runOsvTestM $ do
                    ingest <- newOsvIngest limits (Just Npm) noScores
                    rs <- runConduit $ yieldMany (LBS.toChunks zipData) .| parseOsvStream Nothing ingest .| sinkList
                    st <- readIngestStats ingest
                    pure (rs, st)
            map extCveId results `shouldBe` ["GHSA-good"]
            statAccepted stats `shouldBe` 1
            statDroppedOversize stats `shouldBe` 1
            statDroppedMalformed stats `shouldBe` 0

        it "flags an anomalous fan-out but still ingests every range of the advisory" $ do
            zipData <-
                osvZipOf
                    [("fan.json", "{\"id\":\"GHSA-fan\",\"affected\":[{\"package\":{\"name\":\"fan\",\"ecosystem\":\"npm\"},\"versions\":[\"1.0.0\",\"1.1.0\",\"1.2.0\",\"1.3.0\",\"1.4.0\"]}]}")]
            let limits = defaultIngestLimits{ilMaxAdvisoryFanOut = 3}
            (results, stats) <-
                runOsvTestM $ do
                    ingest <- newOsvIngest limits (Just Npm) noScores
                    rs <- runConduit $ yieldMany (LBS.toChunks zipData) .| parseOsvStream Nothing ingest .| sinkList
                    st <- readIngestStats ingest
                    pure (rs, st)
            length results `shouldBe` 5
            statAccepted stats `shouldBe` 1

        -- 'systemicDrop' is what escalates a feed whose drops stop being isolated.
        it "keeps every per-entry drop below the level an operator pages on" $ do
            zipData <-
                osvZipOf
                    [ ("big.json", LBS.replicate 3000 120)
                    , ("bad.json", "not json at all")
                    , ("fan.json", "{\"id\":\"GHSA-fan\",\"affected\":[{\"package\":{\"name\":\"fan\",\"ecosystem\":\"npm\"},\"versions\":[\"1.0.0\",\"1.1.0\",\"1.2.0\",\"1.3.0\",\"1.4.0\"]}]}")
                    ]
            let limits = defaultIngestLimits{ilMaxAdvisoryBytes = 2000, ilMaxAdvisoryFanOut = 3}
            logged <- captureStdout $ do
                logEnv <- jsonLogEnv
                runOsvTestMWith logEnv $ do
                    ingest <- newOsvIngest limits (Just Npm) noScores
                    void . runConduit $ yieldMany (LBS.toChunks zipData) .| parseOsvStream Nothing ingest .| sinkList
                void (closeScribes logEnv)
            logged `shouldSatisfy` T.isInfixOf "Dropping oversized OSV entry"
            logged `shouldSatisfy` T.isInfixOf "Failed to parse OSV advisory JSON"
            logged `shouldSatisfy` T.isInfixOf "exceeding the sanity threshold"
            logged `shouldSatisfy` (not . T.isInfixOf "\"sev\":\"Error\"")

        it "counts a row the grammar cannot order, and still emits every row" $ do
            -- The tally is an alarm, not a filter: both versions reach the artifact.
            zipData <-
                osvZipOf
                    [("mixed.json", "{\"id\":\"GHSA-mixed\",\"affected\":[{\"package\":{\"name\":\"mixed\",\"ecosystem\":\"npm\"},\"versions\":[\"1.0.0\",\"2026.05.1\"]}]}")]
            (results, stats) <-
                runOsvTestM $ do
                    ingest <- newOsvIngest defaultIngestLimits (Just Npm) noScores
                    rs <- runConduit $ yieldMany (LBS.toChunks zipData) .| parseOsvStream Nothing ingest .| sinkList
                    st <- readIngestStats ingest
                    pure (rs, st)
            map extIntroduced results `shouldBe` [Just "1.0.0", Just "2026.05.1"]
            statAccepted stats `shouldBe` 1
            statUnorderable stats `shouldBe` 1

        it "counts nothing unorderable for a name this build does not serve" $ do
            -- A one-shot compile of an unserved ecosystem carries no grammar to judge by.
            zipData <-
                osvZipOf
                    [("other.json", "{\"id\":\"GHSA-other\",\"affected\":[{\"package\":{\"name\":\"other\",\"ecosystem\":\"npm\"},\"versions\":[\"v1.2\"]}]}")]
            (results, stats) <-
                runOsvTestM $ do
                    ingest <- newOsvIngest defaultIngestLimits Nothing noScores
                    rs <- runConduit $ yieldMany (LBS.toChunks zipData) .| parseOsvStream Nothing ingest .| sinkList
                    st <- readIngestStats ingest
                    pure (rs, st)
            map extIntroduced results `shouldBe` [Just "v1.2"]
            statUnorderable stats `shouldBe` 0

    describe "orderableBounds" $ do
        let row intro upper = ExtractedOsv "pkg" "npm" "GHSA-bounds" intro upper Nothing Nothing

        it "admits a row whose bounds the ecosystem's grammar parses" $
            orderableBounds Npm (row (Just "1.0.0") (FixedBefore "2.0.0")) `shouldBe` True

        it "does not order a row whose upper bound is no version of the ecosystem" $
            -- Date-stamped and two-component bounds both ride the real npm feed. Unordered,
            -- the segment matches every version of the package.
            orderableBounds Npm (row (Just "1.0.0") (FixedBefore "2026.05.1")) `shouldBe` False

        it "does not order a point segment naming a version the grammar rejects" $
            orderableBounds PyPI (row (Just "0.1-bulbasaur") (LastAffected "0.1-bulbasaur")) `shouldBe` False

        it "admits a segment carrying no bound to order" $
            orderableBounds Npm (row Nothing Unbounded) `shouldBe` True

        it "judges each ecosystem by its own grammar" $ do
            -- "1.2" is not semver, and is a legal PEP 440 release.
            orderableBounds Npm (row (Just "1.2") Unbounded) `shouldBe` False
            orderableBounds PyPI (row (Just "1.2") Unbounded) `shouldBe` True

    describe "systemicDrop" $ do
        it "does not trip on a healthy feed with a few bad entries" $
            systemicDrop (IngestStats 40000 3 2 0) `shouldBe` False
        it "does not trip below the absolute floor even at a high fraction" $
            systemicDrop (IngestStats 10 5 5 0) `shouldBe` False
        it "trips when drops are both non-trivial and a large fraction of entries" $
            systemicDrop (IngestStats 50 30 20 0) `shouldBe` True
        it "does not trip when non-trivial drops are only a small fraction" $
            systemicDrop (IngestStats 10000 30 20 0) `shouldBe` False
        it "ignores the unorderable tally, which counts rows rather than entries" $
            systemicDrop (IngestStats 40000 3 2 30000) `shouldBe` False
