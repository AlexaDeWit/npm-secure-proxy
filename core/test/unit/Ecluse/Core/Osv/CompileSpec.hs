-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT
{-# LANGUAGE OverloadedStrings #-}

module Ecluse.Core.Osv.CompileSpec (spec) where

import Data.ByteString.Lazy qualified as LBS
import Data.Map.Strict qualified as Map
import Data.Text (unpack)
import Data.Text qualified as T
import Data.Version (showVersion)
import Database.SQLite.Simple
import Paths_ecluse (version)
import System.Directory (removeFile)
import System.FilePath (takeFileName)
import System.IO.Error (catchIOError)
import Test.Hspec (Spec, anyException, describe, it, shouldBe, shouldSatisfy, shouldThrow)

import Ecluse.Core.Ecosystem (Ecosystem (Npm, PyPI))
import Ecluse.Core.Osv.Advisory (ExtractedOsv (..))
import Ecluse.Core.Osv.Compile (CompileSources (..), compileOsvToSqlite, osvToRow)
import Ecluse.Core.Osv.Ecosystem (osvEcosystemFor)
import Ecluse.Core.Osv.Schema (osvSchemaEpoch)
import Ecluse.Core.Osv.Stream (PilotIngestAborted (..))
import Ecluse.Core.Osv.Types (UpperBound (..))
import Ecluse.Core.Telemetry.Metrics (
    AdvisoryCompileResult (CompileAborted, CompileCompleted),
    AdvisoryDropCause (DropMalformed, DropOversize),
 )
import Ecluse.Test.Osv (osvZipOf, runOsvTestM)
import Ecluse.Test.OsvDb (epssFixtureFile)
import Ecluse.Test.Port (RecordedCompile (RecordedCompile), recordingAdvisoryCompileMetricsPort)
import Ecluse.Test.Stub (Stub, stubBaseUrl, withStub)
import Network.HTTP.Types.Status (status200, status404)

spec :: Spec
spec = describe "SQLite OSV Compilation" $ do
    it "fetches an OSV zip and compiles it into a named, stamped SQLite artifact" $ do
        zipData <- LBS.readFile "test/unit/fixtures/osv/sample.zip"
        epssData <- LBS.readFile epssFixtureFile
        (metrics, readRecorded) <- recordingAdvisoryCompileMetricsPort
        dbFile <- withStub status200 zipData $ \stub ->
            withStub status200 epssData $ \epssStub ->
                runOsvTestM (compileOsvToSqlite metrics Nothing "/tmp" (osvEcosystemFor Npm) (sourcesOf stub epssStub "/sample.zip"))

        conn <- open dbFile
        rows <- query_ conn "SELECT package_name, cve_id, fixed_version, severity, epss_score FROM package_vulnerability_ranges" :: IO [(Text, Text, Maybe Text, Maybe Double, Maybe Double)]
        stamped <- query_ conn "PRAGMA user_version" :: IO [Only Int]
        metaRows <- query_ conn "SELECT key, value FROM meta" :: IO [(Text, Text)]
        indexes <- query_ conn "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'package_vulnerability_ranges' AND name LIKE 'idx_%' ORDER BY name" :: IO [Only Text]
        strictTables <- query_ conn "SELECT name FROM pragma_table_list WHERE name IN ('package_vulnerability_ranges', 'meta') AND strict = 1 ORDER BY name" :: IO [Only Text]
        dedupIndexes <- query_ conn "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'package_vulnerability_ranges' AND name LIKE 'uq_%'" :: IO [Only Text]
        close conn
        catchIOError (removeFile dbFile) (const $ pure ())

        -- The file-name literal and the meta keys below pin the artifact's wire contract, the forms
        -- a reader depends on, not the constants that produced them.
        takeFileName dbFile `shouldBe` "npm-osv-schema3.db"
        -- The sample carries a CVSS 3.1 vector (5.9). The writer stores the computed
        -- base score in preference to the "MODERATE" label. Its EPSS score arrives through
        -- the CVE-2024-48913 alias, since the feed keys on CVE ids and the row on the GHSA id.
        rows `shouldBe` [("hono", "GHSA-2234-fmw7-43wr", Just "4.6.5", Just 5.9, Just 0.75)]
        map fromOnly stamped `shouldBe` [osvSchemaEpoch]
        -- The reader's lookups ride these: by-package fetch and the exact
        -- (name, fixed) remediation probe.
        map fromOnly indexes `shouldBe` ["idx_package_fixed", "idx_package_name"]
        -- The reader accepts an artifact only if both tables are STRICT. A freshly
        -- compiled artifact must satisfy its own contract.
        map fromOnly strictTables `shouldBe` ["meta", "package_vulnerability_ranges"]
        -- The dedup guard behind INSERT OR IGNORE.
        map fromOnly dedupIndexes `shouldBe` ["uq_ranges_segment"]

        let meta = Map.fromList metaRows
        Map.keys meta `shouldBe` ["built_at", "ecosystem", "epss_source_url", "pilot_version", "row_count", "source_url"]
        Map.lookup "ecosystem" meta `shouldBe` Just "npm"
        Map.lookup "row_count" meta `shouldBe` Just "1"
        Map.lookup "pilot_version" meta `shouldBe` Just (toText (showVersion version))
        Map.lookup "source_url" meta `shouldSatisfy` maybe False (T.isSuffixOf "/sample.zip")
        Map.lookup "epss_source_url" meta `shouldSatisfy` maybe False (T.isSuffixOf "/epss.csv.gz")
        Map.lookup "built_at" meta `shouldSatisfy` maybe False (not . T.null)

        -- The sample holds one advisory and no bad entries, so the pass records one accepted
        -- entry, a zero under each drop cause, and one completed run.
        recorded <- readRecorded
        recorded `shouldBe` RecordedCompile [1] [(DropOversize, 0), (DropMalformed, 0)] [CompileCompleted]

    it "aborts the compile without publishing when the drop rate is systemic" $ do
        -- 20 malformed entries to one good one trips the systemic-drop breaker. The breaker must
        -- abandon the run rather than finalise an artifact that silently omits most advisories.
        zipData <-
            osvZipOf
                ( [("mal-" <> show i <> ".json", "this is not valid json") | i <- [1 .. 20 :: Int]]
                    <> [("good.json", "{\"id\":\"GHSA-ok\",\"affected\":[{\"package\":{\"name\":\"ok\",\"ecosystem\":\"npm\"},\"versions\":[\"1.0.0\"]}]}")]
                )
        epssData <- LBS.readFile epssFixtureFile
        (metrics, readRecorded) <- recordingAdvisoryCompileMetricsPort
        let action =
                withStub status200 zipData $ \stub ->
                    withStub status200 epssData $ \epssStub ->
                        runOsvTestM (compileOsvToSqlite metrics Nothing "/tmp" (osvEcosystemFor Npm) (sourcesOf stub epssStub "/all.zip"))
        action `shouldThrow` (\(PilotIngestAborted _) -> True)

        -- The abandoned pass still records its tally, and its run reads as aborted, so an
        -- operator alarms on a feed that keeps failing to compile.
        recorded <- readRecorded
        recorded `shouldBe` RecordedCompile [1] [(DropOversize, 0), (DropMalformed, 20)] [CompileAborted]

    it "reads osv.dev's spelling and writes Ecluse's, for an ecosystem that spells them apart" $ do
        -- osv.dev files PyPI advisories under "PyPI" and stamps that spelling on the affected
        -- package. The sync reads "pypi". One name for both would either drop every row or
        -- publish an artifact acceptance refuses, so this pins the two halves together.
        zipData <-
            osvZipOf
                [("pypi-advisory.json", "{\"id\":\"GHSA-pypi\",\"affected\":[{\"package\":{\"name\":\"requests\",\"ecosystem\":\"PyPI\"},\"versions\":[\"1.0.0\"]}]}")]
        epssData <- LBS.readFile epssFixtureFile
        (metrics, _) <- recordingAdvisoryCompileMetricsPort
        dbFile <- withStub status200 zipData $ \stub ->
            withStub status200 epssData $ \epssStub ->
                runOsvTestM (compileOsvToSqlite metrics Nothing "/tmp" (osvEcosystemFor PyPI) (sourcesOf stub epssStub "/all.zip"))

        conn <- open dbFile
        rows <- query_ conn "SELECT package_name FROM package_vulnerability_ranges" :: IO [Only Text]
        metaRows <- query_ conn "SELECT key, value FROM meta" :: IO [(Text, Text)]
        close conn
        catchIOError (removeFile dbFile) (const $ pure ())

        -- The row survived the filter, so the filter matched on osv.dev's spelling.
        map fromOnly rows `shouldBe` ["requests"]
        -- The key and the meta row are what the proxy's sync polls and what acceptance compares.
        takeFileName dbFile `shouldBe` "pypi-osv-schema3.db"
        Map.lookup "ecosystem" (Map.fromList metaRows) `shouldBe` Just "pypi"

    it "keeps an unorderable bound out of the artifact and decodes the \"0\" lower bound" $ do
        -- The malware feed's shape: an advisory naming versions outright. The date-stamped one
        -- carries a bound semver cannot order, which would otherwise deny every version of the
        -- package, and the range's "0" lower bound lands as NULL rather than as a bound nothing
        -- can compare.
        zipData <-
            osvZipOf
                [ ("point.json", "{\"id\":\"MAL-point\",\"affected\":[{\"package\":{\"name\":\"pointy\",\"ecosystem\":\"npm\"},\"versions\":[\"1.0.0\",\"2026.05.1\"]}]}")
                , ("range.json", "{\"id\":\"MAL-range\",\"affected\":[{\"package\":{\"name\":\"ranged\",\"ecosystem\":\"npm\"},\"ranges\":[{\"type\":\"SEMVER\",\"events\":[{\"introduced\":\"0\"},{\"fixed\":\"1.2.3\"}]}]}]}")
                ]
        epssData <- LBS.readFile epssFixtureFile
        (metrics, _) <- recordingAdvisoryCompileMetricsPort
        dbFile <- withStub status200 zipData $ \stub ->
            withStub status200 epssData $ \epssStub ->
                runOsvTestM (compileOsvToSqlite metrics Nothing "/tmp" (osvEcosystemFor Npm) (sourcesOf stub epssStub "/all.zip"))

        conn <- open dbFile
        rows <- query_ conn "SELECT package_name, introduced_version, fixed_version, last_affected_version FROM package_vulnerability_ranges ORDER BY package_name" :: IO [(Text, Maybe Text, Maybe Text, Maybe Text)]
        close conn
        catchIOError (removeFile dbFile) (const $ pure ())

        rows
            `shouldBe` [ ("pointy", Just "1.0.0", Nothing, Just "1.0.0")
                       , ("ranged", Nothing, Just "1.2.3", Nothing)
                       ]

    it "fails the pass when the EPSS feed answers non-2xx, so nothing reaches the export" $ do
        -- A 404 is permanent, so the fetch gives up at once rather than spending the backoff
        -- budget. The compile throws before it writes meta, and the caller's upload never runs.
        zipData <- LBS.readFile "test/unit/fixtures/osv/sample.zip"
        (metrics, _) <- recordingAdvisoryCompileMetricsPort
        let action =
                withStub status200 zipData $ \stub ->
                    withStub status404 LBS.empty $ \epssStub ->
                        runOsvTestM (compileOsvToSqlite metrics Nothing "/tmp" (osvEcosystemFor Npm) (sourcesOf stub epssStub "/all.zip"))
        action `shouldThrow` anyException

    describe "osvToRow" $ do
        let rowFor upper = osvToRow (ExtractedOsv "pkg" "npm" "GHSA-row" (Just "1.0.0") upper (Just 5.9) (Just 0.25))

        it "writes an exclusive bound to fixed_version and leaves last_affected_version null" $
            rowFor (FixedBefore "2.0.0") `shouldBe` ("pkg", "GHSA-row", Just "1.0.0", Just "2.0.0", Nothing, Just 5.9, Just 0.25)

        it "writes an inclusive bound to last_affected_version and leaves fixed_version null" $
            rowFor (LastAffected "2.0.0") `shouldBe` ("pkg", "GHSA-row", Just "1.0.0", Nothing, Just "2.0.0", Just 5.9, Just 0.25)

        it "leaves both bound columns null for a segment with no upper bound" $
            rowFor Unbounded `shouldBe` ("pkg", "GHSA-row", Just "1.0.0", Nothing, Nothing, Just 5.9, Just 0.25)

        it "carries an unscored segment's null epss_score through" $
            osvToRow (ExtractedOsv "pkg" "npm" "GHSA-row" Nothing Unbounded Nothing Nothing)
                `shouldBe` ("pkg", "GHSA-row", Nothing, Nothing, Nothing, Nothing, Nothing)

-- The two upstreams one compile reads, each served by its own stub on an ephemeral port.
sourcesOf :: Stub -> Stub -> String -> CompileSources
sourcesOf osvStub epssStub osvPath =
    CompileSources
        { csOsvExportUrl = unpack (stubBaseUrl osvStub) <> osvPath
        , csEpssFeedUrl = unpack (stubBaseUrl epssStub) <> "/epss.csv.gz"
        }
