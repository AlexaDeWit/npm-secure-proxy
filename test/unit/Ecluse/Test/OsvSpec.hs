-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Test.OsvSpec (spec) where

import Database.SQLite.Simple (Only (..), close, open, query_)
import System.FilePath ((</>))
import System.IO.Temp (withSystemTempDirectory)
import Test.Hspec (Spec, describe, it, shouldBe, shouldReturn)

import Ecluse.Core.Osv.Schema (osvSchemaEpoch)
import Ecluse.Test.Osv (CorpusVersion (..), mkDbWithViewShadowingRanges, mkDbWithWrongEpoch)
import Ecluse.Test.OsvDb (withFixtureOsvDb)

-- (package, cve, introduced, fixed, severity, epss). Severity is the numeric CVSS score
-- the writer stores, and epss the score the fixture feed carries for the advisory's alias.
type RangeRow = (Text, Text, Maybe Text, Maybe Text, Maybe Double, Maybe Double)

-- The pins are literal on purpose: editing the corpus or the EPSS fixture means updating
-- them, deliberately, in the same change. LOW->3.9, MODERATE->6.9, HIGH->8.9, CRITICAL->10.0.
-- A NULL epss is an advisory the fixture feed does not score, and a NULL introduced is a
-- fixture spelling its lower bound "0", OSV's sentinel for "from the beginning".
corpusV1Rows :: [RangeRow]
corpusV1Rows =
    [ ("@corpus/scoped", "GHSA-corpus-0005", Nothing, Just "3.0.0", Just 3.9, Just 0.25)
    , ("corpus-mixed", "GHSA-corpus-0006", Nothing, Just "1.0.0", Just 6.9, Nothing)
    , ("corpus-multi", "GHSA-corpus-0003", Nothing, Just "1.0.0", Nothing, Nothing)
    , ("corpus-multi", "GHSA-corpus-0003", Just "1.5.0", Just "2.0.0", Nothing, Nothing)
    , ("corpus-unfixed", "GHSA-corpus-0002", Just "1.0.0", Nothing, Just 10.0, Just 0.5)
    , ("corpus-vuln", "GHSA-corpus-0001", Nothing, Just "1.2.0", Just 8.9, Just 0.875)
    , ("corpus-vuln", "GHSA-corpus-0004", Just "2.0.0", Just "2.5.0", Just 6.9, Just 0.0625)
    ]

corpusV2Rows :: [RangeRow]
corpusV2Rows =
    [ ("@corpus/scoped", "GHSA-corpus-0005", Nothing, Just "3.0.0", Just 3.9, Just 0.25)
    , ("corpus-clean", "GHSA-corpus-1001", Nothing, Nothing, Just 8.9, Just 0.375)
    , ("corpus-mixed", "GHSA-corpus-0006", Nothing, Just "1.0.0", Just 6.9, Nothing)
    , ("corpus-multi", "GHSA-corpus-0003", Nothing, Just "1.0.0", Nothing, Nothing)
    , ("corpus-multi", "GHSA-corpus-0003", Just "1.5.0", Just "2.0.0", Nothing, Nothing)
    , ("corpus-unfixed", "GHSA-corpus-0002", Just "1.0.0", Nothing, Just 10.0, Just 0.5)
    , ("corpus-vuln", "GHSA-corpus-0001", Nothing, Just "1.2.0", Just 8.9, Just 0.875)
    , ("corpus-vuln", "GHSA-corpus-0004", Just "2.0.0", Just "2.5.0", Just 6.9, Just 0.0625)
    ]

rangeRows :: FilePath -> IO [RangeRow]
rangeRows db = do
    conn <- open db
    rows <- query_ conn "SELECT package_name, cve_id, introduced_version, fixed_version, severity, epss_score FROM package_vulnerability_ranges ORDER BY package_name, cve_id, introduced_version"
    close conn
    pure rows

spec :: Spec
spec = do
    describe "the OSV fixture corpus" $ do
        -- Full-table equality: the malformed corpus entry contributes zero rows, so
        -- its omission is the assertion.
        it "compiles CorpusV1 to exactly the pinned advisory ranges" $
            withFixtureOsvDb CorpusV1 (\db -> rangeRows db `shouldReturn` corpusV1Rows)

        it "compiles CorpusV2 to CorpusV1 plus the corpus-clean advisory (the swap flip)" $
            withFixtureOsvDb CorpusV2 (\db -> rangeRows db `shouldReturn` corpusV2Rows)

        it "omits foreign affected packages from mixed-ecosystem advisories" $
            withFixtureOsvDb CorpusV1 $ \db -> do
                conn <- open db
                rows <- query_ conn "SELECT package_name FROM package_vulnerability_ranges WHERE package_name = 'redis'" :: IO [Only Text]
                close conn
                map fromOnly rows `shouldBe` []

        it "stamps the generated artifact with the current schema epoch" $
            withFixtureOsvDb CorpusV1 $ \db -> do
                conn <- open db
                stamped <- query_ conn "PRAGMA user_version" :: IO [Only Int]
                close conn
                map fromOnly stamped `shouldBe` [osvSchemaEpoch]

    describe "hostile artifacts" $ do
        it "the wrong-epoch artifact carries a mismatched user_version" $
            withSystemTempDirectory "ecluse-osv-hostile" $ \dir -> do
                let path = dir </> "wrong-epoch.db"
                mkDbWithWrongEpoch path
                conn <- open path
                stamped <- query_ conn "PRAGMA user_version" :: IO [Only Int]
                close conn
                map fromOnly stamped `shouldBe` [osvSchemaEpoch + 1]

        it "the view-shadowed artifact defines the ranges relation as a view, not a table" $
            withSystemTempDirectory "ecluse-osv-hostile" $ \dir -> do
                let path = dir </> "view-shadow.db"
                mkDbWithViewShadowingRanges path
                conn <- open path
                kinds <- query_ conn "SELECT type FROM sqlite_master WHERE name = 'package_vulnerability_ranges'" :: IO [Only Text]
                close conn
                map fromOnly kinds `shouldBe` ["view"]
