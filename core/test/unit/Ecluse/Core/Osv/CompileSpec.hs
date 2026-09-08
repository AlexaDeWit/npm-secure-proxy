-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT
{-# LANGUAGE OverloadedStrings #-}

{- | Compiler regressions over committed feeds
and local HTTP stubs.
-}
module Ecluse.Core.Osv.CompileSpec (spec) where

import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as LBS
import Data.List (lookup)
import Data.Map.Strict qualified as Map
import Data.Text (unpack)
import Data.Text qualified as T
import Data.Version (showVersion)
import Database.SQLite.Simple
import Katip (LogEnv, closeScribes)
import Paths_ecluse (version)
import System.Directory (doesFileExist, listDirectory, removeFile)
import System.FilePath (takeFileName, (</>))
import System.IO.Error (catchIOError)
import System.IO.Temp (withSystemTempDirectory)
import Test.Hspec (Spec, anyException, describe, it, shouldBe, shouldReturn, shouldSatisfy, shouldThrow)
import UnliftIO.Exception (finally)

import Ecluse.Core.Cve (CveDb (..), CveLookup (..), openCveDb)
import Ecluse.Core.Ecosystem (Ecosystem (Npm, PyPI))
import Ecluse.Core.Osv.Advisory (ExtractedOsv (..))
import Ecluse.Core.Osv.Compile (CompileSources (..), compileOsvToSqlite, osvToRow)
import Ecluse.Core.Osv.Ecosystem (osvEcosystemFor)
import Ecluse.Core.Osv.Schema (osvDbFileName, osvSchemaEpoch)
import Ecluse.Core.Osv.Stream (PilotIngestAborted (..))
import Ecluse.Core.Osv.Types (UpperBound (..))
import Ecluse.Core.Security.Authority (authorityLabel)
import Ecluse.Core.Telemetry.Metrics (
    AdvisoryCompileResult (CompileAborted, CompileCompleted),
    AdvisoryDropCause (DropMalformed, DropOversize),
 )
import Ecluse.Test.Log (captureStdout, jsonLogEnv)
import Ecluse.Test.Osv (CorpusVersion (CorpusV1), osvCorpusZip, osvZipOf, runOsvTestM, runOsvTestMWith)
import Ecluse.Test.OsvDb (epssFixtureFile)
import Ecluse.Test.Port (RecordedCompile (RecordedCompile), recordingAdvisoryCompileMetricsPort)
import Ecluse.Test.Stub (Stub, stubBaseUrl, withStub)
import Network.HTTP.Client (applyBasicAuth, defaultRequest, requestHeaders)
import Network.HTTP.Types.Status (status200, status404)
import Network.Wai qualified as Wai
import Network.Wai.Handler.Warp (testWithApplication)

spec :: Spec
spec = describe "SQLite OSV Compilation" $ do
    it "fetches an OSV zip and compiles it into a named, stamped SQLite artifact" $ do
        zipData <- LBS.readFile "test/unit/fixtures/osv/sample.zip"
        epssData <- LBS.readFile epssFixtureFile
        (metrics, readRecorded) <- recordingAdvisoryCompileMetricsPort
        (dbFile, sourceHost, epssHost) <- withStub status200 zipData $ \stub ->
            withStub status200 epssData $ \epssStub ->
                (,authorityLabel (stubBaseUrl stub),authorityLabel (stubBaseUrl epssStub))
                    <$> runOsvTestM (compileOsvToSqlite metrics Nothing "/tmp" (osvEcosystemFor Npm) (sourcesOf stub epssStub "/sample.zip"))

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
        takeFileName dbFile `shouldBe` "npm-osv-schema4.db"
        -- EPSS joins through CVE-2024-48913, while the row retains the GHSA id.
        rows `shouldBe` [("hono", "GHSA-2234-fmw7-43wr", Just "4.6.5", Just 5.9, Just 0.75)]
        map fromOnly stamped `shouldBe` [osvSchemaEpoch]
        map fromOnly indexes `shouldBe` ["idx_package_fixed", "idx_package_name"]
        map fromOnly strictTables `shouldBe` ["meta", "package_vulnerability_ranges"]
        map fromOnly dedupIndexes `shouldBe` ["uq_ranges_segment"]

        let meta = Map.fromList metaRows
        Map.keys meta `shouldBe` ["built_at", "ecosystem", "epss_source_url", "pilot_version", "row_count", "source_url"]
        Map.lookup "ecosystem" meta `shouldBe` Just "npm"
        Map.lookup "row_count" meta `shouldBe` Just "1"
        Map.lookup "pilot_version" meta `shouldBe` Just (toText (showVersion version))
        Map.lookup "source_url" meta `shouldBe` Just sourceHost
        Map.lookup "epss_source_url" meta `shouldBe` Just epssHost
        Map.lookup "built_at" meta `shouldSatisfy` maybe False (not . T.null)

        recorded <- readRecorded
        recorded `shouldBe` RecordedCompile [1] [(DropOversize, 0), (DropMalformed, 0)] [CompileCompleted]

    it "fetches both credential-bearing overrides without persisting or logging their credentials" $ do
        zipData <- LBS.readFile "test/unit/fixtures/osv/sample.zip"
        epssData <- LBS.readFile epssFixtureFile
        (metrics, _) <- recordingAdvisoryCompileMetricsPort
        (dbFile, logged) <- captureStdout' $ \logEnv ->
            withCredentialSource "OSV" zipData $ \source ->
                withCredentialSource "EPSS" epssData $ \epssSource -> do
                    path <- runOsvTestMWith logEnv (compileOsvToSqlite metrics Nothing "/tmp" (osvEcosystemFor Npm) (CompileSources source epssSource))
                    withConnection path $ \conn -> do
                        meta <- Map.fromList <$> (query_ conn "SELECT key, value FROM meta" :: IO [(Text, Text)])
                        Map.lookup "source_url" meta `shouldBe` Just (authorityLabel (toText source))
                        Map.lookup "epss_source_url" meta `shouldBe` Just (authorityLabel (toText epssSource))
                        Map.lookup "built_at" meta `shouldSatisfy` maybe False (not . T.null)
                        Map.lookup "row_count" meta `shouldBe` Just "1"
                    pure path
        bytes <- readFileBS dbFile
        for_ ["OSV", "EPSS"] $ \tag ->
            for_ ["user-", "password-", "query-", "fragment-"] $ \prefix -> do
                let credential = prefix <> tag
                bytes `shouldSatisfy` (not . BS.isInfixOf (encodeUtf8 credential))
                logged `shouldSatisfy` (not . T.isInfixOf credential)
        removeFile dbFile

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

        recorded <- readRecorded
        recorded `shouldBe` RecordedCompile [1] [(DropOversize, 0), (DropMalformed, 20)] [CompileAborted]

    it "accepts a rebuilt PyPI artifact with canonical names and raw fix versions" $ do
        zipData <-
            osvZipOf
                [("pypi-advisory.json", "{\"id\":\"GHSA-pypi\",\"affected\":[{\"package\":{\"name\":\"Flask_Thing\",\"ecosystem\":\"PyPI\"},\"ranges\":[{\"type\":\"ECOSYSTEM\",\"events\":[{\"introduced\":\"0\"},{\"fixed\":\"1.0.0\"}]}]}]}")]
        epssData <- LBS.readFile epssFixtureFile
        (metrics, _) <- recordingAdvisoryCompileMetricsPort
        dbFile <- withStub status200 zipData $ \stub ->
            withStub status200 epssData $ \epssStub ->
                runOsvTestM (compileOsvToSqlite metrics Nothing "/tmp" (osvEcosystemFor PyPI) (sourcesOf stub epssStub "/all.zip"))

        conn <- open dbFile
        rows <- query_ conn "SELECT package_name FROM package_vulnerability_ranges" :: IO [Only Text]
        metaRows <- query_ conn "SELECT key, value FROM meta" :: IO [(Text, Text)]
        close conn

        map fromOnly rows `shouldBe` ["flask-thing"]
        takeFileName dbFile `shouldBe` "pypi-osv-schema4.db"
        Map.lookup "ecosystem" (Map.fromList metaRows) `shouldBe` Just "pypi"
        openCveDb PyPI dbFile >>= \case
            Left rejection -> fail ("rebuilt PyPI artifact rejected: " <> show rejection)
            Right db -> flip finally (cveDbClose db) $ do
                let cve = cveDbLookup db
                cveCoveredNames cve `shouldReturn` ["flask-thing"]
                cveRemediationProbe cve "flask-thing" "1.0.0" `shouldReturn` True
                cveRemediationProbe cve "flask-thing" "1.0" `shouldReturn` False
                cveAdvisoriesFor cve "flask-thing" >>= (`shouldSatisfy` (not . null))
        removeFile dbFile

    it "writes an unorderable bound into the artifact and decodes the \"0\" lower bound" $ do
        -- Malware feeds can name versions outside semver. Dropping them would admit affected versions.
        zipData <-
            osvZipOf
                [ ("point.json", "{\"id\":\"MAL-point\",\"affected\":[{\"package\":{\"name\":\"pointy\",\"ecosystem\":\"npm\"},\"versions\":[\"1.0.0\",\"2026.05.1\"]}]}")
                , ("range.json", "{\"id\":\"MAL-range\",\"affected\":[{\"package\":{\"name\":\"ranged\",\"ecosystem\":\"npm\"},\"ranges\":[{\"type\":\"SEMVER\",\"events\":[{\"introduced\":\"0\"},{\"fixed\":\"1.2.3\"}]}]}]}")
                ]
        epssData <- LBS.readFile epssFixtureFile
        (metrics, _) <- recordingAdvisoryCompileMetricsPort
        (dbFile, logged) <- captureStdout' $ \logEnv ->
            withStub status200 zipData $ \stub ->
                withStub status200 epssData $ \epssStub ->
                    runOsvTestMWith logEnv (compileOsvToSqlite metrics Nothing "/tmp" (osvEcosystemFor Npm) (sourcesOf stub epssStub "/all.zip"))

        logged `shouldSatisfy` T.isInfixOf "for example pointy 2026.05.1"
        logged `shouldSatisfy` T.isInfixOf "kept 1 unorderable"
        logged `shouldSatisfy` (not . T.isInfixOf "\"sev\":\"Error\"")

        conn <- open dbFile
        rows <- query_ conn "SELECT package_name, introduced_version, fixed_version, last_affected_version FROM package_vulnerability_ranges ORDER BY package_name, introduced_version" :: IO [(Text, Maybe Text, Maybe Text, Maybe Text)]
        close conn
        catchIOError (removeFile dbFile) (const $ pure ())

        rows
            `shouldBe` [ ("pointy", Just "1.0.0", Nothing, Just "1.0.0")
                       , ("pointy", Just "2026.05.1", Nothing, Just "2026.05.1")
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

    for_ [("empty", osvZipOf []), ("wrong-ecosystem", LBS.readFile "test/unit/fixtures/osv/sample.zip")] $ \(label, rejectedZip) ->
        for_ [False, True] $ \hasPrevious ->
            it ("refuses " <> label <> " output with ERROR and preserves publication state, previous=" <> show hasPrevious) $
                withSystemTempDirectory "ecluse-zero-output" $ \outDir -> do
                    epssData <- LBS.readFile epssFixtureFile
                    goodZip <- osvCorpusZip CorpusV1
                    badZip <- rejectedZip
                    (metrics, readRecorded) <- recordingAdvisoryCompileMetricsPort
                    let dbFile = outDir </> osvDbFileName "pypi"
                        compile logEnv zipData = withStub status200 zipData $ \stub ->
                            withStub status200 epssData $ \epssStub ->
                                runOsvTestMWith logEnv (compileOsvToSqlite metrics Nothing outDir (osvEcosystemFor PyPI) (sourcesOf stub epssStub "/all.zip"))
                    previous <-
                        if hasPrevious
                            then do
                                (path, _) <- captureStdout' (`compile` goodZip)
                                Just <$> readFileBS path
                            else pure Nothing
                    (_, logged) <- captureStdout' $ \logEnv ->
                        compile logEnv badZip `shouldThrow` (\(PilotIngestAborted _) -> True)
                    logged `shouldSatisfy` T.isInfixOf "zero relevant advisory rows"
                    logged `shouldSatisfy` T.isInfixOf "\"sev\":\"Error\""
                    recorded <- readRecorded
                    case recorded of
                        RecordedCompile _ _ verdicts -> verdicts `shouldBe` ([CompileCompleted | hasPrevious] <> [CompileAborted])
                    case previous of
                        Nothing -> do
                            doesFileExist dbFile >>= (`shouldBe` False)
                            listDirectory outDir >>= (`shouldBe` [])
                        Just bytes -> do
                            readFileBS dbFile >>= (`shouldBe` bytes)
                            listDirectory outDir >>= (`shouldBe` [takeFileName dbFile])

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

captureStdout' :: (LogEnv -> IO a) -> IO (a, Text)
captureStdout' body = do
    resultRef <- newIORef Nothing
    logged <- captureStdout $ do
        logEnv <- jsonLogEnv
        body logEnv >>= writeIORef resultRef . Just
        void (closeScribes logEnv)
    result <- readIORef resultRef
    maybe (fail "the compile under capture produced no result") (pure . (,logged)) result

sourcesOf :: Stub -> Stub -> String -> CompileSources
sourcesOf osvStub epssStub osvPath =
    CompileSources
        { csOsvExportUrl = unpack (stubBaseUrl osvStub) <> osvPath
        , csEpssFeedUrl = unpack (stubBaseUrl epssStub) <> "/epss.csv.gz"
        }

-- The shared stub omits query strings, so this fixture checks authentication before serving bytes.
withCredentialSource :: Text -> LByteString -> (String -> IO a) -> IO a
withCredentialSource tag bytes use =
    testWithApplication (pure app) $ \port ->
        use (toString ("http://user-" <> tag <> ":password-" <> tag <> "@127.0.0.1:" <> show port <> "/feed?unfamiliar=query-" <> tag <> "#fragment-" <> tag))
  where
    expectedAuth = lookup "Authorization" (requestHeaders (applyBasicAuth (encodeUtf8 ("user-" <> tag)) (encodeUtf8 ("password-" <> tag)) defaultRequest))
    app request respond = do
        let authorised =
                lookup "Authorization" (Wai.requestHeaders request) == expectedAuth
                    && Wai.rawQueryString request == encodeUtf8 ("?unfamiliar=query-" <> tag)
                    && Wai.rawPathInfo request == "/feed"
        respond (Wai.responseLBS (if authorised then status200 else status404) [] (if authorised then bytes else "credentials missing"))
