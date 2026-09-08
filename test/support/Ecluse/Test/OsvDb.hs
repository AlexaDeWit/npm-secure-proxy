-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Compile temporary advisory artifacts through Pilot's compiler.
Local HTTP stubs serve the chosen OSV archive and the shared EPSS feed slice.
-}
module Ecluse.Test.OsvDb (
    epssFixtureFile,
    withFixtureOsvDb,
    withOsvZipDb,
) where

import Network.HTTP.Types.Status (status200)
import System.IO.Temp (withSystemTempDirectory)

import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.Osv.Compile (CompileSources (..), compileOsvToSqlite)
import Ecluse.Core.Osv.Ecosystem (osvEcosystemFor)
import Ecluse.Test.Osv (CorpusVersion, osvCorpusZip, runOsvTestM)
import Ecluse.Test.Port (noopAdvisoryCompileMetricsPort)
import Ecluse.Test.Stub (stubBaseUrl, withStub)

{- | The gzipped EPSS feed slice the fixture artifacts join against. It scores the CVE
aliases the corpus advisories carry, and deliberately omits some of them.
-}
epssFixtureFile :: FilePath
epssFixtureFile = "test/unit/fixtures/epss/sample-epss.csv.gz"

-- | Compile a committed corpus version into a temporary artifact through local HTTP stubs.
withFixtureOsvDb :: CorpusVersion -> (FilePath -> IO a) -> IO a
withFixtureOsvDb v use = do
    zipBytes <- osvCorpusZip v
    withOsvZipDb Npm zipBytes use

-- | Compile an archive and the shared EPSS slice into a temporary ecosystem artifact over local HTTP.
withOsvZipDb :: Ecosystem -> LByteString -> (FilePath -> IO a) -> IO a
withOsvZipDb eco zipBytes use = do
    epssBytes <- readFileLBS epssFixtureFile
    withSystemTempDirectory "ecluse-osv-fixture" $ \dir ->
        withStub status200 zipBytes $ \osvStub ->
            withStub status200 epssBytes $ \epssStub -> do
                dbFile <-
                    runOsvTestM
                        ( compileOsvToSqlite
                            noopAdvisoryCompileMetricsPort
                            Nothing
                            dir
                            (osvEcosystemFor eco)
                            CompileSources
                                { csOsvExportUrl = toString (stubBaseUrl osvStub) <> "/all.zip"
                                , csEpssFeedUrl = toString (stubBaseUrl epssStub) <> "/epss_scores-current.csv.gz"
                                }
                        )
                use dbFile
