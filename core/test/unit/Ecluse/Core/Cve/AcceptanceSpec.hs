-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Core.Cve.AcceptanceSpec (spec) where

import Data.List (isSuffixOf)
import Database.SQLite.Simple (Only, Query (Query), SQLError, close, execute_, fromOnly, open, query_)
import System.Directory (getSymbolicLinkTarget, listDirectory)
import System.FilePath ((</>))
import System.IO.Temp (withSystemTempDirectory)
import Test.Hspec (Spec, describe, it, shouldBe, shouldReturn, shouldSatisfy, shouldThrow)
import UnliftIO.Exception (bracket, catchAny, finally, try)

import Ecluse.Core.Cve (AdvisoryRange (..), CveDb (..), CveDbRejected (..), CveLookup (..), CveQueryFault (cqfQuery), openCveDb)
import Ecluse.Core.Cve.Internal (openHardenedConnection, toRange)
import Ecluse.Core.Ecosystem (Ecosystem (Npm, PyPI))
import Ecluse.Core.Osv.Schema (metaTableDdl, osvSchemaEpoch, rangesTableDdl)
import Ecluse.Core.Osv.Types (UpperBound (..))
import Ecluse.Test.Cve (fakeCveLookup)
import Ecluse.Test.Osv (CorpusVersion (CorpusV1), mkDbWithCorruptPage, mkDbWithLaxSchema, mkDbWithMalformedProvenance, mkDbWithMaliciousTrigger, mkDbWithViewShadowingRanges, mkDbWithWrongEpoch, mkDbWithoutEpssColumn)
import Ecluse.Test.OsvDb (withFixtureOsvDb)

-- CorpusV1's rows in the fake's vocabulary. Keep them in lockstep with the corpus pins in
-- Ecluse.Test.OsvSpec. Each severity is the CVSS band ceiling for the fixture's GHSA label
-- (LOW 3.9, MODERATE 6.9, HIGH 8.9, CRITICAL 10.0), each EPSS score comes from the fixture
-- feed's row for the advisory's CVE alias, and no fixture carries a last_affected bound. A
-- fixture spelling its lower bound "0" compiles to no lower bound, the OSV sentinel decoded.
corpusRows :: [(Text, AdvisoryRange)]
corpusRows =
    [ ("@corpus/scoped", AdvisoryRange "GHSA-corpus-0005" (Just 3.9) Nothing (FixedBefore "3.0.0") (Just 0.25))
    , ("corpus-multi", AdvisoryRange "GHSA-corpus-0003" Nothing Nothing (FixedBefore "1.0.0") Nothing)
    , ("corpus-multi", AdvisoryRange "GHSA-corpus-0003" Nothing (Just "1.5.0") (FixedBefore "2.0.0") Nothing)
    , ("corpus-unfixed", AdvisoryRange "GHSA-corpus-0002" (Just 10.0) (Just "1.0.0") Unbounded (Just 0.5))
    , ("corpus-vuln", AdvisoryRange "GHSA-corpus-0001" (Just 8.9) Nothing (FixedBefore "1.2.0") (Just 0.875))
    , ("corpus-vuln", AdvisoryRange "GHSA-corpus-0004" (Just 6.9) (Just "2.0.0") (FixedBefore "2.5.0") (Just 0.0625))
    ]

-- The behavioural contract, written once and run against every 'CveLookup'
-- implementation, so the fake the core suite trusts cannot drift from the real handle.
lookupContract :: ((CveLookup -> IO ()) -> IO ()) -> Spec
lookupContract withLookup = do
    it "probes True for a version an advisory names as its fixed bound" $
        withLookup $ \l -> do
            cveRemediationProbe l "corpus-vuln" "1.2.0" `shouldReturn` True
            cveRemediationProbe l "corpus-vuln" "2.5.0" `shouldReturn` True
            cveRemediationProbe l "@corpus/scoped" "3.0.0" `shouldReturn` True

    it "probes False for versions no advisory names as a fix" $
        withLookup $ \l -> do
            cveRemediationProbe l "corpus-vuln" "1.2.1" `shouldReturn` False
            cveRemediationProbe l "corpus-unfixed" "1.0.0" `shouldReturn` False
            cveRemediationProbe l "no-such-package" "1.0.0" `shouldReturn` False

    it "returns every advisory range recorded against a package" $
        withLookup $ \l -> do
            ranges <- cveAdvisoriesFor l "corpus-vuln"
            sortOn arCveId ranges
                `shouldBe` [ AdvisoryRange "GHSA-corpus-0001" (Just 8.9) Nothing (FixedBefore "1.2.0") (Just 0.875)
                           , AdvisoryRange "GHSA-corpus-0004" (Just 6.9) (Just "2.0.0") (FixedBefore "2.5.0") (Just 0.0625)
                           ]

    it "returns nothing for a package with no advisories" $
        withLookup (\l -> cveAdvisoriesFor l "no-such-package" `shouldReturn` [])

    it "enumerates every name it holds an advisory against" $
        withLookup $ \l -> do
            covered <- cveCoveredNames l
            filter (`notElem` covered) (ordNub (map fst corpusRows)) `shouldBe` []

    it "enumerates a name carrying several advisories once, so a sweep reads it once" $
        -- corpus-multi carries two ranges, so a per-row enumeration would name it twice and make
        -- the store sweep read the same package's metadata twice in one cycle.
        withLookup $ \l -> do
            covered <- cveCoveredNames l
            length covered `shouldBe` length (ordNub covered)

    it "names nothing it holds no advisory against" $
        withLookup $ \l -> do
            covered <- cveCoveredNames l
            ranges <- traverse (cveAdvisoriesFor l) covered
            filter null ranges `shouldBe` []

withFakeLookup :: (CveLookup -> IO ()) -> IO ()
withFakeLookup use = use (fakeCveLookup corpusRows)

-- Hand the body the fixture artifact's path and its accepted owning handle. A
-- rejection of the fixture is a loud test failure. The body owns the close.
withAcceptedDb :: (FilePath -> CveDb -> IO ()) -> IO ()
withAcceptedDb body =
    withFixtureOsvDb CorpusV1 $ \dbFile ->
        openCveDb Npm dbFile >>= \case
            Left rejection -> fail ("fixture artifact unexpectedly rejected: " <> show rejection)
            Right db -> body dbFile db

withRealLookup :: (CveLookup -> IO ()) -> IO ()
withRealLookup use =
    withFixtureOsvDb CorpusV1 $
        openCveDb Npm >=> \case
            Left rejection -> fail ("fixture artifact unexpectedly rejected: " <> show rejection)
            Right db -> use (cveDbLookup db) `finally` cveDbClose db

spec :: Spec
spec = do
    describe "CveLookup conformance (the fake and the real handle agree)" $ do
        describe "in-memory fake" (lookupContract withFakeLookup)
        describe "SQLite handle over the compiled corpus" (lookupContract withRealLookup)

    describe "openCveDb acceptance" $ do
        it "rejects an artifact stamped with the wrong schema epoch" $
            withSystemTempDirectory "ecluse-cve-hostile" $ \dir -> do
                let path = dir </> "wrong-epoch.db"
                mkDbWithWrongEpoch path
                openCveDb Npm path >>= rejectionShouldBe (CveDbWrongEpoch (osvSchemaEpoch + 1))

        it "rejects an artifact whose ranges relation is a view" $
            withSystemTempDirectory "ecluse-cve-hostile" $ \dir -> do
                let path = dir </> "view-shadow.db"
                mkDbWithViewShadowingRanges path
                openCveDb Npm path >>= rejectionShouldBe (CveDbSchemaNonConformant "package_vulnerability_ranges")

        it "rejects an artifact whose tables are not STRICT" $
            withSystemTempDirectory "ecluse-cve-hostile" $ \dir -> do
                let path = dir </> "lax-schema.db"
                -- The reader cannot trust decodes under affinity-hinted (non-STRICT) declarations,
                -- so schema conformance must refuse the artifact as a value.
                mkDbWithLaxSchema path
                openCveDb Npm path >>= rejectionShouldBe (CveDbSchemaNonConformant "package_vulnerability_ranges")

        it "rejects an artifact whose ranges table lacks a column the reader decodes" $
            withSystemTempDirectory "ecluse-cve-hostile" $ \dir -> do
                let path = dir </> "no-epss-column.db"
                -- Reading a pre-column artifact would present every advisory as unscored, which
                -- an EPSS deny rule reads as a denial. Conformance refuses it instead.
                mkDbWithoutEpssColumn path
                openCveDb Npm path >>= rejectionShouldBe (CveDbSchemaNonConformant "package_vulnerability_ranges")

        it "rejects an artifact compiled for a different ecosystem" $
            withFixtureOsvDb CorpusV1 (openCveDb PyPI >=> rejectionShouldBe (CveDbEcosystemMismatch (Just "npm")))

        it "rejects an artifact with no meta table as a value, without leaking the connection" $
            withSystemTempDirectory "ecluse-cve-hostile" $ \dir -> do
                let path = dir </> "no-meta.db"
                -- A structurally-sound artifact with no @meta@ table. An uncaught throw would re-
                -- download the artifact every poll and leak the just-opened connection, so refusal
                -- must be a value.
                bracket (open path) close $ \conn -> do
                    execute_ conn ("PRAGMA user_version = " <> show osvSchemaEpoch)
                    execute_ conn (Query rangesTableDdl)
                openCveDb Npm path >>= rejectionShouldBe (CveDbSchemaNonConformant "meta")
                -- The rejected artifact's connection must not leak.
                held <- openFdTargets
                held `shouldSatisfy` not . any (path `isSuffixOf`)

        it "rejects an artifact whose meta lacks the ecosystem row" $
            withSystemTempDirectory "ecluse-cve-hostile" $ \dir -> do
                let path = dir </> "no-ecosystem-row.db"
                -- Conformant tables, but @meta@ never names an ecosystem: acceptance
                -- cannot confirm the ecosystem, and the refusal is a value.
                bracket (open path) close $ \conn -> do
                    execute_ conn ("PRAGMA user_version = " <> show osvSchemaEpoch)
                    execute_ conn (Query rangesTableDdl)
                    execute_ conn (Query metaTableDdl)
                openCveDb Npm path >>= rejectionShouldBe (CveDbEcosystemMismatch Nothing)

        it "rejects an artifact whose stored meta values violate the strict declaration, without leaking the connection" $
            withSystemTempDirectory "ecluse-cve-hostile" $ \dir -> do
                let path = dir </> "malformed-meta.db"
                -- A BLOB smuggled under a forged STRICT declaration. Refusal must be a rejection
                -- value, never a thrown decode error, so the sync task remembers its ETag.
                mkDbWithMalformedProvenance path
                openCveDb Npm path >>= \case
                    Left (CveDbIntegrityFailed problems) -> problems `shouldSatisfy` not . null
                    Left other -> fail ("expected CveDbIntegrityFailed, got " <> show other)
                    Right db -> do
                        cveDbClose db
                        fail "expected the forged artifact to be rejected, but it was accepted"
                -- The rejected artifact's connection must not leak: no descriptor
                -- may still reference the artifact.
                held <- openFdTargets
                held `shouldSatisfy` not . any (path `isSuffixOf`)

        it "ignores a malicious trigger: reads behave as on a clean artifact" $
            withSystemTempDirectory "ecluse-cve-hostile" $ \dir -> do
                let path = dir </> "trigger.db"
                mkDbWithMaliciousTrigger path
                openCveDb Npm path >>= \case
                    Left rejection -> fail ("trigger artifact unexpectedly rejected: " <> show rejection)
                    Right db ->
                        (cveRemediationProbe (cveDbLookup db) "trigger-pkg" "1.0.0" `shouldReturn` True)
                            `finally` cveDbClose db

        it "rejects an artifact whose b-tree pages are structurally corrupt" $
            withSystemTempDirectory "ecluse-cve-hostile" $ \dir -> do
                let path = dir </> "corrupt.db"
                mkDbWithCorruptPage path
                openCveDb Npm path >>= \case
                    Left (CveDbIntegrityFailed problems) -> problems `shouldSatisfy` not . null
                    Left other -> fail ("expected CveDbIntegrityFailed, got " <> show other)
                    Right db -> do
                        cveDbClose db
                        fail "expected a corrupt artifact to be rejected, but it was accepted"

        it "rejects a non-SQLite artifact as a value, without leaking the connection" $
            withSystemTempDirectory "ecluse-cve-hostile" $ \dir -> do
                let path = dir </> "not-a-database.db"
                -- Arbitrary non-SQLite bytes make SQLite raise SQLITE_NOTADB. Refusal must be a
                -- value, or the connection leaks and the sync task re-downloads the same hostile
                -- object every poll.
                writeFileBS path "this is not an SQLite database, not even close"
                openCveDb Npm path >>= \case
                    Left (CveDbIntegrityFailed problems) -> problems `shouldSatisfy` not . null
                    Left other -> fail ("expected CveDbIntegrityFailed, got " <> show other)
                    Right db -> do
                        cveDbClose db
                        fail "expected a non-SQLite artifact to be rejected, but it was accepted"
                -- The rejected artifact's connection must not leak: no descriptor
                -- may still reference the file.
                held <- openFdTargets
                held `shouldSatisfy` not . any (path `isSuffixOf`)

    describe "the confined query-fault channel" $ do
        it "re-raises a mid-query SQLite fault as CveQueryFault, tagged with the field asked" $
            withAcceptedDb $ \dbFile db -> do
                -- A second, unhardened connection breaks the schema under the open handle. The next
                -- query through the view raises the infrastructural fault the confined channel
                -- carries.
                saboteur <- open dbFile
                execute_ saboteur "DROP TABLE package_vulnerability_ranges"
                close saboteur
                probed <- try (cveRemediationProbe (cveDbLookup db) "corpus-vuln" "1.2.0")
                first cqfQuery probed `shouldBe` Left "remediation-probe"
                listed <- try (cveAdvisoriesFor (cveDbLookup db) "corpus-vuln")
                bimap cqfQuery (map arCveId) listed `shouldBe` Left "advisories-for"
                cveDbClose db

        it "cveDbClose never throws, a second close of the same handle included" $
            withAcceptedDb $ \_dbFile db -> do
                cveDbClose db
                -- The handle absorbs the close fault (the connection is already
                -- released): total by construction.
                cveDbClose db

    describe "the hardened connection" $ do
        it "refuses writes outright, so no trigger can ever fire through it" $
            withFixtureOsvDb CorpusV1 $ \dbFile -> do
                opened <- openHardenedConnection Npm dbFile
                case opened of
                    Left rejection -> fail ("fixture artifact unexpectedly rejected: " <> show rejection)
                    Right conn -> do
                        let write = execute_ conn "INSERT INTO meta (key, value) VALUES ('tampered', '1')"
                        write `shouldThrow` \(_ :: SQLError) -> True
                        close conn

        it "validates cell sizes and reads through the pager, not a memory map" $
            withFixtureOsvDb CorpusV1 $ \dbFile -> do
                opened <- openHardenedConnection Npm dbFile
                case opened of
                    Left rejection -> fail ("fixture artifact unexpectedly rejected: " <> show rejection)
                    Right conn -> do
                        cellCheck <- query_ conn "PRAGMA cell_size_check" :: IO [Only Int]
                        mmap <- query_ conn "PRAGMA mmap_size" :: IO [Only Int]
                        map fromOnly cellCheck `shouldBe` [1]
                        map fromOnly mmap `shouldBe` [0]
                        close conn

    describe "the artifact row decode" $ do
        let boundOf fixed lastAffected = arUpperBound (toRange ("GHSA-decode", Just "1.0.0", fixed, lastAffected, Just 5.9, Just 0.5))

        it "reads a fixed_version column as an exclusive bound" $
            boundOf (Just "2.0.0") Nothing `shouldBe` FixedBefore "2.0.0"

        it "reads a last_affected_version column as an inclusive bound" $
            boundOf Nothing (Just "2.0.0") `shouldBe` LastAffected "2.0.0"

        it "reads a row with neither bound column as unbounded" $
            boundOf Nothing Nothing `shouldBe` Unbounded

        it "resolves a row that carries both bound columns as the fix" $
            -- The writer fills at most one column, so only a hand-built artifact reaches
            -- this. The decode must still yield exactly one bound.
            boundOf (Just "2.0.0") (Just "3.0.0") `shouldBe` FixedBefore "2.0.0"

        it "carries the row's identity, lower bound, and both scores through unchanged" $
            toRange ("GHSA-decode", Just "1.0.0", Just "2.0.0", Nothing, Just 5.9, Just 0.5)
                `shouldBe` AdvisoryRange "GHSA-decode" (Just 5.9) (Just "1.0.0") (FixedBefore "2.0.0") (Just 0.5)

-- Every path this process holds an open descriptor to, read from Linux's /proc
-- table. It is empty elsewhere, which degrades the leak assertion to the throw alone.
openFdTargets :: IO [FilePath]
openFdTargets =
    ( do
        fds <- listDirectory "/proc/self/fd"
        catMaybes
            <$> forM
                fds
                (\fd -> (Just <$> getSymbolicLinkTarget ("/proc/self/fd" </> fd)) `catchAny` const (pure Nothing))
    )
        `catchAny` const (pure [])

-- A rejection assertion that also releases the resource if acceptance
-- unexpectedly succeeded, so a failing test never leaks the connection.
rejectionShouldBe :: CveDbRejected -> Either CveDbRejected CveDb -> IO ()
rejectionShouldBe expected = \case
    Left rejection -> rejection `shouldBe` expected
    Right db -> do
        cveDbClose db
        fail ("expected rejection " <> show expected <> " but the artifact was accepted")
