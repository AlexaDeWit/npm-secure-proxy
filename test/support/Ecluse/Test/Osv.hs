-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT
{-# LANGUAGE UndecidableInstances #-}

{- | The shared OSV advisory fixture corpus, the artifacts derived from it, and the
monad the derivation runs in.

The committed JSON advisories under @test\/fixtures\/osv\/@ are the single source of
truth for advisory-shaped test data, so a fixture can never drift from the artifact
contract ("Ecluse.Core.Osv.Schema"). 'CorpusV2' is 'CorpusV1' plus an advisory for a
package V1 leaves clean, so a V1-to-V2 shadow swap flips an observable rule outcome.
The hostile builders model tampered artifacts the real compiler must never produce.
-}
module Ecluse.Test.Osv (
    -- * The corpus
    CorpusVersion (..),
    osvCorpusZip,
    osvZipOf,

    -- * Hostile artifacts
    mkDbWithWrongEpoch,
    mkDbWithViewShadowingRanges,
    mkDbWithMaliciousTrigger,
    mkDbWithMalformedProvenance,
    mkDbWithLaxSchema,
    mkDbWithoutEpssColumn,
    mkDbWithCorruptPage,
    mkMinimalValidDb,

    -- * The monad the OSV pipeline runs in
    OsvTestM,
    runOsvTestM,
    runOsvTestMWith,
) where

import Codec.Archive.Zip.Conduit.Zip (ZipData (..), ZipEntry (..), defaultZipOptions, zipStream)
import Conduit (MonadResource, MonadThrow, MonadUnliftIO, PrimMonad, ResourceT, runConduit, runResourceT, sinkLazy, yieldMany, (.|))
import Control.Monad.Catch (MonadCatch, MonadMask)
import Data.ByteString qualified as BS
import Data.Time (LocalTime (..), fromGregorian, midnight)
import Database.SQLite.Simple (Connection, Only (Only), Query (Query), execute, execute_, withConnection)
import Katip (Katip (..), KatipContext (..), LogEnv)
import System.FilePath (takeFileName, (</>))
import System.IO (SeekMode (AbsoluteSeek), hSeek, withBinaryFile)

import Ecluse.Core.Osv.Schema (metaTableDdl, osvSchemaEpoch, rangesTableDdl)
import Ecluse.Test.Log (newTestLogEnv)

data CorpusVersion = CorpusV1 | CorpusV2
    deriving stock (Bounded, Enum, Eq, Show)

corpusRoot :: FilePath
corpusRoot = "test/fixtures/osv"

-- Explicit lists, not a directory listing: the corpus is pinned by name, so a
-- stray file cannot silently join the fixture set.
corpusV1Files :: [FilePath]
corpusV1Files =
    [ "v1/GHSA-corpus-0001.json"
    , "v1/GHSA-corpus-0002.json"
    , "v1/GHSA-corpus-0003.json"
    , "v1/GHSA-corpus-0004.json"
    , "v1/GHSA-corpus-0005.json"
    , "v1/GHSA-corpus-0006.json"
    , "v1/malformed-deliberate.json"
    ]

corpusV2ExtraFiles :: [FilePath]
corpusV2ExtraFiles = ["v2/GHSA-corpus-1001.json"]

-- | A corpus version's advisory files, as (zip-entry name, bytes).
osvCorpusFiles :: CorpusVersion -> IO [(FilePath, LByteString)]
osvCorpusFiles v = traverse readEntry (files v)
  where
    files CorpusV1 = corpusV1Files
    files CorpusV2 = corpusV1Files <> corpusV2ExtraFiles
    readEntry rel = do
        bytes <- readFileLBS (corpusRoot </> rel)
        pure (takeFileName rel, bytes)

{- | Assemble the osv.dev-shaped export, a flat zip of advisory JSON files, for a corpus version.
The entry timestamp is fixed, so the archive is deterministic.
-}
osvCorpusZip :: CorpusVersion -> IO LByteString
osvCorpusZip v = do
    entries <- osvCorpusFiles v
    osvZipOf (map (first toText) entries)

{- | Assemble an osv.dev-shaped zip from arbitrary (entry name, bytes) pairs, so a suite can build
tampered or pathological archives the corpus does not carry. The entry timestamp is fixed, so the
archive is deterministic.
-}
osvZipOf :: [(Text, LByteString)] -> IO LByteString
osvZipOf entries =
    runConduit $
        yieldMany (map toZipEntry entries)
            .| void (zipStream defaultZipOptions)
            .| sinkLazy
  where
    toZipEntry (name, bytes) =
        ( ZipEntry
            { zipEntryName = Left name
            , zipEntryTime = corpusTimestamp
            , zipEntrySize = Nothing
            , zipEntryExternalAttributes = Nothing
            }
        , ZipDataByteString bytes
        )

corpusTimestamp :: LocalTime
corpusTimestamp = LocalTime (fromGregorian 2026 1 1) midnight

{- | A structurally plausible artifact stamped with a different table-schema epoch. A reader must
reject it on the 'osvSchemaEpoch' check alone, so the interior shape is deliberately minimal.
-}
mkDbWithWrongEpoch :: FilePath -> IO ()
mkDbWithWrongEpoch path = withConnection path $ \conn -> do
    createRangesTable conn
    setEpoch conn (osvSchemaEpoch + 1)

{- | An artifact with the right epoch whose ranges relation is a __view__. A view is schema-borne
SQL, and a hardened reader (read-only, @PRAGMA trusted_schema = OFF@) must refuse to evaluate it.
Schema conformance refuses it as not a real @STRICT@ table.
-}
mkDbWithViewShadowingRanges :: FilePath -> IO ()
mkDbWithViewShadowingRanges path = withConnection path $ \conn -> do
    execute_
        conn
        "CREATE TABLE raw_rows (\
        \  package_name TEXT,\
        \  cve_id TEXT,\
        \  introduced_version TEXT,\
        \  fixed_version TEXT,\
        \  last_affected_version TEXT,\
        \  severity REAL,\
        \  epss_score REAL\
        \)"
    execute_
        conn
        "CREATE VIEW package_vulnerability_ranges AS \
        \SELECT package_name, cve_id, introduced_version, fixed_version, last_affected_version, severity, epss_score FROM raw_rows"
    setEpoch conn osvSchemaEpoch

{- | An artifact that passes acceptance but carries a malicious trigger poised on the ranges table.
A read-only consumer must behave exactly as it would on a clean artifact, because a trigger fires
only on a write and the hardened connection refuses writes outright.
-}
mkDbWithMaliciousTrigger :: FilePath -> IO ()
mkDbWithMaliciousTrigger path = withConnection path $ \conn -> do
    createRangesTable conn
    createMetaTable conn
    execute_ conn "INSERT INTO meta (key, value) VALUES ('ecosystem', 'npm')"
    execute_ conn "INSERT INTO package_vulnerability_ranges VALUES ('trigger-pkg', 'GHSA-trigger', '0', '1.0.0', NULL, 7.5, 0.5)"
    execute_
        conn
        "CREATE TRIGGER malicious AFTER INSERT ON package_vulnerability_ranges \
        \BEGIN DELETE FROM package_vulnerability_ranges; END"
    setEpoch conn osvSchemaEpoch

{- | An artifact forged to look conformant whose stored @meta@ values violate the declaration. The
builder authors @meta@ __lax__ so the hostile BLOB row can exist, then rewrites the stored DDL to
the canonical @STRICT@ text under @PRAGMA writable_schema@. Only the @PRAGMA quick_check@ integrity
walk catches the BLOB, and the reader must refuse it as a rejection value, never a thrown error.
-}
mkDbWithMalformedProvenance :: FilePath -> IO ()
mkDbWithMalformedProvenance path = withConnection path $ \conn -> do
    createRangesTable conn
    execute_ conn "CREATE TABLE meta (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL)"
    execute_ conn "INSERT INTO meta (key, value) VALUES ('ecosystem', 'npm')"
    execute_ conn "INSERT INTO meta (key, value) VALUES ('zz-opaque', X'DEADBEEF')"
    execute_ conn "PRAGMA writable_schema = ON"
    execute conn "UPDATE sqlite_schema SET sql = ? WHERE type = 'table' AND name = 'meta'" (Only metaTableDdl)
    execute_ conn "PRAGMA writable_schema = OFF"
    setEpoch conn osvSchemaEpoch

{- | An artifact whose tables carry the right names and columns but without @STRICT@. The declared
types are then affinity hints, not enforced storage types, so schema conformance must refuse it as
a value.
-}
mkDbWithLaxSchema :: FilePath -> IO ()
mkDbWithLaxSchema path = withConnection path $ \conn -> do
    execute_
        conn
        "CREATE TABLE package_vulnerability_ranges (\
        \  package_name TEXT NOT NULL,\
        \  cve_id TEXT NOT NULL,\
        \  introduced_version TEXT,\
        \  fixed_version TEXT,\
        \  last_affected_version TEXT,\
        \  severity REAL,\
        \  epss_score REAL\
        \)"
    execute_ conn "CREATE TABLE meta (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL)"
    execute_ conn "INSERT INTO meta (key, value) VALUES ('ecosystem', 'npm')"
    setEpoch conn osvSchemaEpoch

{- | A right-epoch, @STRICT@, otherwise conformant artifact whose ranges table carries no
@epss_score@ column. Conformance must refuse it as a value rather than let the decode fail.
-}
mkDbWithoutEpssColumn :: FilePath -> IO ()
mkDbWithoutEpssColumn path = withConnection path $ \conn -> do
    execute_
        conn
        "CREATE TABLE package_vulnerability_ranges (\
        \  package_name TEXT NOT NULL,\
        \  cve_id TEXT NOT NULL,\
        \  introduced_version TEXT,\
        \  fixed_version TEXT,\
        \  last_affected_version TEXT,\
        \  severity REAL\
        \) STRICT"
    createMetaTable conn
    execute_ conn "INSERT INTO meta (key, value) VALUES ('ecosystem', 'npm')"
    setEpoch conn osvSchemaEpoch

{- | A valid, right-epoch database whose interior b-tree pages carry garbage on disk, modelling a
tampered or truncated download. Page 1 stays intact, so the file still opens and presents a real
@package_vulnerability_ranges@ table, and only the @PRAGMA quick_check@ walk catches it. The
builder creates the ranges table first, so its b-tree root is page 2.
-}
mkDbWithCorruptPage :: FilePath -> IO ()
mkDbWithCorruptPage path = do
    withConnection path $ \conn -> do
        createRangesTable conn
        createMetaTable conn
        execute_ conn "INSERT INTO meta (key, value) VALUES ('ecosystem', 'npm')"
        for_ [1 .. 32 :: Int] $ \i ->
            execute
                conn
                "INSERT INTO package_vulnerability_ranges VALUES (?, 'GHSA-corpus-bulk', '0', '1.0.0', NULL, NULL, NULL)"
                (Only (show i :: Text))
        setEpoch conn osvSchemaEpoch
    -- Overwrite page 2 (the ranges b-tree root, at the default 4096-byte page
    -- size) with 0xFF. Page 1's header and schema stay readable.
    withBinaryFile path ReadWriteMode $ \h -> do
        hSeek h AbsoluteSeek 4096
        BS.hPut h (BS.replicate 4096 255)

{- | A minimal artifact 'Ecluse.Core.Cve.openCveDb' accepts, carrying one advisory row whose package
name is the given tag and whose exact fixed bound is @1.0.0@. Sync and slot tests then tell
generations apart by which package answers the remediation probe. The corpus-compiled fixtures stay
the schema's conformance authority.
-}
mkMinimalValidDb :: FilePath -> Text -> IO ()
mkMinimalValidDb path pkg = withConnection path $ \conn -> do
    createRangesTable conn
    createMetaTable conn
    execute_ conn "INSERT INTO meta (key, value) VALUES ('ecosystem', 'npm')"
    execute conn "INSERT INTO meta (key, value) VALUES ('source_url', ?)" (Only pkg)
    execute conn "INSERT INTO package_vulnerability_ranges VALUES (?, 'GHSA-minimal', '0', '1.0.0', NULL, NULL, NULL)" (Only pkg)
    setEpoch conn osvSchemaEpoch

-- The canonical tables, verbatim from the schema contract, so a builder here
-- can never drift from what acceptance requires.
createRangesTable, createMetaTable :: Connection -> IO ()
createRangesTable conn = execute_ conn (Query rangesTableDdl)
createMetaTable conn = execute_ conn (Query metaTableDdl)

setEpoch :: Connection -> Int -> IO ()
setEpoch conn epoch = execute_ conn (fromString ("PRAGMA user_version = " <> show epoch))

{- | The monad the OSV ingest and compile pipelines run in: resource-scoped, with a 'Katip'
environment their log lines need.
-}
newtype OsvTestM a = OsvTestM {unOsvTestM :: ReaderT LogEnv (ResourceT IO) a}
    deriving newtype (Functor, Applicative, Monad, MonadIO, MonadResource, MonadThrow, MonadCatch, MonadMask, PrimMonad, MonadUnliftIO)

instance Katip OsvTestM where
    getLogEnv = OsvTestM ask
    localLogEnv f (OsvTestM m) = OsvTestM (local f m)

instance KatipContext OsvTestM where
    getKatipContext = pure mempty
    localKatipContext _ m = m
    getKatipNamespace = pure mempty
    localKatipNamespace _ m = m

-- | Run an 'OsvTestM' action against a scribe-free log environment.
runOsvTestM :: OsvTestM a -> IO a
runOsvTestM action = newTestLogEnv >>= \logEnv -> runOsvTestMWith logEnv action

-- | 'runOsvTestM' over a caller-supplied 'LogEnv', so a spec reads back what the ingest logged.
runOsvTestMWith :: LogEnv -> OsvTestM a -> IO a
runOsvTestMWith logEnv action = runResourceT (runReaderT (unOsvTestM action) logEnv)
