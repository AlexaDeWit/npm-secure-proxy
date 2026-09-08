-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT
{-# LANGUAGE UndecidableInstances #-}

{- | Shared OSV fixtures derived from @test\/fixtures\/osv\/@ and hostile artifact builders.
'CorpusV2' adds an advisory for a package absent from 'CorpusV1', making swaps observable.
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
    mkMinimalValidDbWithMeta,

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
import Database.SQLite.Simple (Connection, Only (Only), Query (Query), execute, executeMany, execute_, withConnection)
import Katip (Katip (..), KatipContext (..), LogEnv)
import System.FilePath (takeFileName, (</>))
import System.IO (SeekMode (AbsoluteSeek), hSeek, withBinaryFile)

import Ecluse.Core.Osv.Schema (metaTableDdl, osvSchemaEpoch, rangesTableDdl)
import Ecluse.Test.Log (newTestLogEnv)

-- | A committed advisory corpus generation.
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

-- | Build a zip from arbitrary entries with a fixed timestamp for deterministic hostile fixtures.
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

-- | A right-epoch artifact whose ranges relation is a view, which schema conformance must refuse.
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

-- | An accepted artifact with a malicious trigger that the read-only consumer must never activate.
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

-- | Forged strict metadata containing a BLOB. Only the integrity check catches the storage mismatch.
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

-- | An artifact with matching columns but lax tables, which schema conformance must refuse.
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

-- | An artifact with intact schema and a corrupt ranges b-tree, caught only by the integrity check.
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

-- | An accepted artifact with one package fixed at @1.0.0@, so probes distinguish generations.
mkMinimalValidDb :: FilePath -> Text -> IO ()
mkMinimalValidDb path pkg = mkMinimalValidDbWithMeta path pkg [("source_url", pkg)]

-- | A minimal accepted artifact with caller-supplied provenance, apart from its fixed npm ecosystem.
mkMinimalValidDbWithMeta :: FilePath -> Text -> [(Text, Text)] -> IO ()
mkMinimalValidDbWithMeta path pkg meta = withConnection path $ \conn -> do
    createRangesTable conn
    createMetaTable conn
    execute_ conn "INSERT INTO meta (key, value) VALUES ('ecosystem', 'npm')"
    executeMany conn "INSERT INTO meta (key, value) VALUES (?, ?)" meta
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
