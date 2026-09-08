-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT
{-# LANGUAGE OverloadedStrings #-}

{- | Compile OSV advisories and EPSS scores into the artifact
consumed by CVE sync.
-}
module Ecluse.Core.Osv.Compile (
    CompileSources (..),
    compileOsvToSqlite,
    osvToRow,
) where

import Conduit
import Control.Monad.Catch (MonadMask)
import Data.Conduit.List qualified as CL
import Data.Time (getCurrentTime)
import Data.Time.Format.ISO8601 (iso8601Show)
import Database.SQLite.Simple
import Katip (KatipContext, Severity (..), SimpleLogPayload, katipAddContext, logFM, ls, sl)
import System.Directory (createDirectoryIfMissing, removeFile)
import System.FilePath ((</>))
import System.IO.Error (catchIOError)
import UnliftIO.Exception (bracket, throwIO)

import Ecluse.Core.BuildIdentity (productVersion)
import Ecluse.Core.Osv.Advisory (ExtractedOsv (..))
import Ecluse.Core.Osv.Ecosystem (OsvEcosystem (osvEcosystemTag, osvExportDirectory, osvWireName))
import Ecluse.Core.Osv.Epss (fetchEpssScores, maxEpssFeedBytes)
import Ecluse.Core.Osv.Retry (defaultOsvRetryPolicy, withOsvRetry)
import Ecluse.Core.Osv.Schema (MetaKey (..), metaTableDdl, osvDbFileName, osvSchemaEpoch, rangesTableDdl, renderMetaKey)
import Ecluse.Core.Osv.Stream (
    IngestStats (..),
    PilotIngestAborted (..),
    defaultIngestLimits,
    newOsvIngest,
    readIngestStats,
    resetIngestStats,
    streamOsvUrl,
    systemicDrop,
 )
import Ecluse.Core.Osv.Types (UpperBound (FixedBefore, LastAffected, Unbounded))
import Ecluse.Core.Security.Authority (authorityLabel)
import Ecluse.Core.Telemetry.Metrics (
    AdvisoryCompileResult (CompileAborted, CompileCompleted),
    AdvisoryDropCause (DropMalformed, DropOversize),
 )
import Ecluse.Core.Telemetry.Record (AdvisoryCompileMetricsPort (acmpCompileAccepted, acmpCompileDropped, acmpCompileRun))
import Ecluse.Core.Telemetry.Span (withOptionalSpan)
import OpenTelemetry.Trace.Core (Span, SpanKind (Internal), SpanStatus (Error), TracerProvider, addAttribute, setStatus)

{- | The two upstreams one compile pass reads: the ecosystem's advisories, and the
exploitability scores it joins onto them.
-}
data CompileSources = CompileSources
    { csOsvExportUrl :: String
    -- ^ The ecosystem's OSV export archive ('Ecluse.Core.Osv.Advisory.osvExportUrl').
    , csEpssFeedUrl :: String
    -- ^ The EPSS daily feed, from the configured @advisories.epssFeedUrl@.
    }
    deriving stock (Eq, Show)

{- | Compile one ecosystem into @outDir@ using "Ecluse.Core.Osv.Schema".
An escaping fault leaves no completion verdict on the ecosystem's metrics port.
-}
compileOsvToSqlite :: (MonadResource m, MonadMask m, MonadUnliftIO m, KatipContext m) => AdvisoryCompileMetricsPort -> Maybe TracerProvider -> FilePath -> OsvEcosystem -> CompileSources -> m FilePath
compileOsvToSqlite metrics mTracerProvider outDir eco sources = do
    let ecosystem = osvWireName eco
        dbFile = outDir </> osvDbFileName ecosystem
    logFM InfoS (ls ("Compiling OSV data for " <> ecosystem <> " to " <> toText dbFile))

    liftIO $ createDirectoryIfMissing True outDir
    liftIO $ catchIOError (removeFile dbFile) (const $ pure ())

    withOptionalSpan mTracerProvider Internal "ecluse.pilot.osv.compile" $
        \mSpan -> do
            forM_ mSpan $ \sp -> do
                addAttribute sp "ecluse.osv.ecosystem" ecosystem
                addAttribute sp "ecluse.osv.source_host" (authorityLabel (toText (csOsvExportUrl sources)))

            -- The join needs the whole score table before the first advisory row lands, and a
            -- feed the retry budget cannot fetch fails the pass rather than shipping without.
            epss <- withOsvRetry defaultOsvRetryPolicy (fetchEpssScores maxEpssFeedBytes (csEpssFeedUrl sources))
            ingest <- newOsvIngest defaultIngestLimits (osvEcosystemTag eco) epss

            bracket (liftIO $ open dbFile) (liftIO . close) $ \conn -> do
                liftIO $ initSchema conn

                -- A failed attempt leaves committed batches. NULL bounds defeat deduplication,
                -- so each retry clears the table and tally.
                withOsvRetry defaultOsvRetryPolicy $ do
                    resetIngestStats ingest
                    liftIO $ execute_ conn "DELETE FROM package_vulnerability_ranges"
                    runConduit $
                        streamOsvUrl mTracerProvider ingest (csOsvExportUrl sources)
                            .| CL.filter ((== osvExportDirectory eco) . extEcosystem)
                            .| CL.chunksOf 2000
                            .| sinkSqlite conn

                stats <- readIngestStats ingest
                concludeCompile metrics mSpan conn ecosystem sources stats

    pure dbFile

-- A systemic drop rate must not ship as a fresh-looking artifact that silently omits
-- advisories, so this abandons the run before 'writeMeta' finalises it.
concludeCompile :: (KatipContext m) => AdvisoryCompileMetricsPort -> Maybe Span -> Connection -> Text -> CompileSources -> IngestStats -> m ()
concludeCompile metrics mSpan conn ecosystem sources stats = do
    forM_ mSpan $ \sp -> do
        addAttribute sp "ecluse.osv.accepted" (show (statAccepted stats) :: Text)
        addAttribute sp "ecluse.osv.dropped_oversize" (show (statDroppedOversize stats) :: Text)
        addAttribute sp "ecluse.osv.dropped_malformed" (show (statDroppedMalformed stats) :: Text)
        addAttribute sp "ecluse.osv.unorderable" (show (statUnorderable stats) :: Text)
    liftIO (recordTallies metrics stats)
    when (systemicDrop stats) $ do
        forM_ mSpan $ \sp -> setStatus sp (Error "systemic advisory drop rate; compile abandoned")
        liftIO (acmpCompileRun metrics CompileAborted)
        katipAddContext (dropFields ecosystem stats) $
            logFM ErrorS (ls ("Aborting OSV compile for " <> ecosystem <> ": " <> renderDrops stats))
        throwIO (PilotIngestAborted stats)

    rowCount <- liftIO $ writeMeta conn ecosystem sources
    liftIO (acmpCompileRun metrics CompileCompleted)
    forM_ mSpan $ \sp -> addAttribute sp "ecluse.osv.row_count" (show rowCount :: Text)
    katipAddContext (sl "row_count" rowCount <> dropFields ecosystem stats) $
        logFM InfoS (ls ("Compiled " <> show rowCount <> " advisory ranges for " <> ecosystem <> " (" <> renderDrops stats <> ")"))

-- An abandoned pass records its tallies too, and a pass with no drops records a zero, so
-- the drop series exists before the first drop.
recordTallies :: AdvisoryCompileMetricsPort -> IngestStats -> IO ()
recordTallies metrics stats = do
    acmpCompileAccepted metrics (statAccepted stats)
    acmpCompileDropped metrics DropOversize (statDroppedOversize stats)
    acmpCompileDropped metrics DropMalformed (statDroppedMalformed stats)

renderDrops :: IngestStats -> Text
renderDrops s =
    "accepted "
        <> show (statAccepted s)
        <> ", dropped "
        <> show (statDroppedOversize s)
        <> " oversize / "
        <> show (statDroppedMalformed s)
        <> " malformed, kept "
        <> show (statUnorderable s)
        <> " unorderable"

dropFields :: Text -> IngestStats -> SimpleLogPayload
dropFields ecosystem s =
    sl "ecosystem" ecosystem
        <> sl "accepted" (statAccepted s)
        <> sl "dropped_oversize" (statDroppedOversize s)
        <> sl "dropped_malformed" (statDroppedMalformed s)
        <> sl "unorderable" (statUnorderable s)

initSchema :: Connection -> IO ()
initSchema conn = do
    execute_ conn (Query rangesTableDdl)
    -- A unique index rather than a composite PRIMARY KEY: @STRICT@ makes primary-key
    -- columns implicitly NOT NULL, and the three bound columns are legitimately NULL.
    execute_ conn "CREATE UNIQUE INDEX uq_ranges_segment ON package_vulnerability_ranges(package_name, cve_id, introduced_version, fixed_version, last_affected_version)"
    execute_ conn "CREATE INDEX idx_package_name ON package_vulnerability_ranges(package_name)"
    execute_ conn "CREATE INDEX idx_package_fixed ON package_vulnerability_ranges(package_name, fixed_version)"
    execute_ conn (Query metaTableDdl)
    execute_ conn (fromString ("PRAGMA user_version = " <> show osvSchemaEpoch))

-- Written once, after the stream completes: the row count is only meaningful for a
-- complete artifact.
writeMeta :: Connection -> Text -> CompileSources -> IO Int
writeMeta conn ecosystem sources = do
    now <- getCurrentTime
    counted <- query_ conn "SELECT COUNT(*) FROM package_vulnerability_ranges" :: IO [Only Int]
    let rowCount = maybe 0 fromOnly (listToMaybe counted)
    executeMany
        conn
        "INSERT INTO meta (key, value) VALUES (?, ?)"
        [ (renderMetaKey MetaPilotVersion, productVersion)
        , (renderMetaKey MetaEcosystem, ecosystem)
        , (renderMetaKey MetaBuiltAt, toText (iso8601Show now))
        , (renderMetaKey MetaSourceUrl, authorityLabel (toText (csOsvExportUrl sources)))
        , (renderMetaKey MetaEpssSourceUrl, authorityLabel (toText (csEpssFeedUrl sources)))
        , (renderMetaKey MetaRowCount, show rowCount)
        ]
    pure rowCount

sinkSqlite :: (MonadIO m) => Connection -> ConduitT [ExtractedOsv] o m ()
sinkSqlite conn = awaitForever $ \batch ->
    liftIO $
        withTransaction conn $
            executeMany
                conn
                "INSERT OR IGNORE INTO package_vulnerability_ranges (package_name, cve_id, introduced_version, fixed_version, last_affected_version, severity, epss_score) VALUES (?, ?, ?, ?, ?, ?, ?)"
                (map osvToRow batch)

{- | One extracted segment as its artifact row. The upper bound spreads over the
@fixed_version@ and @last_affected_version@ columns, and fills at most one of them.
-}
osvToRow :: ExtractedOsv -> (Text, Text, Maybe Text, Maybe Text, Maybe Text, Maybe Double, Maybe Double)
osvToRow osv = (extPackage osv, extCveId osv, extIntroduced osv, fixed, lastAffected, extSeverity osv, extEpss osv)
  where
    (fixed, lastAffected) = case extUpperBound osv of
        FixedBefore f -> (Just f, Nothing)
        LastAffected la -> (Nothing, Just la)
        Unbounded -> (Nothing, Nothing)
