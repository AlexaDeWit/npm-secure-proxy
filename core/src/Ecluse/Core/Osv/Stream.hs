-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

{- | Streaming ingest of the osv.dev export archive Pilot compiles @osv.db@ from. The feed
aggregates many upstream databases, so one poisoned record can ride in with every transport
header honest, and the bounds here are per entry: a drop is counted in 'IngestStats' and the
rest of the archive keeps flowing. 'ilMaxAdvisoryBytes' applies before the bytes are retained
and before the JSON decodes, so an inflation bomb never reaches the decoder whole, and the
offending entry drains to its boundary so the entries after it stay aligned. An advisory over
'ilMaxAdvisoryFanOut' ranges is anomalous, logged, and kept. The aggregate verdict is the
separate pure decision 'systemicDrop', which the compiler reads once the stream completes.
-}
module Ecluse.Core.Osv.Stream (
    streamOsvUrl,
    parseOsvStream,

    -- * Ingest bounds and drop accounting
    IngestLimits (..),
    defaultIngestLimits,
    IngestStats (..),
    OsvIngest,
    newOsvIngest,
    readIngestStats,
    resetIngestStats,
    systemicDrop,
    PilotIngestAborted (..),
) where

import Codec.Archive.Zip.Conduit.Types (ZipEntry (..))
import Codec.Archive.Zip.Conduit.UnZip (unZipStream)
import Conduit
import Data.Aeson (decodeStrict)
import Data.ByteString qualified as BS
import Katip (KatipContext, Severity (..), logFM, ls)
import Network.HTTP.Simple (getResponseBody, httpSource, parseRequest, setRequestCheckStatus)
import OpenTelemetry.Trace.Core (SpanKind (Internal), TracerProvider, addAttribute)

import Ecluse.Core.Osv.Advisory (ExtractedOsv, OsvAdvisory, extractFromAdvisory, osvId)
import Ecluse.Core.Osv.Epss (EpssScores)
import Ecluse.Core.Security.Authority (authorityLabel)
import Ecluse.Core.Telemetry.Span (closeOptionalSpan, openOptionalSpan)

{- | The tunable per-advisory ingest bounds. Generous by design, because Pilot trusts
osv.dev in normal operation. They only backstop a pathological or tampered payload, and
must never trip on a real, if large, advisory.
-}
data IngestLimits = IngestLimits
    { ilMaxAdvisoryBytes :: !Int
    {- ^ Largest decompressed advisory JSON, in bytes, the ingest accepts from one
    zip entry. It drops a larger one. Bounds memory and, transitively, decode cost.
    -}
    , ilMaxAdvisoryFanOut :: !Int
    {- ^ Number of extracted ranges one advisory may expand into before the ingest
    flags it as anomalous. Log-only: the ingest still keeps the advisory.
    -}
    }
    deriving stock (Eq, Show)

{- | Sane defaults for 'IngestLimits': an 8 MiB per-advisory ceiling and a 256-range
fan-out flag. A real advisory is kilobytes and expands into a small multiple of its
affected packages, so both defaults leave generous headroom.
-}
defaultIngestLimits :: IngestLimits
defaultIngestLimits =
    IngestLimits
        { ilMaxAdvisoryBytes = 8 * 1024 * 1024
        , ilMaxAdvisoryFanOut = 256
        }

{- | The running tally of one ingest pass. Pilot reads it once the stream completes to
decide whether the artifact is trustworthy enough to publish ('systemicDrop').
-}
data IngestStats = IngestStats
    { statAccepted :: !Int
    -- ^ Advisory entries that decoded successfully.
    , statDroppedOversize :: !Int
    -- ^ Entries dropped for breaching 'ilMaxAdvisoryBytes'.
    , statDroppedMalformed :: !Int
    -- ^ Entries dropped because their JSON did not decode.
    }
    deriving stock (Eq, Show)

emptyIngestStats :: IngestStats
emptyIngestStats = IngestStats 0 0 0

-- The mutable drop tally for one ingest pass. Opaque: read it with 'readIngestStats'.
newtype IngestCounter = IngestCounter {counterRef :: IORef IngestStats}

-- | The context one ingest pass threads through the stream.
data OsvIngest = OsvIngest
    { ingestLimits :: IngestLimits
    , ingestCounter :: IngestCounter
    , ingestEpss :: EpssScores
    -- ^ The pass's EPSS table, joined onto each advisory as it is extracted.
    }

-- | A fresh ingest context with the given bounds and EPSS table, and a zeroed tally.
newOsvIngest :: (MonadIO m) => IngestLimits -> EpssScores -> m OsvIngest
newOsvIngest limits scores = do
    counter <- IngestCounter <$> newIORef emptyIngestStats
    pure (OsvIngest limits counter scores)

-- | Read the current drop tally.
readIngestStats :: (MonadIO m) => OsvIngest -> m IngestStats
readIngestStats ingest = readIORef (counterRef (ingestCounter ingest))

{- | Zero the tally. The compiler re-streams from a clean slate on each retry attempt
and zeroes the tally alongside it, so the tally reflects only the final attempt.
-}
resetIngestStats :: (MonadIO m) => OsvIngest -> m ()
resetIngestStats ingest = writeIORef (counterRef (ingestCounter ingest)) emptyIngestStats

{- | Whether a run's drop tally signals systemic corruption, a hostile or broken feed,
rather than a few poisoned records. Pilot must not publish a systemically corrupt run's
artifact.
-}
systemicDrop :: IngestStats -> Bool
systemicDrop s =
    dropped >= systemicDropFloor && dropped * 100 >= total * systemicDropPercent
  where
    dropped = statDroppedOversize s + statDroppedMalformed s
    total = dropped + statAccepted s

{- | Fewest drops that can count as systemic, so a tiny feed with a couple of bad
entries is never judged corrupt.
-}
systemicDropFloor :: Int
systemicDropFloor = 16

{- | The fraction of all entries (as a percent) the ingest must drop before a feed
counts as systemically corrupt.
-}
systemicDropPercent :: Int
systemicDropPercent = 10

{- | Raised after a compile pass whose drop tally 'systemicDrop' judged systemic. The
compiler abandons the run without publishing, so a consumer keeps its last-good artifact.
-}
newtype PilotIngestAborted = PilotIngestAborted IngestStats
    deriving stock (Show)

instance Exception PilotIngestAborted

-- | Fetch the OSV zip and stream its contents, bounded by @ingest@.
streamOsvUrl :: (MonadResource m, MonadThrow m, KatipContext m) => Maybe TracerProvider -> OsvIngest -> String -> ConduitT i ExtractedOsv m ()
streamOsvUrl mTracerProvider ingest urlStr = do
    lift $ logFM InfoS (ls ("Initializing OSV stream from " <> authorityLabel (toText urlStr)))
    bracketP
        (openOptionalSpan mTracerProvider Internal "ecluse.pilot.osv.stream")
        closeOptionalSpan
        ( \mSpan -> do
            forM_ mSpan $ \sp -> addAttribute sp "ecluse.osv.source_host" (authorityLabel (toText urlStr))
            -- 'setRequestCheckStatus' makes a non-2xx response throw at the header boundary,
            -- so the backoff wrapper ('Ecluse.Core.Osv.Retry') treats a 502 from osv.dev as
            -- retryable instead of streaming an error page into the unzip parser.
            req <- liftIO $ setRequestCheckStatus <$> parseRequest urlStr
            httpSource req (\res -> getResponseBody res .| parseOsvStream mTracerProvider ingest)
        )

-- | Parse the zip stream and emit ExtractedOsv, bounded by @ingest@.
parseOsvStream :: (MonadResource m, MonadThrow m, KatipContext m) => Maybe TracerProvider -> OsvIngest -> ConduitT ByteString ExtractedOsv m ()
parseOsvStream mTracerProvider ingest = do
    lift $ logFM InfoS (ls ("Starting OSV zip extraction and parsing pipeline" :: String))
    bracketP
        (openOptionalSpan mTracerProvider Internal "ecluse.pilot.osv.parse")
        closeOptionalSpan
        (\_ -> void (transPipe liftIO unZipStream) .| processZipEntries ingest)

processZipEntries :: (MonadThrow m, KatipContext m) => OsvIngest -> ConduitT (Either ZipEntry ByteString) ExtractedOsv m ()
processZipEntries ingest =
    await >>= \case
        Nothing -> lift $ logFM InfoS (ls ("OSV stream fully processed" :: String))
        Just (Left entry) -> do
            outcome <- collectFile (ilMaxAdvisoryBytes (ingestLimits ingest))
            handleEntry ingest entry outcome
            processZipEntries ingest
        Just (Right _) -> processZipEntries ingest

-- The outcome of accumulating one zip entry: its bytes, or a signal that it breached
-- the byte cap. The signal carries the entry's full decompressed size, for the log.
data EntryOutcome = EntryBytes !ByteString | EntryOversize !Int

-- Decide what one collected entry yields: drop-and-count an over-large or malformed
-- entry, or count and emit a decoded advisory's ranges (flagging an anomalous fan-out).
handleEntry :: (KatipContext m) => OsvIngest -> ZipEntry -> EntryOutcome -> ConduitT (Either ZipEntry ByteString) ExtractedOsv m ()
handleEntry ingest entry = \case
    EntryOversize seen -> lift $ do
        bumpOversize (ingestCounter ingest)
        logFM WarningS (ls ("Dropping oversized OSV entry " <> zipEntryNameText entry <> ": " <> show seen <> " bytes exceeds the " <> show cap <> "-byte per-advisory cap"))
    EntryBytes fileBytes -> case decodeStrict fileBytes :: Maybe OsvAdvisory of
        Nothing -> lift $ do
            bumpMalformed (ingestCounter ingest)
            logFM WarningS (ls ("Failed to parse OSV advisory JSON from entry: " <> zipEntryNameText entry))
        Just adv -> do
            lift $ bumpAccepted (ingestCounter ingest)
            let extracted = extractFromAdvisory (ingestEpss ingest) adv
            lift $ warnOnFanOut ingest adv extracted
            yieldMany extracted
  where
    cap = ilMaxAdvisoryBytes (ingestLimits ingest)

warnOnFanOut :: (KatipContext m) => OsvIngest -> OsvAdvisory -> [ExtractedOsv] -> m ()
warnOnFanOut ingest adv extracted =
    when (n > limit) $
        logFM WarningS (ls ("OSV advisory " <> osvId adv <> " expanded into " <> show n <> " ranges, exceeding the sanity threshold of " <> show limit <> "; ingesting it regardless"))
  where
    n = length extracted
    limit = ilMaxAdvisoryFanOut (ingestLimits ingest)

bumpAccepted :: (MonadIO m) => IngestCounter -> m ()
bumpAccepted (IngestCounter ref) = modifyIORef' ref (\s -> s{statAccepted = statAccepted s + 1})

bumpOversize :: (MonadIO m) => IngestCounter -> m ()
bumpOversize (IngestCounter ref) = modifyIORef' ref (\s -> s{statDroppedOversize = statDroppedOversize s + 1})

bumpMalformed :: (MonadIO m) => IngestCounter -> m ()
bumpMalformed (IngestCounter ref) = modifyIORef' ref (\s -> s{statDroppedMalformed = statDroppedMalformed s + 1})

zipEntryNameText :: ZipEntry -> Text
zipEntryNameText entry = case zipEntryName entry of
    Left txt -> txt
    Right bs -> decodeUtf8With lenientDecode bs

-- Checks @cap@ before each chunk, so memory never exceeds the cap plus one chunk. It is also the
-- only depth guard: 'decodeStrict' materialises the whole value before any post-decode check.
collectFile :: (Monad m) => Int -> ConduitT (Either ZipEntry ByteString) o m EntryOutcome
collectFile cap = go 0 []
  where
    go !seen acc =
        await >>= \case
            Nothing -> pure (EntryBytes (BS.concat (reverse acc)))
            Just (Left entry) -> do
                leftover (Left entry)
                pure (EntryBytes (BS.concat (reverse acc)))
            Just (Right bs) ->
                let seen' = seen + BS.length bs
                 in if seen' > cap
                        then drainOversize seen'
                        else go seen' (bs : acc)
    -- Not carrying acc forward frees the accumulated prefix, so the drain to the next
    -- entry boundary retains only the running size.
    drainOversize !seen =
        await >>= \case
            Nothing -> pure (EntryOversize seen)
            Just (Left entry) -> do
                leftover (Left entry)
                pure (EntryOversize seen)
            Just (Right bs) -> drainOversize (seen + BS.length bs)
