-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The advisory database's sync mechanics, and the write side of "Ecluse.Core.Cve.Slot":
detect a new @osv.db@ artifact in object storage, download it bounded, verify it, and
shadow-swap it into the read path, one task per configured mount. 'syncStep' performs
exactly one such cycle over an injected 'CveFetch', so unit tests drive it without a
network, and 'runCveSync' schedules those steps: an eager boot burst, retried with
incremental backoff and eventually allowed to fail so a broken bucket never wedges
startup, then the steady ETag poll. Until an artifact lands, the ecosystem denies by
default.
-}
module Ecluse.Runtime.Cve.Sync (
    -- * The injected transport
    CveFetch (..),
    DbEtag (..),
    OsvDbFetchFault (..),
    OsvDbCapExceeded (..),
    S3CveSource,
    newS3CveSource,
    s3CveFetchFor,
    cappedAt,

    -- * One sync cycle
    SyncEnv (..),
    SyncOutcome (..),
    syncStep,

    -- * The scheduled task
    SyncSchedule (..),
    runCveSync,
    bootBackoffDelays,
) where

import Conduit (ConduitT, await, runResourceT, yield, (.|))
import Control.Retry (retrying)
import Data.ByteString qualified as BS
import Data.Conduit.Combinators qualified as C
import Katip (KatipContext, Severity (DebugS, ErrorS, InfoS, WarningS), logFM, ls)
import Network.HTTP.Types.Status (statusCode)
import System.Directory (removeFile, renameFile)
import UnliftIO (MonadUnliftIO, withRunInIO)
import UnliftIO.Concurrent (threadDelay)
import UnliftIO.Exception (catch, catchAny, mask, onException, throwIO)

import Amazonka qualified as AWS
import Amazonka.S3 qualified as S3
import Amazonka.S3.Lens qualified as S3L
import Lens.Micro ((^.))

import Ecluse.Core.Cve (CveDb (cveDbClose, cveDbMeta), CveDbRejected, DbEtag (..), openCveDb)
import Ecluse.Core.Cve.Slot (CveSlot, swapIn)
import Ecluse.Core.Ecosystem (Ecosystem)
import Ecluse.Core.Fault (TransportFault)
import Ecluse.Core.Supervision (delayListPolicy)
import Ecluse.Core.Telemetry.Metrics (
    AdvisorySyncResult (AdvisoryFetchFailed, AdvisoryNonePublished, AdvisoryRefused, AdvisorySwapped, AdvisoryUnchanged),
 )
import Ecluse.Core.Telemetry.Record (AdvisorySyncMetricsPort (asmpSyncAttempt, asmpSyncDuration), timedSeconds)
import Ecluse.Core.Telemetry.Span (AdvisorySyncTracingPort (astpSyncAttemptSpan))
import Ecluse.Runtime.Aws.Env (AwsEndpoint)
import Ecluse.Runtime.Aws.Fault (classifyAwsTransport)
import Ecluse.Runtime.Aws.S3 (buildS3Env)

{- | The sync transport, as data: the remote artifact's current version and its bytes. Injected so
'syncStep' runs without a network. The composition root draws one from 'newS3CveSource'.
-}
data CveFetch = CveFetch
    { fetchHeadEtag :: IO (Either OsvDbFetchFault (Maybe DbEtag))
    {- ^ The remote artifact's current ETag. @Right Nothing@ when the object does not exist (not yet
    published). Every fetch failure, a transport fault included, is the 'Left' value.
    -}
    , fetchDownload :: FilePath -> IO (Either OsvDbFetchFault DbEtag)
    {- ^ Download the artifact to the given path, byte-bounded. The ETag is the download's own, so a
    publish racing the poll is recorded truthfully. A 'Left' may leave a partial file at that path.
    -}
    }

{- | Why an artifact fetch did not yield usable bytes. Every one is a value on the 'CveFetch'
channel, never an exception, and 'syncStep' folds it into its outcome.
-}
data OsvDbFetchFault
    = -- | The object exceeds the configured byte cap (carried, in bytes).
      OsvDbTooLarge Int
    | -- | The response carried no ETag, so there is nothing truthful to record.
      OsvDbNoEtag
    | -- | The transport could not deliver the object (carried, classified).
      OsvDbTransport TransportFault
    deriving stock (Eq, Show)

{- | 'cappedAt' sits in a conduit and has no value channel, so it reports an overstepped byte cap
by throwing this __confined__ exception. 's3Download' catches it and folds it into 'OsvDbTooLarge'.
-}
newtype OsvDbCapExceeded = OsvDbCapExceeded Int
    deriving stock (Eq, Show)

instance Exception OsvDbCapExceeded

-- | Everything one ecosystem's sync task operates on.
data SyncEnv = SyncEnv
    { syncFetch :: CveFetch
    -- ^ The transport for this ecosystem's object key.
    , syncEcosystem :: Ecosystem
    -- ^ The ecosystem the artifact must verify as.
    , syncDbPath :: FilePath
    -- ^ The canonical on-disk artifact path (the stable per-ecosystem name).
    , syncSlot :: CveSlot
    -- ^ The slot this task's swaps publish to.
    }

{- | What one 'syncStep' concluded. The caller ('runCveSync') logs it and decides
scheduling.
-}
data SyncOutcome
    = -- | Verification accepted a new artifact and it is now live (its ETag and provenance carried).
      SyncSwapped DbEtag [(Text, Text)]
    | -- | The remote ETag matches the last seen one, so there is nothing to do.
      SyncUnchanged
    | -- | The object does not exist in the bucket (not yet published).
      SyncAbsent
    | {- | The artifact downloaded, and verification __refused__ it. The last-good
      generation keeps serving and the sync remembers the ETag.
      -}
      SyncRejected DbEtag CveDbRejected
    | {- | The fetch itself failed (carried). The step learned nothing about the
      remote artifact, so the last seen ETag stands and the schedule retries.
      -}
      SyncFetchFaulted OsvDbFetchFault
    deriving stock (Show)

{- | One detect-download-verify-swap cycle against the last seen ETag. Total over the fetch and
over verification: a failed fetch and a refused artifact are outcomes, not exceptions.
-}
syncStep :: SyncEnv -> Maybe DbEtag -> IO SyncOutcome
syncStep env lastSeen =
    fetchHeadEtag (syncFetch env) >>= \case
        Left fault -> pure (SyncFetchFaulted fault)
        Right Nothing -> pure SyncAbsent
        Right (Just remote)
            | Just remote == lastSeen -> pure SyncUnchanged
            | otherwise -> syncNewArtifact env

-- Nothing unverified is renamed onto the name the read path opens. The 'onException' guards
-- absorb nothing: they discard the temp file when a filesystem fault escapes, then re-propagate.
syncNewArtifact :: SyncEnv -> IO SyncOutcome
syncNewArtifact env = do
    let temp = syncDbPath env <> ".tmp"
    downloaded <- fetchDownload (syncFetch env) temp `onException` discardTemp temp
    case downloaded of
        Left fault -> do
            -- A failed download may have written partial bytes to the temp path
            -- (the byte cap trips mid-stream). Discard them.
            discardTemp temp
            pure (SyncFetchFaulted fault)
        Right fetched -> do
            opened <- openCveDb (syncEcosystem env) temp `onException` discardTemp temp
            case opened of
                Left rejection -> do
                    discardTemp temp
                    pure (SyncRejected fetched rejection)
                Right db -> publishVerified env temp fetched db

publishVerified :: SyncEnv -> FilePath -> DbEtag -> CveDb -> IO SyncOutcome
publishVerified env temp fetched db = mask $ \restore -> do
    -- The verified connection follows the inode through the rename. This side still owns it,
    -- so a failure closes the connection and discards the download.
    restore (renameFile temp (syncDbPath env))
        `onException` (cveDbClose db >> discardTemp temp)
    -- 'swapIn' owns the connection from entry, so nothing wraps it: a failure while the displaced
    -- generation drains must never close the newly live database. The mask pins the handoff.
    swapIn (syncSlot env) fetched db
    pure (SyncSwapped fetched (cveDbMeta db))

-- Best-effort: the temp may already be renamed away or never created.
discardTemp :: FilePath -> IO ()
discardTemp temp = removeFile temp `catchAny` const pass

{- | The task's timing: the boot burst's backoff delays and the steady poll interval, both in
microseconds. The composition root ships 'bootBackoffDelays' and the configured poll interval.
-}
data SyncSchedule = SyncSchedule
    { schedBootBackoff :: [Int]
    -- ^ Delays before each boot-burst retry. The list's length is the budget.
    , schedPollDelay :: Int
    -- ^ The steady ETag-poll interval.
    }

{- | The shipped boot-burst backoff: an immediate first attempt, then a retry after each delay,
then the burst concedes to the steady poll. The poll interval, not this, is the operator's knob.
-}
bootBackoffDelays :: [Int]
bootBackoffDelays = [1_000_000, 2_000_000, 4_000_000, 8_000_000, 16_000_000]

{- | One ecosystem's sync task: the boot burst, then the steady poll, forever. The burst concedes
early on a refused artifact, because the same bytes cannot end differently. An empty slot denies by
default. @notifyFirstSync@ runs after every successful swap, so its consumer must be idempotent.
-}
runCveSync ::
    (MonadUnliftIO m, KatipContext m) =>
    AdvisorySyncMetricsPort ->
    AdvisorySyncTracingPort ->
    SyncEnv ->
    SyncSchedule ->
    IO () ->
    m ()
runCveSync metrics tracing env schedule notifyFirstSync = do
    seen <- burst
    poll seen
  where
    eco = show (syncEcosystem env) :: Text

    step = observedStep metrics tracing env eco notifyFirstSync

    -- 'lastSeen' is fixed at 'Nothing' because the only not-settled outcomes ('SyncAbsent',
    -- 'SyncFetchFaulted') return it untouched, so it never changes across the burst.
    burst = do
        (settled, seen') <-
            retrying
                (delayListPolicy (schedBootBackoff schedule))
                (\_ (done, _) -> pure (not done))
                (\_ -> step Nothing)
        unless settled $
            -- The readiness gate reads 'csReady', so this ecosystem denies by default.
            -- Logged at 'ErrorS' because a persistent failure here is a misconfiguration.
            logFM ErrorS (ls ("cve-sync[" <> eco <> "]: boot fetch did not acquire an advisory database within the boot budget; this ecosystem stays not-ready and denies by default until one is acquired. Continuing to poll; investigate the bucket, object, or IAM if this persists."))
        pure seen'

    poll lastSeen = do
        threadDelay (schedPollDelay schedule)
        (_, seen') <- step lastSeen
        poll seen'

{- One observed step, yielding (the burst may stop, the ETag now last seen). Residue propagates to
the task's supervision. The span closes after the two records, so it reads marginally longer.
-}
observedStep ::
    (MonadUnliftIO m, KatipContext m) =>
    AdvisorySyncMetricsPort ->
    AdvisorySyncTracingPort ->
    SyncEnv ->
    Text ->
    IO () ->
    Maybe DbEtag ->
    m (Bool, Maybe DbEtag)
observedStep metrics tracing env eco notifyFirstSync lastSeen =
    withRunInIO $ \runInIO ->
        snd <$> astpSyncAttemptSpan tracing ecosystem fst (metered (runInIO attempt))
  where
    ecosystem = syncEcosystem env

    -- Residue escaping the attempt bypasses these records. An attempt that never
    -- concluded has no result to label, and the supervision above reports it.
    metered :: IO (AdvisorySyncResult, (Bool, Maybe DbEtag)) -> IO (AdvisorySyncResult, (Bool, Maybe DbEtag))
    metered act = do
        (attempted, seconds) <- timedSeconds act
        asmpSyncAttempt metrics ecosystem (fst attempted)
        asmpSyncDuration metrics ecosystem (fst attempted) seconds
        pure attempted

    attempt =
        liftIO (syncStep env lastSeen) >>= \case
            SyncFetchFaulted fault -> do
                -- The step learned nothing about the remote artifact, so the last seen ETag and
                -- the last good database both stand and the next poll retries.
                logFM WarningS (ls ("cve-sync[" <> eco <> "]: sync fetch failed: " <> show fault))
                pure (AdvisoryFetchFailed, (False, lastSeen))
            SyncSwapped etag meta -> do
                logFM InfoS (ls ("cve-sync[" <> eco <> "]: advisory database swapped in: etag=" <> show etag <> " meta=" <> show meta))
                liftIO notifyFirstSync
                pure (AdvisorySwapped, (True, Just etag))
            SyncUnchanged -> do
                logFM DebugS (ls ("cve-sync[" <> eco <> "]: advisory database unchanged"))
                pure (AdvisoryUnchanged, (True, lastSeen))
            SyncAbsent -> do
                logFM DebugS (ls ("cve-sync[" <> eco <> "]: no advisory database published yet"))
                pure (AdvisoryNonePublished, (False, lastSeen))
            SyncRejected etag rejection -> do
                logFM ErrorS (ls ("cve-sync[" <> eco <> "]: downloaded artifact refused (keeping last good): " <> show rejection))
                -- Remember the ETag so the same refused artifact is not re-downloaded.
                -- A fixed re-publish carries a new one. Identical bytes cannot end differently.
                pure (AdvisoryRefused, (True, Just etag))

{- | An S3-backed advisory-fetch source. 'newS3CveSource' captures one @amazonka@ 'AWS.Env', so
every mount's 'CveFetch' shares one credential discovery. The composition shell never sees it.
-}
newtype S3CveSource = S3CveSource
    { s3CveFetchFor :: Text -> Text -> Int -> CveFetch
    -- ^ A 'CveFetch' against one bucket, object key, and byte cap, over the captured env.
    }

-- | Build an 'S3CveSource' over one S3 @amazonka@ env, honouring the resolved endpoint override.
newS3CveSource :: Maybe AwsEndpoint -> IO S3CveSource
newS3CveSource mEndpoint = do
    awsEnv <- buildS3Env mEndpoint
    pure (S3CveSource (s3CveFetch awsEnv))

{- | The real transport over the captured env: S3 @HEAD@ for the ETag, bounded streaming @GET@ for
the bytes. A @404@ on @HEAD@ is @Right Nothing@, and every other fault is the classified 'Left'.
-}
s3CveFetch :: AWS.Env -> Text -> Text -> Int -> CveFetch
s3CveFetch awsEnv bucket key maxBytes =
    CveFetch
        { fetchHeadEtag = s3HeadEtag awsEnv bucket key
        , fetchDownload = s3Download awsEnv bucket key maxBytes
        }

s3HeadEtag :: AWS.Env -> Text -> Text -> IO (Either OsvDbFetchFault (Maybe DbEtag))
s3HeadEtag awsEnv bucket key =
    runResourceT (AWS.sendEither awsEnv (S3.newHeadObject (S3.BucketName bucket) (S3.ObjectKey key))) <&> \case
        Right resp -> Right (dbEtag <$> resp ^. S3L.headObjectResponse_eTag)
        Left err
            | isNotFound err -> Right Nothing
            | otherwise -> Left (OsvDbTransport (classifyAwsTransport err))

s3Download :: AWS.Env -> Text -> Text -> Int -> FilePath -> IO (Either OsvDbFetchFault DbEtag)
s3Download awsEnv bucket key maxBytes dest = classified . runResourceT $ do
    resp <- AWS.send awsEnv (S3.newGetObject (S3.BucketName bucket) (S3.ObjectKey key))
    -- The declared length fails fast. The streaming cap is the enforcement: a
    -- declared length is not a guarantee.
    for_ (resp ^. S3L.getObjectResponse_contentLength) $ \len ->
        when (len > fromIntegral maxBytes) (throwIO (OsvDbCapExceeded maxBytes))
    AWS.sinkBody (resp ^. S3L.getObjectResponse_body) (cappedAt maxBytes .| C.sinkFile dest)
    pure (maybe (Left OsvDbNoEtag) (Right . dbEtag) (resp ^. S3L.getObjectResponse_eTag))
  where
    -- The adapter boundary: fold the two typed escapes into the value channel. Nothing else
    -- is caught, so a filesystem fault writing the destination propagates as residue.
    classified :: IO (Either OsvDbFetchFault DbEtag) -> IO (Either OsvDbFetchFault DbEtag)
    classified act =
        act
            `catch` (\(err :: AWS.Error) -> pure (Left (OsvDbTransport (classifyAwsTransport err))))
            `catch` (\(OsvDbCapExceeded n) -> pure (Left (OsvDbTooLarge n)))

dbEtag :: S3.ETag -> DbEtag
dbEtag (S3.ETag bytes) = DbEtag (decodeUtf8 bytes)

isNotFound :: AWS.Error -> Bool
isNotFound = \case
    AWS.ServiceError se -> statusCode (se ^. AWS.serviceError_status) == 404
    _ -> False

{- | A pass-through conduit that refuses to stream past the byte cap. A breach throws the confined
'OsvDbCapExceeded', which the adapter boundary folds into 'OsvDbTooLarge'.
-}
cappedAt :: (MonadIO m) => Int -> ConduitT ByteString ByteString m ()
cappedAt maxBytes = go 0
  where
    go seen =
        await >>= \case
            Nothing -> pass
            Just chunk -> do
                let seen' = seen + BS.length chunk
                when (seen' > maxBytes) (throwIO (OsvDbCapExceeded maxBytes))
                yield chunk
                go seen'
