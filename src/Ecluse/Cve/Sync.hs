-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The advisory-sync plan: one ecosystem's sync wiring ('CveSyncHandle') and the
config-driven plan that builds it ('planCveSync'). It also holds the projections the
composition root reads off that plan: the per-ecosystem rule capabilities, the
first-sync readiness gate, and the sync schedule. "Ecluse.Service" builds the plan at boot
and hands every role one supervised sync task per handle.
-}
module Ecluse.Cve.Sync (
    CveSyncHandle (..),
    planCveSync,
    sweepStaleTemps,
    sweepStep,
    cveRuleDepsFor,
    katipFaultReporter,
    cveSyncReady,
    cveSyncScheduleFor,
    cveSyncTasks,
    backgroundLoopBackoff,
) where

import Data.Map.Strict qualified as Map
import Katip (LogEnv, Severity (WarningS), SimpleLogPayload, runKatipContextT, sl)
import System.Directory (createDirectoryIfMissing, listDirectory, removeFile)
import System.FilePath (isExtensionOf, (</>))
import System.IO.Error (IOError, catchIOError)

import Ecluse.Config (
    AdvisoriesSettings (advDataDir, advPollInterval, advUrl),
    AdvisoryStoreUrl,
    AppConfig (cfgAdvisories, cfgLimits),
    LimitsSettings (limMaxAdvisoryDatabaseBytes),
    advisoryObjectKey,
    advisoryStoreBucket,
 )
import Ecluse.Core.Breaker (BreakerReporter)
import Ecluse.Core.Cve.Slot (currentAdvisoryEtag, newCveSlot, withSlotLookup)
import Ecluse.Core.Ecosystem (Ecosystem, ecosystemName)
import Ecluse.Core.Osv.Schema (osvDbFileName)
import Ecluse.Core.Rules (FaultReporter (..), RuleDeps (..))
import Ecluse.Core.Supervision (
    BackoffSchedule (BackoffSchedule, bsBaseMicros, bsCapMicros),
    secondsToMicros,
    superviseLoop,
    transientPolicy,
 )
import Ecluse.Runtime.Aws.Env (AwsEndpoint)
import Ecluse.Runtime.Cve.Sync (S3CveSource, SyncEnv (..), SyncSchedule (SyncSchedule, schedBootBackoff, schedPollDelay), bootBackoffDelays, newS3CveSource, runCveSync, s3CveFetchFor)
import Ecluse.Runtime.Log (logLine, moduleField)
import Ecluse.Runtime.Telemetry (Telemetry)
import Ecluse.Runtime.Telemetry.Instruments (Metrics, advisorySyncMetricsPortOf)
import Ecluse.Runtime.Telemetry.Tracing (advisorySyncTracingPortOf)

{- | The rules' boot-bound capabilities for one mount ecosystem. A mount's rules read only their own
ecosystem's advisory database, and abstain when the sync plan carries no slot for it.
-}
cveRuleDepsFor :: Map.Map Ecosystem CveSyncHandle -> BreakerReporter -> FaultReporter -> Ecosystem -> RuleDeps
cveRuleDepsFor plan reporter faultReporter eco =
    RuleDeps
        { rdWithCveLookup = maybe (\use -> use Nothing) (withSlotLookup . syncSlot . csEnv) (Map.lookup eco plan)
        , rdCurrentAdvisoryEtag = maybe (pure Nothing) (currentAdvisoryEtag . syncSlot . csEnv) (Map.lookup eco plan)
        , rdBreakerReporter = reporter
        , rdFaultReporter = faultReporter
        }

{- | A 'FaultReporter' logging an exhausted rule's fault detail, so a fault stays diagnosable
rather than a bare @Unavailable@. The detail is bounded, carries no secret, and reaches no client.
-}
katipFaultReporter :: LogEnv -> FaultReporter
katipFaultReporter logEnv =
    FaultReporter $ \ruleName detail ->
        logLine
            logEnv
            (moduleField "Ecluse.Core.Rules" <> sl "rule" ruleName <> sl "fault" detail)
            WarningS
            "effectful rule evaluation faulted"

{- | The readiness gate over the sync plan: ready once every ecosystem completes its first sync.
Each flag flips one way, so readiness never flaps. An empty plan is vacuously ready.
-}
cveSyncReady :: Map.Map Ecosystem CveSyncHandle -> IO Bool
cveSyncReady plan = allM (readTVarIO . csReady) (Map.elems plan)

{- | The sync tasks' timing: the shipped boot burst over the configured poll interval. The microsecond
conversion cannot wrap: the config decoder bounds the interval to @[1, maxBound div 1_000_000]@ seconds.
-}
cveSyncScheduleFor :: AppConfig -> SyncSchedule
cveSyncScheduleFor env =
    SyncSchedule
        { schedBootBackoff = bootBackoffDelays
        , schedPollDelay = secondsToMicros (advPollInterval (cfgAdvisories env))
        }

{- | One supervised sync task per configured ecosystem, each flipping its own one-way readiness
flag once its first sync lands. Every role that evaluates rules runs these.
-}
cveSyncTasks :: LogEnv -> Metrics -> Telemetry -> SyncSchedule -> Map.Map Ecosystem CveSyncHandle -> [IO ()]
cveSyncTasks logEnv metrics telemetry schedule plan =
    [ void . runKatipContextT logEnv (mempty :: SimpleLogPayload) "cve-sync" $
        superviseLoop
            (transientPolicy ("cve-sync[" <> show (syncEcosystem (csEnv handle)) <> "]") backgroundLoopBackoff)
            (runCveSync syncMetrics syncTracing (csEnv handle) schedule (atomically (writeTVar (csReady handle) True)))
    | handle <- Map.elems plan
    ]
  where
    syncMetrics = advisorySyncMetricsPortOf metrics
    syncTracing = advisorySyncTracingPortOf telemetry

{- | The pace every shell background loop retries a transient fault at: one second after the
first failure, doubling to a thirty-second ceiling.
-}
backgroundLoopBackoff :: BackoffSchedule
backgroundLoopBackoff = BackoffSchedule{bsBaseMicros = 1_000_000, bsCapMicros = 30_000_000}

-- | One configured ecosystem's advisory-sync wiring.
data CveSyncHandle = CveSyncHandle
    { csReady :: TVar Bool
    -- ^ The one-way first-sync readiness flag.
    , csEnv :: SyncEnv
    {- ^ The sync task's environment. Its 'syncSlot' is the slot this ecosystem's mount
    rules borrow through.
    -}
    }

{- | Build the advisory-sync plan, one 'CveSyncHandle' per vetted mount ecosystem, or nothing with
no store. A mount the build does not ship awaits an artifact that never comes, so it stays unready.
-}
planCveSync :: LogEnv -> Maybe AwsEndpoint -> AppConfig -> [Ecosystem] -> IO (Map.Map Ecosystem CveSyncHandle)
planCveSync logEnv s3Endpoint appCfg ecosystems = case advUrl (cfgAdvisories appCfg) of
    Nothing -> pure Map.empty
    Just store -> do
        let dataDir = advDataDir (cfgAdvisories appCfg)
        createDirectoryIfMissing True dataDir
        sweepStaleTemps logEnv dataDir
        cveSource <- newS3CveSource s3Endpoint
        Map.fromList <$> traverse (cveSyncHandleFor appCfg cveSource store) ecosystems

-- 'cveSource' captures the S3 environment once, so every ecosystem's transport shares one
-- credential discovery. The store addresses the remote object, the local copy its bare file name.
cveSyncHandleFor :: AppConfig -> S3CveSource -> AdvisoryStoreUrl -> Ecosystem -> IO (Ecosystem, CveSyncHandle)
cveSyncHandleFor appCfg cveSource store eco = do
    slot <- newCveSlot
    ready <- newTVarIO False
    let fileName = osvDbFileName (ecosystemName eco)
        maxBytes = limMaxAdvisoryDatabaseBytes (cfgLimits appCfg)
        syncEnv =
            SyncEnv
                { syncFetch =
                    s3CveFetchFor
                        cveSource
                        (advisoryStoreBucket store)
                        (advisoryObjectKey store fileName)
                        maxBytes
                , syncEcosystem = eco
                , syncDbPath = advDataDir (cfgAdvisories appCfg) </> fileName
                , syncSlot = slot
                }
    pure (eco, CveSyncHandle{csReady = ready, csEnv = syncEnv})

{- | Sweep the in-progress downloads an interrupted run left behind, which an @emptyDir@ keeps
across a container restart. The sweep is best effort, per 'sweepStep'.
-}
sweepStaleTemps :: LogEnv -> FilePath -> IO ()
sweepStaleTemps logEnv dataDir =
    sweepStep logEnv dataDir $ do
        entries <- listDirectory dataDir
        traverse_ (removeStaleTemp logEnv dataDir) (filter (isExtensionOf "tmp") entries)

-- Remove one stray @.tmp@ entry, tolerating a per-entry filesystem fault so a single
-- unremovable file does not abort the rest of the sweep.
removeStaleTemp :: LogEnv -> FilePath -> FilePath -> IO ()
removeStaleTemp logEnv dataDir entry =
    let path = dataDir </> entry in sweepStep logEnv path (removeFile path)

{- | Run one best-effort step of the stale-temp sweep. It logs and swallows an 'IOError', so a
read-only or mispermissioned data dir does not stop the boot, and any other exception propagates.
-}
sweepStep :: LogEnv -> FilePath -> IO () -> IO ()
sweepStep logEnv path step = step `catchIOError` logSweepFailure logEnv path

-- The logged OS error detail is the operator's own filesystem, not untrusted input.
logSweepFailure :: LogEnv -> FilePath -> IOError -> IO ()
logSweepFailure logEnv path err =
    logLine logEnv payload WarningS ("could not sweep stale advisory temp files: " <> show err)
  where
    payload = moduleField "Ecluse.Cve.Sync" <> sl "path" (toText path)
