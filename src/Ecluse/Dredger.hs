-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The Dredger role's front door: the supervised mirror sweep, the advisory-sync tasks its
rules read, and the health probes an orchestrator judges the pod by. Every decision the sweep
acts on lives in "Ecluse.Core.Registry.Sweep", so what is left here is the effect behind each
of its ports, the latch a halted cycle sets, and the invocation the command line carried.
-}
module Ecluse.Dredger (
    runDredger,
    dredgerServerConfig,
) where

import Data.Map.Strict qualified as Map
import Data.Time (getCurrentTime)
import Katip (LogEnv, Severity (ErrorS, InfoS), SimpleLogPayload, runKatipContextT)
import UnliftIO.Async (mapConcurrently_, race_)
import UnliftIO.Concurrent (threadDelay)

import Ecluse.Boot (BootEnv (..), probeServerConfig)
import Ecluse.Composition.Executable (PrunerWiring (pwCveSync, pwDeferredMetrics, pwMounts))
import Ecluse.Config (AppConfig, Config (configApp))
import Ecluse.Core.Cve.Slot (currentAdvisoryEtag)
import Ecluse.Core.Ecosystem (Ecosystem, ecosystemName)
import Ecluse.Core.Registry.Maintenance (
    RefillPosture (RefillPermitted, RefillRefused),
    StoreFacts (factBackend, factRefill),
    storeCursor,
    storeFacts,
 )
import Ecluse.Core.Registry.Sweep (sweepCycle)
import Ecluse.Core.Registry.Sweep.Types (
    CycleHalt,
    CycleOutcome (outcomeHalt),
    SweepAudit (SweepAudit, auditError, auditInfo),
    SweepMode (SweepDeletes, SweepRehearses),
    SweepMount (smEcosystem, smStore),
    SweepPacing (swpCyclePause, swpShape),
    SweepPorts (SweepPorts, sweepAdvisoryEtag, sweepAudit, sweepDelay, sweepMetrics, sweepNow),
    SweepShape (SweepCandidates, SweepEverything),
    latches,
    renderCycleHalt,
    sweepDelayMicros,
 )
import Ecluse.Core.Supervision (superviseLoop, transientPolicy)
import Ecluse.Cve.Sync (
    CveSyncHandle (csEnv),
    backgroundLoopBackoff,
    cveSyncReady,
    cveSyncScheduleFor,
    cveSyncTasks,
 )
import Ecluse.Dredger.Plan (
    DredgerOptions (doMode, doRepetition),
    SweepRepetition (SweepContinuously, SweepOnce),
    haltDetail,
    sweepPacingFor,
 )
import Ecluse.Runtime.Cve.Sync (SyncEnv (syncSlot))
import Ecluse.Runtime.Log (moduleLog)
import Ecluse.Runtime.Server (
    ServerConfig (scCheckReady, scPort),
    probeOnlyApplication,
    raceServerAgainstLoop,
    runWarp,
 )
import Ecluse.Runtime.Telemetry.Instruments (Metrics, dredgerMetricsPortOf, newMetrics)
import Ecluse.Runtime.Telemetry.Reporters (installMetrics)

{- | What a running Dredger keeps between cycles: the halt that latched it, which only the
deletion cap sets and nothing clears, and the halt a one-shot run ended on, which becomes that
invocation's exit status.
-}
data SweepStatus = SweepStatus
    { stLatched :: IORef (Maybe CycleHalt)
    , stFinal :: IORef (Maybe CycleHalt)
    }

newSweepStatus :: IO SweepStatus
newSweepStatus = SweepStatus <$> newIORef Nothing <*> newIORef Nothing

{- | Run the Dredger. Under the shipped invocation the sweep and the sync tasks never return, so
the probe server's graceful return on shutdown cancels them. Under @--once@ the sweep returns and
the race ends with it, carrying the halt that cycle raised, which is what makes the role scriptable.
-}
runDredger :: BootEnv -> DredgerOptions -> PrunerWiring -> IO (Maybe Text)
runDredger bootEnv opts pruner = do
    metrics <- newMetrics telemetry
    -- The instruments exist now, so installing them makes the credential providers' and the
    -- effectful rules' deferred reporters live for the rest of the run.
    installMetrics (pwDeferredMetrics pruner) metrics
    status <- newSweepStatus
    traverse_ (logBlastRadius logEnv opts pacing) (pwMounts pruner)
    moduleLog logEnv dredgerModule InfoS ("Dredger starting up, health probes on port " <> show (scPort (cfg status)))
    raceServerAgainstLoop
        (runWarp (cfg status) probeOnlyApplication)
        (race_ (sweepTask logEnv opts pacing (portsOver metrics) status (pwMounts pruner)) (syncTasks metrics))
    fmap haltDetail <$> readIORef (stFinal status)
  where
    logEnv = beLogEnv bootEnv
    telemetry = beTelemetry bootEnv
    appConfig = configApp (beConfig bootEnv)
    pacing = sweepPacingFor appConfig
    cfg status = dredgerServerConfig appConfig (dredgerReady (pwCveSync pruner) status)
    syncTasks metrics =
        mapConcurrently_ id (cveSyncTasks logEnv metrics telemetry (cveSyncScheduleFor appConfig) (pwCveSync pruner))
    portsOver metrics = sweepPortsFor logEnv metrics (pwCveSync pruner)

{- | The Dredger's health surface: no mount, the shared @server.port@, and a readiness that the
advisory sync opens and a latched halt closes for good. A latch never fails liveness, because an
orchestrator restart would start sweeping the same poisoned generation again.
-}
dredgerServerConfig :: AppConfig -> IO Bool -> ServerConfig
dredgerServerConfig appConfig checkReady = (probeServerConfig appConfig){scCheckReady = checkReady}

-- Ready once the advisory sync has landed, and never again after a halt latched.
dredgerReady :: Map Ecosystem CveSyncHandle -> SweepStatus -> IO Bool
dredgerReady cveSync status = (&&) <$> cveSyncReady cveSync <*> (isNothing <$> readIORef (stLatched status))

{- Run the sweep on the invocation's repetition. A cycle is one supervised step, so a fault that
escapes a store handle's typed contract backs off and the next cycle runs, rather than ending the
role. A single cycle runs unsupervised: its fault is the command's own non-zero exit. -}
sweepTask :: LogEnv -> DredgerOptions -> SweepPacing -> SweepPorts -> SweepStatus -> [SweepMount] -> IO ()
sweepTask logEnv opts pacing ports status mounts = case doRepetition opts of
    SweepOnce -> oneCycle
    SweepContinuously ->
        void . runKatipContextT logEnv (mempty :: SimpleLogPayload) "dredger" $
            superviseLoop (transientPolicy "dredger-sweep" backgroundLoopBackoff) (liftIO step)
  where
    oneCycle = do
        halt <- outcomeHalt <$> sweepCycle (doMode opts) pacing ports mounts
        writeIORef (stFinal status) halt
        when (any latches halt) (writeIORef (stLatched status) halt)

    {- A latched halt runs no further cycle and touches no store. It repeats its own line at each
    cycle interval instead, so a halted Dredger keeps reporting until an operator restarts it. -}
    step = do
        readIORef (stLatched status) >>= maybe oneCycle (reportLatched ports)
        sweepDelay ports (swpCyclePause pacing)

reportLatched :: SweepPorts -> CycleHalt -> IO ()
reportLatched ports halt =
    auditError (sweepAudit ports) ("the mirror sweep is halted and runs no cycle: " <> renderCycleHalt halt)

{- The effects behind the sweep's ports: the process clock, the advisory slots the sync tasks
fill, the delay, the instruments, and the process log stream. -}
sweepPortsFor :: LogEnv -> Metrics -> Map Ecosystem CveSyncHandle -> SweepPorts
sweepPortsFor logEnv metrics cveSync =
    SweepPorts
        { sweepNow = getCurrentTime
        , sweepAdvisoryEtag = \eco ->
            maybe (pure Nothing) (currentAdvisoryEtag . syncSlot . csEnv) (Map.lookup eco cveSync)
        , sweepDelay = threadDelay . sweepDelayMicros
        , sweepMetrics = dredgerMetricsPortOf metrics
        , sweepAudit =
            SweepAudit
                { auditInfo = moduleLog logEnv dredgerModule InfoS
                , auditError = moduleLog logEnv dredgerModule ErrorS
                }
        }

{- One boot line per store, putting the Dredger's blast radius on record before it deletes
anything: which backend holds it, whether a deleted version can come back, what this run does,
and whether a full walk over it resumes after a restart. -}
logBlastRadius :: LogEnv -> DredgerOptions -> SweepPacing -> SweepMount -> IO ()
logBlastRadius logEnv opts pacing mount =
    moduleLog logEnv dredgerModule InfoS $
        "sweeping the "
            <> ecosystemName (smEcosystem mount)
            <> " mirror store on "
            <> factBackend facts
            <> ", "
            <> refill
            <> ", "
            <> disposition
            <> resumption
  where
    facts = storeFacts (smStore mount)
    refill = case factRefill facts of
        RefillPermitted -> "which accepts a re-publication of a version it deleted"
        RefillRefused -> "which refuses a re-publication, so a delete retires the version for good"
    disposition = case doMode opts of
        SweepDeletes -> "deleting what a named decisive deny condemns"
        SweepRehearses -> "rehearsing only: this run deletes nothing"
    resumption = case (swpShape pacing, storeCursor (smStore mount)) of
        (SweepCandidates, _) -> ""
        (SweepEverything, Just _) -> "; the full walk resumes from this store's own marker"
        (SweepEverything, Nothing) -> "; this store keeps no marker, so the full walk restarts after a restart"

dredgerModule :: Text
dredgerModule = "Ecluse.Dredger"
