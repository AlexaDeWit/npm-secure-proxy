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
    withSyncTasks,
    dredgerServerConfig,
    dredgerReady,
    latchedStep,
) where

import Data.Map.Strict qualified as Map
import Data.Time (getCurrentTime)
import Katip (LogEnv, Severity (ErrorS, InfoS, WarningS), SimpleLogPayload, runKatipContextT)
import UnliftIO.Async (link, mapConcurrently_, withAsync)
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
    SweepAudit (SweepAudit, auditError, auditInfo, auditWarn),
    SweepMount (smEcosystem, smStore),
    SweepPacing (swpCyclePause, swpShape),
    SweepPorts (SweepPorts, sweepAdvisoryEtag, sweepAudit, sweepDelay, sweepMetrics, sweepNow, sweepReport),
    SweepReport,
    SweepShape (SweepCandidates, SweepEverything),
    latches,
    renderCycleHalt,
 )
import Ecluse.Core.Supervision (secondsToMicros, superviseLoop, transientPolicy)
import Ecluse.Cve.Sync (
    CveSyncHandle (csEnv),
    backgroundLoopBackoff,
    cveSyncReady,
    cveSyncScheduleFor,
    cveSyncTasks,
 )
import Ecluse.Dredger.Plan (
    DredgerOptions (doMode, doRepetition),
    SweepMode (SweepDeletes, SweepRehearses),
    SweepRepetition (SweepContinuously, SweepOnce),
    advisoryPollMicros,
    advisoryWaitAttempts,
    haltDetail,
    rehearsedStore,
    sweepPacingFor,
    sweepReportFor,
    waitsForAdvisories,
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

{- | What a running Dredger keeps between cycles: the halt that latched it, which only the cap
sets, and the halt a one-shot run ended on, which becomes that invocation's exit status.
-}
data SweepStatus = SweepStatus
    { stLatched :: IORef (Maybe CycleHalt)
    , stFinal :: IORef (Maybe CycleHalt)
    }

newSweepStatus :: IO SweepStatus
newSweepStatus = SweepStatus <$> newIORef Nothing <*> newIORef Nothing

{- | Run the Dredger. Under @--once@ the sweep returns and the race ends with it, carrying the halt
that cycle raised, which is what makes the role scriptable.
-}
runDredger :: BootEnv -> DredgerOptions -> PrunerWiring -> IO (Maybe Text)
runDredger bootEnv opts pruner = do
    metrics <- newMetrics telemetry
    -- The instruments exist now, so installing them makes the credential providers' and the
    -- effectful rules' deferred reporters live for the rest of the run.
    installMetrics (pwDeferredMetrics pruner) metrics
    status <- newSweepStatus
    traverse_ (logBlastRadius logEnv opts pacing) mounts
    moduleLog logEnv dredgerModule InfoS ("Dredger starting up, health probes on port " <> show (scPort (cfg status)))
    raceServerAgainstLoop
        (runWarp (cfg status) probeOnlyApplication)
        (withSyncTasks (syncTasks metrics) (sweepTask logEnv opts pacing (portsOver metrics) syncReady status mounts))
    fmap haltDetail <$> readIORef (stFinal status)
  where
    logEnv = beLogEnv bootEnv
    telemetry = beTelemetry bootEnv
    appConfig = configApp (beConfig bootEnv)
    pacing = sweepPacingFor appConfig
    -- A dry run holds a store that cannot delete, so the loop never asks which run it is in.
    mounts = case doMode opts of
        SweepDeletes -> pwMounts pruner
        SweepRehearses -> [mount{smStore = rehearsedStore (smStore mount)} | mount <- pwMounts pruner]
    syncReady = cveSyncReady (pwCveSync pruner)
    cfg status = dredgerServerConfig appConfig (dredgerReady syncReady (readIORef (stLatched status)))
    syncTasks metrics = cveSyncTasks logEnv metrics telemetry (cveSyncScheduleFor appConfig) (pwCveSync pruner)
    portsOver metrics = sweepPortsFor logEnv metrics (sweepReportFor (doMode opts)) (pwCveSync pruner)

{- | The Dredger's health surface: the shared @server.port@, and a readiness the advisory sync
opens and a latched halt closes for good. A latch never fails liveness, so nothing restarts it.
-}
dredgerServerConfig :: AppConfig -> IO Bool -> ServerConfig
dredgerServerConfig appConfig checkReady = (probeServerConfig appConfig){scCheckReady = checkReady}

{- | Ready once the advisory sync has landed, and never again after a halt latched. Liveness stays
untouched, because a restart would begin sweeping the generation that latched it.
-}
dredgerReady :: IO Bool -> IO (Maybe CycleHalt) -> IO Bool
dredgerReady checkReady readLatched = (&&) <$> checkReady <*> (isNothing <$> readLatched)

{- Run the sweep on the invocation's repetition. A cycle is one supervised step, so a fault that
escapes a store handle's typed contract backs off and the next cycle runs. -}
sweepTask :: LogEnv -> DredgerOptions -> SweepPacing -> SweepPorts -> IO Bool -> SweepStatus -> [SweepMount] -> IO ()
sweepTask logEnv opts pacing ports checkReady status mounts = case doRepetition opts of
    SweepOnce -> awaitAdvisories >> onceCycle
    SweepContinuously ->
        void . runKatipContextT logEnv (mempty :: SimpleLogPayload) "dredger" $ do
            liftIO awaitAdvisories
            superviseLoop (transientPolicy "dredger-sweep" backgroundLoopBackoff) (liftIO step)
  where
    -- Only a one-shot run reports its cycle's halt as the process ending. A cycling Dredger stops
    -- by being asked to, whatever its last cycle did, so a supervisor does not restart it.
    onceCycle = do
        halt <- outcomeHalt <$> sweepCycle pacing ports mounts
        writeIORef (stFinal status) halt
        when (any latches halt) (writeIORef (stLatched status) halt)

    step = latchedStep pacing ports mounts (stLatched status)

    {- Give the first advisory sync a bounded chance to land before the first cycle decides
    anything, where a rule reads the database at all. Past the bound the cycle runs regardless. -}
    awaitAdvisories = when (waitsForAdvisories mounts) (poll (advisoryWaitAttempts pacing))

    poll remaining
        | remaining <= (0 :: Int) = pass
        | otherwise = checkReady >>= bool (threadDelay advisoryPollMicros >> poll (remaining - 1)) pass

{- | Run the sweep with the advisory sync tasks beside it. The sweep alone decides when the run
ends, and a task that faults still brings the run down with it.
-}
withSyncTasks :: [IO ()] -> IO a -> IO a
withSyncTasks tasks act = withAsync (mapConcurrently_ id tasks) (\syncs -> link syncs >> act)

{- | One step of the cycling Dredger: run a cycle, or report the halt that latched instead, then
wait the cycle pause. A latched Dredger touches no store and keeps reporting until it is restarted.
-}
latchedStep :: SweepPacing -> SweepPorts -> [SweepMount] -> IORef (Maybe CycleHalt) -> IO ()
latchedStep pacing ports mounts latched = do
    readIORef latched >>= maybe runCycle (reportLatched ports)
    sweepDelay ports (swpCyclePause pacing)
  where
    runCycle = do
        halt <- outcomeHalt <$> sweepCycle pacing ports mounts
        when (any latches halt) (writeIORef latched halt)

reportLatched :: SweepPorts -> CycleHalt -> IO ()
reportLatched ports halt =
    auditError (sweepAudit ports) ("the mirror sweep is halted and runs no cycle: " <> renderCycleHalt halt)

{- The effects behind the sweep's ports: the process clock, the advisory slots the sync tasks
fill, the delay, the instruments, and the process log stream. -}
sweepPortsFor :: LogEnv -> Metrics -> SweepReport -> Map Ecosystem CveSyncHandle -> SweepPorts
sweepPortsFor logEnv metrics report cveSync =
    SweepPorts
        { sweepNow = getCurrentTime
        , sweepAdvisoryEtag = \eco ->
            maybe (pure Nothing) (currentAdvisoryEtag . syncSlot . csEnv) (Map.lookup eco cveSync)
        , sweepDelay = threadDelay . secondsToMicros
        , sweepMetrics = dredgerMetricsPortOf metrics
        , sweepAudit =
            SweepAudit
                { auditInfo = moduleLog logEnv dredgerModule InfoS
                , auditWarn = moduleLog logEnv dredgerModule WarningS
                , auditError = moduleLog logEnv dredgerModule ErrorS
                }
        , sweepReport = report
        }

{- One boot line per store, putting the Dredger's blast radius on record: which backend holds it,
whether a deleted version can come back, what this run does, and whether a walk over it resumes. -}
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
