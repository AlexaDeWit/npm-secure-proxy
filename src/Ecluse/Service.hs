-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The assembly every mirror-pipeline role runs over: the composition-root 'Env' and the
services derived from it.

'withServiceRuntime' builds from the 'ExecutablePlan' the boot already gated, so nothing here
refuses to boot. "Ecluse.Proxy" adds the front door over it and "Ecluse.Mirror" runs the worker
alone, so the dedicated worker is the same worker the serve path embeds, not a second copy.
-}
module Ecluse.Service (
    -- * The role-shared runtime
    ServiceRuntime (..),
    withServiceRuntime,
    workerLiveness,

    -- * The mirror worker
    runWorker,

    -- * npm front door
    mountBindingFor,
) where

import Data.Map.Strict qualified as Map
import GHC.Conc (setNumCapabilities)
import Katip (LogEnv, SimpleLogPayload, katipAddNamespace, runKatipContextT)
import Network.HTTP.Client.TLS (tlsManagerSettings)

import Ecluse.Boot (BootEnv (beLogEnv, beTelemetry), logBootWarning, logRuleBootOrder)
import Ecluse.Composition (BootWiring (bwBindings, bwPublishTargets))
import Ecluse.Composition.Executable (
    ExecutablePlan (epBootPlan),
    MirrorWiring (mwBootWiring, mwCveSync, mwDeferredMetrics, mwQueue, mwRole),
 )
import Ecluse.Composition.MemoryPlan (
    MemoryPlan (mpAdmissionCapacity, mpMirrorArtifactTenant, mpShedCapabilities),
    MirrorArtifactTenant (matMaxBytes),
    mirrorArtifactBytesCap,
 )
import Ecluse.Composition.MirrorQueue (MirrorRuntimePlan (MirrorWith, NoMirroring))
import Ecluse.Composition.MirrorRole (enqueuesJobs, spawnsWorker)
import Ecluse.Composition.Plan (
    BootPlan (bpCacheConfig, bpMemoryPlan, bpMirrorRuntime, bpPrivateConnections, bpPublicConnections, bpValidated),
 )
import Ecluse.Composition.Sizing (newPooledManager)
import Ecluse.Composition.Sizing qualified as Composition
import Ecluse.Composition.Types (MirrorRole)
import Ecluse.Composition.Validate (ValidatedPlan (vpSettings))
import Ecluse.Composition.Worker (workerPoliciesFor)
import Ecluse.Config (AppConfig)
import Ecluse.Core.Credential.Refresh (CredentialError (Unconfigured))
import Ecluse.Core.Cve.Slot (generationInstalledAt)
import Ecluse.Core.Ecosystem (Ecosystem, prefixFor)
import Ecluse.Core.Queue (MirrorQueue, newEnqueueBuffer, reportWorthy)
import Ecluse.Core.Registry.Adapter (
    RegistryAdapter,
    adapterEcosystem,
    adapterFor,
    adapterServe,
    serveCredential,
    serveRouter,
 )
import Ecluse.Core.Server.Admission (newServeAdmission)
import Ecluse.Core.Server.Cache (newMetadataCache)
import Ecluse.Core.Server.Context (PackumentDeps, PublishDeps)
import Ecluse.Core.Supervision (
    FaultDisposition (Permanent, Transient),
    SupervisionPolicy (SupervisionPolicy, spBackoff, spClassify, spLabel),
    superviseLoop,
    transientPolicy,
 )
import Ecluse.Core.Worker (Liveness, WorkerHeartbeat, WorkerPolicies, alwaysLive, heartbeatLivenessNow, runWorkerM, workerLoop)
import Ecluse.Cve.Sync (CveSyncHandle (csEnv), backgroundLoopBackoff, cveSyncReady, cveSyncScheduleFor, cveSyncTasks)
import Ecluse.Runtime.Cve.Sync (SyncEnv (syncSlot))
import Ecluse.Runtime.Env (Env, envDdContext, envLogEnv, envMetrics, envTelemetry, newWorkerHeartbeat, withEnvWithAdmission, workerRuntimeOf)
import Ecluse.Runtime.Server (MountBinding (..))
import Ecluse.Runtime.Telemetry.Correlation (ddPayloadNow)
import Ecluse.Runtime.Telemetry.Instruments (registerAdvisoryDatabaseAge)
import Ecluse.Runtime.Telemetry.Reporters (
    DeferredMetrics,
    deferredMirrorEnqueueFailure,
    installMetrics,
 )
import Ecluse.Runtime.Telemetry.Tracing (instrumentDataPlaneManagerSettings)

{- | Everything a role needs to start its own tasks, built once by 'withServiceRuntime'. The
background tasks arrive already wrapped in their supervision policy.
-}
data ServiceRuntime = ServiceRuntime
    { svcRole :: MirrorRole
    {- ^ The mirror-pipeline half this runtime serves, taken from the boot plan so the role's
    entry point selects its behaviour from what the plan carries.
    -}
    , svcRunsWorker :: Bool
    {- ^ Whether this process runs the mirror worker ('spawnsWorker'), the one fact both the
    spawn decision and the @\/livez@ arm below are derived from.
    -}
    , svcEnv :: Env
    , svcAppConfig :: AppConfig
    , svcBindings :: [MountBinding]
    -- ^ The resolved mounts. A worker-only role builds them for their rules, and serves none.
    , svcWorkerPolicies :: WorkerPolicies
    , svcMirrorDrain :: Maybe (IO ())
    {- ^ The supervised enqueue-buffer drain, present exactly when this role produces mirror
    jobs into a configured queue.
    -}
    , svcSyncTasks :: [IO ()]
    -- ^ One supervised advisory-sync task per configured ecosystem.
    , svcCheckReady :: IO Bool
    , svcCheckLive :: IO Liveness
    }

{- | Assemble the role's runtime and run @action@ within it. The plan it takes is post-gating, so
this only builds and allocates: nothing here can refuse the boot.
-}
withServiceRuntime :: BootEnv -> ExecutablePlan -> MirrorWiring -> (ServiceRuntime -> IO ()) -> IO ()
withServiceRuntime bootEnv plan mirror action = do
    let logEnv = beLogEnv bootEnv
        telemetry = beTelemetry bootEnv
        -- Every decision below comes from the plan the boot resolved and logged, and
        -- "Ecluse.Composition.Executable" then cleared. This assembly only applies it.
        bootPlan = epBootPlan plan
        role = mwRole mirror
        appConfig = vpSettings (bpValidated bootPlan)
        mirrorRuntime = bpMirrorRuntime bootPlan
        memoryPlan = bpMemoryPlan bootPlan
        deferredMetrics = mwDeferredMetrics mirror
        cveSyncPlan = mwCveSync mirror
        bindings = bwBindings (mwBootWiring mirror)

    -- Apply a shed capability count in-process before the parallel machinery spins up. Past the
    -- gate, so a refused boot never reshapes the process it is about to abandon.
    whenJust (mpShedCapabilities memoryPlan) setNumCapabilities
    serveAdmission <- newServeAdmission (mpAdmissionCapacity memoryPlan)
    heartbeat <- newWorkerHeartbeat
    let runsWorkerHere = spawnsWorker role mirrorRuntime
    -- Log each mount's resolved rule boot order so an operator sees at start-up exactly
    -- how their policy will resolve (highest precedence first, then name).
    logRuleBootOrder logEnv bindings
    (queue, mirrorDrain) <- mirrorHandOff role logEnv deferredMetrics mirrorRuntime (mwQueue mirror)
    metadataCache <- newMetadataCache (bpCacheConfig bootPlan)

    -- The two managers stay split: public reads are anonymous and private reads forward the
    -- client's credential. Https-only egress closes the SSRF and resolve-to-internal class.
    publicSettings <- instrumentDataPlaneManagerSettings telemetry tlsManagerSettings
    privateSettings <- instrumentDataPlaneManagerSettings telemetry tlsManagerSettings
    manager <- newPooledManager (bpPublicConnections bootPlan) publicSettings
    privateManager <- newPooledManager (bpPrivateConnections bootPlan) privateSettings
    withEnvWithAdmission serveAdmission queue manager privateManager metadataCache logEnv telemetry heartbeat $ \builtEnv -> do
        -- The instruments exist now, so installing them makes the credential provider's deferred
        -- reporters live for the rest of the run.
        installMetrics deferredMetrics (envMetrics builtEnv)
        registerAdvisoryAges builtEnv cveSyncPlan
        -- 'MirrorWith' always carries the artifact tenant.
        let workerArtifactMaxBytes = maybe mirrorArtifactBytesCap matMaxBytes (mpMirrorArtifactTenant memoryPlan)
        action
            ServiceRuntime
                { svcRole = role
                , svcRunsWorker = runsWorkerHere
                , svcEnv = builtEnv
                , svcAppConfig = appConfig
                , svcBindings = bindings
                , svcWorkerPolicies = workerPoliciesFor builtEnv bindings (bwPublishTargets (mwBootWiring mirror)) workerArtifactMaxBytes
                , svcMirrorDrain = superviseDrain builtEnv <$> mirrorDrain
                , svcSyncTasks =
                    cveSyncTasks
                        (envLogEnv builtEnv)
                        (envMetrics builtEnv)
                        (envTelemetry builtEnv)
                        (cveSyncScheduleFor appConfig)
                        cveSyncPlan
                , svcCheckReady = cveSyncReady cveSyncPlan
                , svcCheckLive = workerLiveness runsWorkerHere heartbeat
                }

{- | The @\/livez@ arm a process answers from, given whether it runs the worker
('spawnsWorker'): the consume-loop heartbeat where it does, the listener alone where it does not.
-}
workerLiveness :: Bool -> WorkerHeartbeat -> IO Liveness
workerLiveness runningWorker heartbeat
    | runningWorker = heartbeatLivenessNow heartbeat
    | otherwise = pure alwaysLive

{- Build the role's view of the queue the boot already built, and, for a producing role, its
drain. A worker-only role takes the backend directly, because nothing in that process enqueues. -}
mirrorHandOff :: MirrorRole -> LogEnv -> DeferredMetrics -> MirrorRuntimePlan -> MirrorQueue -> IO (MirrorQueue, Maybe (IO ()))
mirrorHandOff role logEnv deferredMetrics mirrorRuntime backendQueue = case mirrorRuntime of
    -- Under NoMirroring the inert queue is unreachable.
    NoMirroring -> pure (backendQueue, Nothing)
    MirrorWith _
        | not (enqueuesJobs role) -> pure (backendQueue, Nothing)
        | otherwise -> do
            -- The buffered hand-off keeps the serve path off the backend's enqueue latency.
            (queue, drainEnqueueBuffer) <-
                bufferedMirrorHandOff (logBootWarning logEnv) (deferredMirrorEnqueueFailure deferredMetrics) backendQueue
            pure (queue, Just drainEnqueueBuffer)

{- The buffered hand-off in front of the mirror queue's backend. A dropped or undelivered
job is safe, because the serve path re-enqueues it on the next demand for its artifact. -}
bufferedMirrorHandOff :: (Text -> IO ()) -> IO () -> MirrorQueue -> IO (MirrorQueue, IO ())
bufferedMirrorHandOff warn countEnqueueFailure =
    newEnqueueBuffer
        Composition.mirrorEnqueueBufferDepth
        ( \drops -> do
            when (enqueueReportWorthy drops) $
                warn ("mirror enqueue buffer full: " <> show drops <> " job(s) dropped so far; each is re-enqueued on the next demand for its artifact")
            countEnqueueFailure
        )
        ( \failures detail -> do
            when (enqueueReportWorthy failures) $
                warn ("mirror enqueue delivery failed (" <> show failures <> " so far): " <> detail)
            countEnqueueFailure
        )

{- True for the first event, then every 'Composition.mirrorEnqueueReportInterval'-th. Only
the log line is rate-limited, and the metric alongside counts every event. -}
enqueueReportWorthy :: Int -> Bool
enqueueReportWorthy n = reportWorthy n Composition.mirrorEnqueueReportInterval

{- Attach each ecosystem's advisory-database age to the observable gauge, once at boot. The
callback reads the slot, which outlives the sync tasks, so the age survives a task restart. -}
registerAdvisoryAges :: Env -> Map.Map Ecosystem CveSyncHandle -> IO ()
registerAdvisoryAges builtEnv plan =
    for_ (Map.toList plan) $ \(eco, handle) ->
        registerAdvisoryDatabaseAge (envMetrics builtEnv) eco (generationInstalledAt (syncSlot (csEnv handle)))

{- The enqueue-buffer drain under the shared supervision combinator. Pacing lives in the
buffer's own loop, so this wrapper only stops residue ending mirror-job delivery. -}
superviseDrain :: Env -> IO () -> IO ()
superviseDrain builtEnv drain =
    void . runKatipContextT (envLogEnv builtEnv) (mempty :: SimpleLogPayload) "mirror-enqueue-drain" $
        superviseLoop (transientPolicy "mirror-enqueue-drain" backgroundLoopBackoff) (liftIO drain)

{- | Run the supervised mirror worker over the composition-root 'Env' and the per-ecosystem
bundles. The loop re-runs current policy against a job before it mirrors.
-}
runWorker :: WorkerPolicies -> Env -> IO ()
runWorker policies env = do
    dd <- ddPayloadNow (envDdContext env)
    void (runWorkerM (envLogEnv env) dd (workerRuntimeOf policies env) (katipAddNamespace "worker" (workerLoop workerSupervision)))

{- The worker's supervision policy. An unconfigured credential leaf is a wiring fault no
retry can fix, so it takes the process down for a restart against corrected configuration. -}
workerSupervision :: SupervisionPolicy
workerSupervision =
    SupervisionPolicy
        { spLabel = "worker"
        , spClassify = classify
        , spBackoff = backgroundLoopBackoff
        }
  where
    classify fault
        | Just (Unconfigured _) <- fromException fault = Permanent
        | otherwise = Transient

{- | Resolve an 'Ecosystem' to its complete 'MountBinding', or 'Nothing' when that ecosystem
has no registered adapter. The path prefix derives from the ecosystem ('prefixFor'), never config.
-}
mountBindingFor :: Ecosystem -> PackumentDeps -> Maybe PublishDeps -> Maybe MountBinding
mountBindingFor eco packumentDeps publishDeps =
    adapterFor eco <&> \adapter -> mountOf adapter packumentDeps publishDeps

{- The mount projection of one adapter: its serve router under the derived prefix.
'Nothing' publish deps leave @PUT \/{pkg}@ answering @405@: no publication target. -}
mountOf :: RegistryAdapter -> PackumentDeps -> Maybe PublishDeps -> MountBinding
mountOf adapter packumentDeps publishDeps =
    MountBinding
        { bindingPrefix = prefixFor (adapterEcosystem adapter)
        , bindingRouter = serveRouter (adapterServe adapter)
        , bindingCredential = serveCredential (adapterServe adapter)
        , bindingPackumentDeps = packumentDeps
        , bindingPublishDeps = publishDeps
        }
