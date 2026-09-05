-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The boot's effectful planning phase: take the cleared 'BootPlan' and yield the
'ExecutablePlan' the booting role assembles its runtime from.

Every role plans through here, so a refusal only a live environment can settle is spent at one
gate whatever the role, and holding an 'ExecutablePlan' means nothing downstream refuses to
boot. A listener that fails to bind is a runtime fault for supervision, not a refusal.
@ecluse check-config@ makes no cloud call, so it stops at the 'BootPlan' and never reaches here.
-}
module Ecluse.Composition.Executable (
    ExecutablePlan (epBootPlan, epRoleWiring),
    RoleWiring (..),
    MirrorWiring (mwRole, mwBootWiring, mwCveSync, mwQueue, mwDeferredMetrics),
    PrunerWiring (pwMounts, pwCveSync, pwDeferredMetrics),
    BuildMirrorQueue,
    BuildCredentials,
    planExecutable,
) where

import Data.Time (getCurrentTime)
import Katip (LogEnv)
import Validation (eitherToValidation, validationToEither)

import Data.Map.Strict qualified as Map

import Ecluse.Composition (
    BootWiring,
    PublishBudget (PublishBudget, pbBodyBudget, pbMaxRequestBytes),
    ResolveAdapter,
    WiringPorts (WiringPorts, wpClock, wpReporters, wpResolveAdapter, wpRuleDeps),
    firstPartyName,
    resolveBootWiring,
 )
import Ecluse.Composition.BootError (
    BootError (AdvisorySyncUnavailable, MirrorQueueUnavailable, PilotWithoutEcosystem),
    refuseOnThrow,
 )
import Ecluse.Composition.Credential (CredentialProviders, noCredentialProviders, providerLabel)
import Ecluse.Composition.Maintenance (BuildStoreMaintenance, planStoreMaintenance)
import Ecluse.Composition.MemoryPlan (
    MemoryPlan (mpMaxRequestBytes, mpPublishTenant, mpQueueMemoryMaxDepth),
    PublishTenant (ptAggregateBytes),
 )
import Ecluse.Composition.MirrorQueue (
    MirrorQueuePlan,
    MirrorRuntimePlan (MirrorWith, NoMirroring),
 )
import Ecluse.Composition.Plan (
    BootPlan (bpLimits, bpMemoryPlan, bpMirrorRuntime, bpRole, bpS3Endpoint, bpValidated),
 )
import Ecluse.Composition.Types (
    BootRole (BootMirrorPipeline, BootStorePruner, BootWithoutPipeline),
    MirrorRole,
 )
import Ecluse.Composition.Validate (
    ValidatedPlan (vpMirrorStores, vpMounts, vpSettings),
    VettedMount (vmAdapter, vmConfig, vmEcosystem, vmMount),
 )
import Ecluse.Config (AppConfig (cfgAdvisories), Mount (mountPolicy), MountConfig (mntFirstParty), StoreTag)
import Ecluse.Core.Credential.Refresh (CredentialReporters (CredentialReporters, crBreakerReporter, crRefreshReporter))
import Ecluse.Core.Ecosystem (Ecosystem)
import Ecluse.Core.Package (PackageName)
import Ecluse.Core.Queue (MirrorQueue, noMirrorQueue)
import Ecluse.Core.Registry.Adapter (ProjectName, adapterProjectName)
import Ecluse.Core.Registry.Maintenance (StoreMaintenance)
import Ecluse.Core.Registry.Sweep.Types (SweepMount (..))
import Ecluse.Core.Rules (PreparedRule, RuleDeps, prepare)
import Ecluse.Core.Rules.Types (PrecededRule (prRule), Rule)
import Ecluse.Core.Server.Admission.Bytes (newByteAdmission)
import Ecluse.Core.Telemetry.Metrics (BreakerSource (CredentialMint, EffectfulRule))
import Ecluse.Core.Telemetry.Span (TracingPort)
import Ecluse.Cve.Sync (CveSyncHandle, cveRuleDepsFor, katipFaultReporter, planCveSync)
import Ecluse.Pilot.Plan (ExportLoopPlan, exportLoopPlan)
import Ecluse.Runtime.Telemetry.Reporters (
    DeferredMetrics,
    deferredBreakerReporter,
    deferredRefreshReporter,
    newDeferredMetrics,
 )

{- | The boot's post-gating artefact: the cleared plan, and the wiring only a live environment
could settle. 'planExecutable' is its one producer, so a role cannot assemble an unvetted one.
-}
data ExecutablePlan = ExecutablePlan
    { epBootPlan :: BootPlan
    -- ^ The config-decidable plan every decision below was planned against.
    , epRoleWiring :: RoleWiring
    -- ^ What the booting role's own arm of this phase settled.
    }

{- | What each role's arm settled. A role starts from its own arm, so wiring one role's boot
planned cannot reach another role's runtime.
-}
data RoleWiring
    = -- | @ecluse proxy@, @ecluse proxy --no-worker@ and @ecluse mirror@.
      MirrorPipelineWiring MirrorWiring
    | -- | @ecluse dredger@: the stores it sweeps, and what decides for each of them.
      StorePrunerWiring PrunerWiring
    | -- | @ecluse pilot@: the export loop the advisory settings and the vetted mounts name.
      PilotWiring ExportLoopPlan

-- | What a mirror-pipeline role's arm settled, and all "Ecluse.Service" assembles its runtime from.
data MirrorWiring = MirrorWiring
    { mwRole :: MirrorRole
    -- ^ The pipeline half the plan vetted, so the severities it cleared and the runtime agree.
    , mwBootWiring :: BootWiring
    -- ^ The mounts the front door serves, and the publish targets the worker writes through.
    , mwCveSync :: Map Ecosystem CveSyncHandle
    -- ^ One advisory-sync handle per mount ecosystem, empty where no advisory store is configured.
    , mwQueue :: MirrorQueue
    -- ^ The mirror-queue backend the plan selected, inert where no mount mirrors.
    , mwDeferredMetrics :: DeferredMetrics
    {- ^ The metric handle the credential providers and the rule breakers already record through.
    The assembly makes those recordings live once the instruments exist.
    -}
    }

{- | What the store pruner's arm settled: one sweepable mount per cleared store, and the advisory
sync the sweep's rules read. "Ecluse.Dredger" assembles the whole role from it.
-}
data PrunerWiring = PrunerWiring
    { pwMounts :: [SweepMount]
    {- ^ One entry per store the pass cleared, carrying its maintenance handle, its own prepared
    rule set, and the shared first-party predicate its belt reads.
    -}
    , pwCveSync :: Map Ecosystem CveSyncHandle
    -- ^ One advisory-sync handle per mount ecosystem, empty where no advisory store is configured.
    , pwDeferredMetrics :: DeferredMetrics
    {- ^ The metric handle the credential providers and the sweep's rule breakers already record
    through. The role makes those recordings live once the instruments exist.
    -}
    }

{- | How a boot builds the selected mirror-queue backend. Injected, as the adapter resolver is,
so a spec can drive this phase's refusals without reaching a cloud.
-}
type BuildMirrorQueue = LogEnv -> Int -> MirrorQueuePlan -> IO MirrorQueue

{- | How a boot builds the mirror-write credential providers. Injected, as the queue and store
builders are, so a spec drives this phase without minting against a cloud.
-}
type BuildCredentials = (StoreTag -> CredentialReporters) -> [Mount] -> IO (Either [BootError] CredentialProviders)

{- | Plan the runtime the cleared plan's role starts, or report every refusal only a live
environment can settle. Each role has one arm here, and a refusal is spent once for all of them.
-}
planExecutable ::
    LogEnv ->
    TracingPort ->
    ResolveAdapter ->
    BuildMirrorQueue ->
    BuildCredentials ->
    BuildStoreMaintenance ->
    BootPlan ->
    IO (Either [BootError] ExecutablePlan)
planExecutable logEnv tracing resolveAdapter buildQueue buildCredentials buildStore bootPlan = case bpRole bootPlan of
    BootMirrorPipeline role ->
        fmap (executablePlan . MirrorPipelineWiring)
            <$> planMirrorWiring logEnv resolveAdapter buildQueue role bootPlan
    BootStorePruner ->
        fmap (executablePlan . StorePrunerWiring)
            <$> planPrunerWiring logEnv tracing buildCredentials buildStore bootPlan
    BootWithoutPipeline -> pure (executablePlan . PilotWiring <$> pilotExportPlan (bpValidated bootPlan))
  where
    executablePlan wiring = ExecutablePlan{epBootPlan = bootPlan, epRoleWiring = wiring}

{- The deleting role's arm: the advisory sync its rules read, the credential its stores answer to,
and a handle per store. All three refusable steps accumulate, so one launch reports every problem. -}
planPrunerWiring :: LogEnv -> TracingPort -> BuildCredentials -> BuildStoreMaintenance -> BootPlan -> IO (Either [BootError] PrunerWiring)
planPrunerWiring logEnv tracing buildCredentials buildStore bootPlan = do
    deferredMetrics <- newDeferredMetrics
    cveSync <- planAdvisorySync logEnv bootPlan
    credentials <- buildCredentials (credentialReportersOver deferredMetrics) prunerMounts
    stores <-
        planStoreMaintenance
            buildStore
            tracing
            (fromRight noCredentialProviders credentials)
            (bpLimits bootPlan)
            (vpMirrorStores validated)
    -- A refused sync leaves the rules abstaining, so the policies below still prepare and still
    -- report. The accumulation then discards them along with the sync.
    let ruleDepsFor =
            cveRuleDepsFor
                (fromRight mempty cveSync)
                (deferredBreakerReporter deferredMetrics EffectfulRule)
                (katipFaultReporter logEnv)
    policies <- Map.fromList <$> traverse (sweepPolicyFor ruleDepsFor) (vpMounts validated)
    pure . validationToEither $
        prunerWiringFrom deferredMetrics policies
            <$> eitherToValidation cveSync
            <* eitherToValidation credentials
            <*> eitherToValidation stores
  where
    validated = bpValidated bootPlan
    prunerMounts = map vmMount (vpMounts validated)

{- What decides for one mount's store: its own rule set, prepared as the serve path prepares its,
and the shared first-party predicate. A mount declaring no namespaces owns none. -}
sweepPolicyFor :: (Ecosystem -> RuleDeps) -> VettedMount -> IO (Ecosystem, SweepPolicy)
sweepPolicyFor ruleDepsFor vetted = do
    prepared <- prepare deps configured
    pure (eco, SweepPolicy{spRules = prepared, spConfigured = map prRule configured, spDeps = deps, spProject = project, spFirstParty = firstParty})
  where
    eco = vmEcosystem vetted
    deps = ruleDepsFor eco
    configured = mountPolicy (vmMount vetted)
    project = adapterProjectName (vmAdapter vetted)
    firstParty = maybe (const False) firstPartyName (mntFirstParty (vmConfig vetted))

{- One mount's half of a sweepable store. The configured rules ride beside the prepared ones,
because a prepared rule no longer carries the identity a deny names. -}
data SweepPolicy = SweepPolicy
    { spRules :: [PreparedRule]
    , spConfigured :: [Rule]
    , spDeps :: RuleDeps
    , spProject :: ProjectName
    , spFirstParty :: PackageName -> Bool
    }

{- The artefact the arm yields. The join is on the ecosystem, and only a mount declaring a mirror
target reaches the store map, so a store with no policy cannot arise. -}
prunerWiringFrom ::
    DeferredMetrics ->
    Map Ecosystem SweepPolicy ->
    Map Ecosystem CveSyncHandle ->
    Map Ecosystem StoreMaintenance ->
    PrunerWiring
prunerWiringFrom deferredMetrics policies cveSync stores =
    PrunerWiring
        { pwMounts =
            [ SweepMount
                { smEcosystem = eco
                , smStore = store
                , smRules = spRules policy
                , smConfigured = spConfigured policy
                , smRuleDeps = spDeps policy
                , smProjectName = spProject policy
                , smFirstParty = spFirstParty policy
                }
            | (eco, store) <- Map.toAscList stores
            , Just policy <- [Map.lookup eco policies]
            ]
        , pwCveSync = cveSync
        , pwDeferredMetrics = deferredMetrics
        }

{- The Pilot publishes one artifact per vetted mount, so a configured store with no mount leaves
it nothing to compile, and a role with no runtime behaviour refuses rather than idling. -}
pilotExportPlan :: ValidatedPlan -> Either [BootError] ExportLoopPlan
pilotExportPlan validated = maybeToRight [PilotWithoutEcosystem] (exportLoopPlan advisories mounted)
  where
    advisories = cfgAdvisories (vpSettings validated)
    mounted = map vmEcosystem (vpMounts validated)

{- The mirror pipeline's arm: the advisory sync, the queue backend, and the mount wiring. The three
refusable steps accumulate, so one launch reports every one rather than the earliest alone. -}
planMirrorWiring :: LogEnv -> ResolveAdapter -> BuildMirrorQueue -> MirrorRole -> BootPlan -> IO (Either [BootError] MirrorWiring)
planMirrorWiring logEnv resolveAdapter buildQueue role bootPlan = do
    -- The metric instruments do not exist until the assembly builds the telemetry substrate. The
    -- credential providers minted below record through reporters 'installMetrics' makes live.
    deferredMetrics <- newDeferredMetrics
    cveSync <- planAdvisorySync logEnv bootPlan
    publishBudget <- planPublishBudget memoryPlan
    queue <- planMirrorQueue buildQueue logEnv (mpQueueMemoryMaxDepth memoryPlan) (bpMirrorRuntime bootPlan)
    -- A refused sync leaves the rules abstaining, so the wiring below still builds and still
    -- reports what it refuses. The accumulation then discards it along with the sync.
    let ruleDeps =
            cveRuleDepsFor
                (fromRight mempty cveSync)
                (deferredBreakerReporter deferredMetrics EffectfulRule)
                (katipFaultReporter logEnv)
        ports =
            WiringPorts
                { wpReporters = credentialReportersOver deferredMetrics
                , wpResolveAdapter = resolveAdapter
                , wpClock = getCurrentTime
                , wpRuleDeps = ruleDeps
                }
    -- The wiring reads the rule deps and the publish budget above, so it follows them rather than
    -- accumulating with them.
    wiring <- resolveBootWiring ports (bpLimits bootPlan) publishBudget validated
    pure . validationToEither $
        mirrorWiringFrom role deferredMetrics
            <$> eitherToValidation cveSync
            <*> eitherToValidation queue
            <*> eitherToValidation wiring
  where
    validated = bpValidated bootPlan
    memoryPlan = bpMemoryPlan bootPlan

-- The artefact the arm yields once its refusable steps cleared.
mirrorWiringFrom :: MirrorRole -> DeferredMetrics -> Map Ecosystem CveSyncHandle -> MirrorQueue -> BootWiring -> MirrorWiring
mirrorWiringFrom role deferredMetrics cveSync queue wiring =
    MirrorWiring
        { mwRole = role
        , mwBootWiring = wiring
        , mwCveSync = cveSync
        , mwQueue = queue
        , mwDeferredMetrics = deferredMetrics
        }

{- It creates the local data directory and discovers the advisory store's credentials, so an
environment that can do neither refuses here rather than at first sync. -}
planAdvisorySync :: LogEnv -> BootPlan -> IO (Either [BootError] (Map Ecosystem CveSyncHandle))
planAdvisorySync logEnv bootPlan =
    refuseOnThrow AdvisorySyncUnavailable $
        planCveSync logEnv (bpS3Endpoint bootPlan) (vpSettings validated) (map vmEcosystem (vpMounts validated))
  where
    validated = bpValidated bootPlan

{- Build the selected queue backend. It dials the provider to read the queue's redrive policy, so
an environment that cannot reach it refuses here rather than failing the running worker. -}
planMirrorQueue :: BuildMirrorQueue -> LogEnv -> Int -> MirrorRuntimePlan -> IO (Either [BootError] MirrorQueue)
planMirrorQueue buildQueue logEnv memoryDepth = \case
    -- Under NoMirroring nothing enqueues, so the inert queue is unreachable.
    NoMirroring -> pure (Right noMirrorQueue)
    MirrorWith queuePlan -> refuseOnThrow MirrorQueueUnavailable (buildQueue logEnv memoryDepth queuePlan)

{- One process-wide byte aggregate serves every publishing mount. It exists exactly when a
publication target is configured, the same predicate the plan's tenant derives from. -}
planPublishBudget :: MemoryPlan -> IO (Maybe PublishBudget)
planPublishBudget memoryPlan =
    forM (mpPublishTenant memoryPlan) $ \tenant -> do
        bodyBudget <- newByteAdmission (ptAggregateBytes tenant)
        pure PublishBudget{pbBodyBudget = bodyBudget, pbMaxRequestBytes = mpMaxRequestBytes memoryPlan}

-- Where a store's mirror-write credential provider records its mint breaker and refresh outcomes.
credentialReportersOver :: DeferredMetrics -> StoreTag -> CredentialReporters
credentialReportersOver deferredMetrics tag =
    CredentialReporters
        { crBreakerReporter = deferredBreakerReporter deferredMetrics CredentialMint
        , crRefreshReporter = deferredRefreshReporter deferredMetrics (providerLabel tag)
        }
