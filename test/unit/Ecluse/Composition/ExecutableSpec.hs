-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Composition.ExecutableSpec (spec) where

import Data.Text qualified as T
import Test.Hspec
import UnliftIO.Exception (throwIO)

import Ecluse.Composition (
    BootWiring (bwBindings, bwPublishTargets),
    PublishTarget (ptEcosystem),
    ResolveAdapter,
 )
import Ecluse.Composition.BootError (
    BootError (
        AdvisorySyncUnavailable,
        CodeArtifactMintFailed,
        MirrorQueueUnavailable,
        MissingAdapter,
        PilotWithoutEcosystem,
        StoreMaintenanceUnavailable
    ),
    StoreMaintenanceReason (ClientBuildFailed),
 )
import Ecluse.Composition.Credential (noCredentialProviders)
import Ecluse.Composition.Executable (
    BuildCredentials,
    BuildMirrorQueue,
    ExecutablePlan (epBootPlan, epRoleWiring),
    MirrorWiring (mwBootWiring, mwCveSync, mwRole),
    PrunerWiring (pwMounts),
    RoleWiring (MirrorPipelineWiring, PilotWiring, StorePrunerWiring),
    planExecutable,
 )
import Ecluse.Composition.Maintenance (BuildStoreMaintenance)
import Ecluse.Composition.Plan (BootPlan (bpRole))
import Ecluse.Composition.Support (codeArtifactEnvVars, expectConfig, expectPlanFor, noCeiling, overrideEnv, staticEnvVars)
import Ecluse.Composition.Types (
    BootRole (BootMirrorPipeline, BootStorePruner, BootWithoutPipeline),
    MirrorRole (ServeAndMirror),
 )
import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.Queue (noMirrorQueue)
import Ecluse.Core.Registry.Sweep.Types (SweepMount (smEcosystem))
import Ecluse.Core.Server.Context (MountBinding (bindingPrefix))
import Ecluse.Pilot.Plan (ExportLoopPlan (ExportIdle, ExportTo))
import Ecluse.Service (mountBindingFor)
import Ecluse.Test.Log (newTestLogEnv)
import Ecluse.Test.Maintenance (FakeStore (fakeMaintenance), defaultFakeStoreConfig, newFakeStore)
import Ecluse.Test.Port (passthroughTracingPort)

{- | Tests the boot's effectful planning phase. Every role plans through it, and every refusal a
live environment can settle is spent there, so a yielded plan is one nothing downstream rejects.
-}
spec :: Spec
spec = describe "planExecutable" $ do
    it "yields the mounts and the publish targets a mirror-pipeline role assembles from" $ do
        plan <- expectExecutable (BootMirrorPipeline ServeAndMirror) mountBindingFor inertQueue inertStore
        mirror <- expectMirrorWiring plan
        mwRole mirror `shouldBe` ServeAndMirror
        map bindingPrefix (bwBindings (mwBootWiring mirror)) `shouldBe` [pure "npm"]
        map ptEcosystem (bwPublishTargets (mwBootWiring mirror)) `shouldBe` [Npm]
        -- No advisory store is configured, so the map is empty and readiness is ungated.
        null (mwCveSync mirror) `shouldBe` True

    it "refuses, and yields no plan, where a cleared mount resolves to no binding" $ do
        -- The refusal this phase raises without a cloud. The injected resolver stands in for a
        -- build shipping no adapter, which is what makes the wiring, not the pure pass, refuse.
        outcome <- planFor (BootMirrorPipeline ServeAndMirror) (\_ _ _ -> Nothing) inertQueue inertStore
        case outcome of
            Right _ -> expectationFailure "expected the planning phase to refuse"
            Left errs -> errs `shouldBe` [MissingAdapter Npm]

    it "refuses a mirror-queue backend the live environment cannot build" $ do
        -- The backend dials its provider at boot, so a throw there is a refusal at the gate and
        -- never a fault inside an assembly that claims nothing can refuse.
        outcome <- planFor (BootMirrorPipeline ServeAndMirror) mountBindingFor refusingQueue inertStore
        case outcome of
            Right _ -> expectationFailure "expected the planning phase to refuse"
            Left [MirrorQueueUnavailable detail] -> detail `shouldSatisfy` T.isInfixOf "NoCredentials"
            Left errs -> expectationFailure ("expected one queue refusal, got: " <> show errs)

    it "reports the queue refusal and the wiring refusal from one run" $ do
        -- The two refusable steps accumulate, so an operator fixes both before the next boot
        -- rather than meeting the second one only once the first is gone.
        outcome <- planFor (BootMirrorPipeline ServeAndMirror) (\_ _ _ -> Nothing) refusingQueue inertStore
        case outcome of
            Right _ -> expectationFailure "expected the planning phase to refuse"
            Left [MirrorQueueUnavailable _, MissingAdapter Npm] -> pass
            Left errs -> expectationFailure ("expected both refusals in one list, got: " <> show errs)

    it "refuses an advisory sync the live environment cannot prepare" $ do
        -- The sync creates its data directory and discovers the advisory store's credentials, and
        -- it runs a step ahead of the queue build, so a throw here would exit 1 past this gate.
        outcome <- planWith unwritableAdvisoryEnv (BootMirrorPipeline ServeAndMirror) mountBindingFor inertQueue inertStore
        case outcome of
            Right _ -> expectationFailure "expected the planning phase to refuse"
            Left [AdvisorySyncUnavailable detail] -> detail `shouldSatisfy` T.isInfixOf advisoryDataDir
            Left errs -> expectationFailure ("expected one advisory-sync refusal, got: " <> show errs)

    it "reports the advisory refusal beside the queue and wiring refusals from one run" $ do
        -- The advisory sync accumulates with the other two rather than short-circuiting them,
        -- which is what keeps one launch reporting every problem an operator must fix.
        outcome <- planWith unwritableAdvisoryEnv (BootMirrorPipeline ServeAndMirror) (\_ _ _ -> Nothing) refusingQueue inertStore
        case outcome of
            Right _ -> expectationFailure "expected the planning phase to refuse"
            Left [AdvisorySyncUnavailable _, MirrorQueueUnavailable _, MissingAdapter Npm] -> pass
            Left errs -> expectationFailure ("expected all three refusals in one list, got: " <> show errs)

    it "plans the store pruner a sweepable mount per cleared store" $ do
        -- The build carries a sweep, so the arm yields the plan rather than refusing: one mount
        -- per store the pass cleared, carrying what decides for it.
        pruner <- expectExecutableWith codeArtifactEnvVars BootStorePruner (\_ _ _ -> Nothing) refusingQueue inertStore
        plannedArm (epRoleWiring pruner) `shouldBe` "store pruner"
        case epRoleWiring pruner of
            StorePrunerWiring wiring -> map smEcosystem (pwMounts wiring) `shouldBe` [Npm]
            other -> expectationFailure ("expected the store pruner arm, got the " <> toString (plannedArm other) <> " arm")

    it "reports a store maintenance client the live environment cannot build" $ do
        -- The client discovers an AWS identity when it is built, so an environment with none
        -- refuses here rather than failing the Dredger's first call against the store.
        outcome <- planWith codeArtifactEnvVars BootStorePruner (\_ _ _ -> Nothing) refusingQueue refusingStore
        case outcome of
            Right _ -> expectationFailure "expected the planning phase to refuse"
            Left [StoreMaintenanceUnavailable Npm (ClientBuildFailed detail)] ->
                detail `shouldSatisfy` T.isInfixOf "NoCredentials"
            Left errs -> expectationFailure ("expected the handle refusal, got: " <> show errs)

    it "reports a mirror-write mint the live environment refuses" $ do
        -- The Dredger reads and deletes through the mirror write's own credential, so it mints
        -- at boot exactly as the proxy does, and an identity that cannot answer refuses here.
        outcome <- planUnder codeArtifactEnvVars BootStorePruner (\_ _ _ -> Nothing) refusingQueue refusingCredentials inertStore
        case outcome of
            Right _ -> expectationFailure "expected the planning phase to refuse"
            Left errs -> errs `shouldBe` [CodeArtifactMintFailed "no identity answered"]

    it "reports a refused mint and a store client it cannot build together" $ do
        -- All three refusable steps accumulate, so one launch names every problem.
        outcome <- planUnder codeArtifactEnvVars BootStorePruner (\_ _ _ -> Nothing) refusingQueue refusingCredentials refusingStore
        case outcome of
            Right _ -> expectationFailure "expected the planning phase to refuse"
            Left [CodeArtifactMintFailed _, StoreMaintenanceUnavailable Npm (ClientBuildFailed _)] -> pass
            Left errs -> expectationFailure ("expected the mint and the handle refusal, got: " <> show errs)

    it "plans the pilot through the same phase, on its own arm" $ do
        -- Nothing here needs a live environment, so ports that refuse outright leave the role
        -- clearing exactly as working ones do. The gate still stands ahead of it, which is
        -- where the Pilot's own refusal is spent.
        pilot <- expectExecutable BootWithoutPipeline (\_ _ _ -> Nothing) refusingQueue refusingStore
        plannedArm (epRoleWiring pilot) `shouldBe` "pilot"
        bpRole (epBootPlan pilot) `shouldBe` BootWithoutPipeline
        -- No advisory store is configured here, so the export loop idles.
        expectPilotPlan pilot >>= (`shouldBe` ExportIdle)

    it "carries the vetted mounts the pilot compiles an artifact for" $ do
        -- The same list the advisory sync reads, so the Pilot publishes to the key each
        -- ecosystem's sync polls rather than to npm's alone.
        pilot <- expectExecutableWith advisoryStoreEnv BootWithoutPipeline mountBindingFor inertQueue inertStore
        plan <- expectPilotPlan pilot
        case plan of
            ExportTo _ ecosystems -> ecosystems `shouldBe` Npm :| []
            ExportIdle -> expectationFailure "expected a configured store to turn the export loop on"

    it "refuses a pilot with an advisory store and no mount to compile for" $ do
        -- A role with no coherent runtime behaviour gets no runtime: the store is configured,
        -- so every cycle would publish nothing at all.
        outcome <- planWith unmountedAdvisoryEnv BootWithoutPipeline mountBindingFor inertQueue inertStore
        case outcome of
            Right _ -> expectationFailure "expected the pilot arm to refuse"
            Left errs -> errs `shouldBe` [PilotWithoutEcosystem]

-- | Which arm of the phase a plan came back through, so an assertion names it rather than a shape.
plannedArm :: RoleWiring -> Text
plannedArm = \case
    MirrorPipelineWiring _ -> "mirror pipeline"
    StorePrunerWiring _ -> "store pruner"
    PilotWiring _ -> "pilot"

-- | A queue builder that allocates nothing, for the arms whose refusals are elsewhere.
inertQueue :: BuildMirrorQueue
inertQueue _ _ _ = pure noMirrorQueue

{- | A queue builder that throws as @amazonka@ does when it discovers no credentials, the live
call this phase folds into a refusal.
-}
refusingQueue :: BuildMirrorQueue
refusingQueue _ _ _ = throwIO NoCredentials

-- | A store builder that hands out the in-memory fake, so the pruner's arm reaches no cloud.
inertStore :: BuildStoreMaintenance
inertStore _ _ _ = fakeMaintenance <$> newFakeStore defaultFakeStoreConfig

-- | A store builder that throws as @amazonka@ does when it discovers no credentials.
refusingStore :: BuildStoreMaintenance
refusingStore _ _ _ = throwIO NoCredentials

-- | A credential build that mints nothing, so a case reaches no cloud.
inertCredentials :: BuildCredentials
inertCredentials _ _ = pure (Right noCredentialProviders)

-- | A credential build that refuses, as a mint against an identity that cannot answer does.
refusingCredentials :: BuildCredentials
refusingCredentials _ _ = pure (Left [CodeArtifactMintFailed "no identity answered"])

-- | The typed stand-in for amazonka's credential-discovery failure.
data NoCredentials = NoCredentials
    deriving stock (Show)

instance Exception NoCredentials

{- | An advisory store over a data directory under a path that is not a directory, so preparing
the sync throws where every host behaves alike, before it reaches a credential chain.
-}
unwritableAdvisoryEnv :: [(String, String)]
unwritableAdvisoryEnv =
    overrideEnv "ECLUSE_ADVISORIES__DATA_DIR" advisoryDataDir $
        overrideEnv "ECLUSE_ADVISORIES__URL" "s3://advisories.example.test/ecluse" staticEnvVars

-- | The unwritable data directory 'unwritableAdvisoryEnv' points at, which its refusal names.
advisoryDataDir :: (IsString s) => s
advisoryDataDir = "/dev/null/ecluse-advisories"

-- | The shipped mount over a configured advisory store, so the pilot's arm has work to plan.
advisoryStoreEnv :: [(String, String)]
advisoryStoreEnv = overrideEnv "ECLUSE_ADVISORIES__URL" advisoryStoreUrl staticEnvVars

{- | An advisory store with no mount declared under it. The proxy would serve nothing and the
Pilot would compile nothing, which is the pilot arm's own refusal.
-}
unmountedAdvisoryEnv :: [(String, String)]
unmountedAdvisoryEnv = [("ECLUSE_ADVISORIES__URL", advisoryStoreUrl)]

advisoryStoreUrl :: String
advisoryStoreUrl = "s3://advisories.example.test/ecluse"

-- | Plan a boot over 'staticEnvVars' for one role, through the given ports.
planFor :: BootRole -> ResolveAdapter -> BuildMirrorQueue -> BuildStoreMaintenance -> IO (Either [BootError] ExecutablePlan)
planFor = planWith staticEnvVars

-- | 'planFor' over a named environment layer, for a refusal 'staticEnvVars' cannot reach.
planWith :: [(String, String)] -> BootRole -> ResolveAdapter -> BuildMirrorQueue -> BuildStoreMaintenance -> IO (Either [BootError] ExecutablePlan)
planWith envVars role resolveAdapter buildQueue = planUnder envVars role resolveAdapter buildQueue inertCredentials

-- | 'planWith' over a chosen credential build, for the deleting role's own mint.
planUnder ::
    [(String, String)] ->
    BootRole ->
    ResolveAdapter ->
    BuildMirrorQueue ->
    BuildCredentials ->
    BuildStoreMaintenance ->
    IO (Either [BootError] ExecutablePlan)
planUnder envVars role resolveAdapter buildQueue buildCredentials buildStore = do
    config <- expectConfig envVars Nothing
    bootPlan <- expectPlanFor role envVars Nothing config noCeiling
    logEnv <- newTestLogEnv
    planExecutable logEnv passthroughTracingPort resolveAdapter buildQueue buildCredentials buildStore bootPlan

-- | 'planFor', failing the test on a refusal.
expectExecutable :: BootRole -> ResolveAdapter -> BuildMirrorQueue -> BuildStoreMaintenance -> IO ExecutablePlan
expectExecutable = expectExecutableWith staticEnvVars

-- | 'planWith', failing the test on a refusal.
expectExecutableWith :: [(String, String)] -> BootRole -> ResolveAdapter -> BuildMirrorQueue -> BuildStoreMaintenance -> IO ExecutablePlan
expectExecutableWith envVars role resolveAdapter buildQueue buildStore =
    planWith envVars role resolveAdapter buildQueue buildStore
        >>= either (\errs -> fail ("planning refused: " <> show errs)) pure

-- | The pilot arm's export loop, failing the test on any other arm.
expectPilotPlan :: ExecutablePlan -> IO ExportLoopPlan
expectPilotPlan plan = case epRoleWiring plan of
    PilotWiring exportPlan -> pure exportPlan
    other -> fail ("expected the pilot arm, got the " <> toString (plannedArm other) <> " arm")

-- | The mirror-pipeline arm of a plan, failing the test on any other arm.
expectMirrorWiring :: ExecutablePlan -> IO MirrorWiring
expectMirrorWiring plan = case epRoleWiring plan of
    MirrorPipelineWiring mirror -> pure mirror
    other -> fail ("expected the mirror-pipeline arm, got the " <> toString (plannedArm other) <> " arm")
