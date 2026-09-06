-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Composition.PlanSpec (spec) where

import Data.Text qualified as T
import Test.Hspec

import Ecluse.Composition.BootError (
    BootError (
        AwsEndpointMalformed,
        MemoryPlanOverrideUnsafe,
        MirrorRoleWithoutMirroring,
        MirrorTargetOnMountEndpoint,
        MissingAdapter,
        QueueUrlUnrecognised,
        SplitRoleNeedsDurableQueue
    ),
    renderBootError,
 )
import Ecluse.Composition.MemoryPlan (MemoryPlan (mpOverrideViolations, mpQueueMemoryMaxDepth))
import Ecluse.Composition.MirrorQueue (
    MirrorQueuePlan (MemoryBackend, SqsBackend),
    MirrorRuntimePlan (MirrorWith, NoMirroring),
    memoryQueueBootWarning,
 )
import Ecluse.Composition.Plan (
    BootPlan (..),
    BootReport (brAdvisories, brOutcome, brProvenance),
    configDocumentPath,
    defaultConfigPath,
    resolveBootPlan,
    roleRefusalWarnings,
 )
import Ecluse.Composition.Support (
    bootInputsFor,
    codeArtifactEnvVars,
    expectConfig,
    expectPlan,
    malformedAwsEndpoint,
    noCeiling,
    noMaintenanceBackend,
    overrideEnv,
    staticEnvVars,
    withoutMirrorTargetUrl,
    withoutQueueUrl,
 )
import Ecluse.Composition.Types (
    BootRole (BootMirrorPipeline, BootStorePruner, BootWithoutPipeline),
    MirrorRole (MirrorOnly, ServeOnly),
 )
import Ecluse.Config (mountPostureLines, resolvedKeyProvenance)
import Ecluse.Core.Credential (mkSecret)
import Ecluse.Core.Ecosystem (Ecosystem (Npm, RubyGems))
import Ecluse.Rts (
    CgroupLimits (..),
    EffectiveAxis (..),
    EffectiveRuntimePlan (..),
    Provenance (FromCgroup),
    RtsPosture (..),
    RuntimeOverrides (..),
    appliedRuntimePlan,
    reconcileRuntimePlan,
    resolveRuntimePlan,
 )

spec :: Spec
spec = describe "resolveBootPlan" $ do
    it "orders the plan's lines into the one list both entry points emit" $ do
        -- The golden the acceptance criterion rests on: the boot logs this list and
        -- check-config prints it, so the two transcripts cannot diverge.
        config <- expectConfig staticEnvVars Nothing
        plan <- expectPlan staticEnvVars Nothing config noCeiling
        bpLines plan
            `shouldBe` [ "runtime: private connection pool 256 (computed from file-descriptor limit 1024)"
                       , "runtime: public connection pool 128 (computed from file-descriptor limit 1024)"
                       , "runtime: serve admission 20 (computed from 2 capabilities)"
                       , "memory plan: response byte cap 12582912" <> fallbackClause
                       , "memory plan: request byte cap 26214400" <> fallbackClause
                       , "memory plan: cache byte bound 268435456" <> fallbackClause
                       , "memory plan: cache entry bound 1024" <> fallbackClause
                       , "memory plan: memory-queue depth 50000" <> fallbackClause
                       , "memory plan: mirror artifact byte cap 536870912" <> fallbackClause
                       , "mirror queue: sqs, https://sqs.us-east-1.amazonaws.com/123456789012/mirror (region us-east-1)"
                       ]
                <> mountPostureLines config
        bpWarnings plan `shouldBe` []

    it "returns the preamble on the refusing path as well as the succeeding one" $ do
        -- A refusal that names a config key stays traceable to the layer that set it.
        let refusingEnv = overrideEnv "ECLUSE_QUEUE__URL" "https://queue.example.test/q" staticEnvVars
        ok <- expectConfig staticEnvVars Nothing
        refused <- expectConfig refusingEnv Nothing
        let okReport = resolveBootPlan BootWithoutPipeline (bootInputsFor staticEnvVars Nothing ok noCeiling)
            refusedReport = resolveBootPlan BootWithoutPipeline (bootInputsFor refusingEnv Nothing refused noCeiling)
        brProvenance okReport `shouldBe` absentDocumentLine : resolvedKeyProvenance staticEnvVars Nothing
        brProvenance refusedReport `shouldBe` absentDocumentLine : resolvedKeyProvenance refusingEnv Nothing
        refusalsOf refusedReport `shouldSatisfy` isLeft
        -- The plan's own lines never repeat the preamble, so no line has two emission sites.
        fmap (any (`elem` brProvenance okReport) . bpLines) (brOutcome okReport) `shouldBe` Right False

    it "carries the role it vetted under, so a boot starts the behaviour the plan names" $ do
        -- The boot reads the behaviour off this field, so a plan resolved for one role can no
        -- longer start another's. The mirror target is one the deleting role can sweep, so
        -- every role clears the configuration.
        config <- expectConfig codeArtifactEnvVars Nothing
        let roleOf role = fmap bpRole (brOutcome (resolveBootPlan role (bootInputsFor codeArtifactEnvVars Nothing config noCeiling)))
        roleOf (BootMirrorPipeline MirrorOnly) `shouldBe` Right (BootMirrorPipeline MirrorOnly)
        roleOf BootStorePruner `shouldBe` Right BootStorePruner
        roleOf BootWithoutPipeline `shouldBe` Right BootWithoutPipeline

    it "decides the mirror runtime, the memory plan, and both connection pools" $ do
        config <- expectConfig staticEnvVars Nothing
        plan <- expectPlan staticEnvVars Nothing config noCeiling
        case bpMirrorRuntime plan of
            MirrorWith (SqsBackend _) -> pass
            other -> expectationFailure ("expected an SQS mirror runtime, got: " <> show other)
        bpPrivateConnections plan `shouldBe` 256
        bpPublicConnections plan `shouldBe` 128
        mpQueueMemoryMaxDepth (bpMemoryPlan plan) `shouldBe` 50000
        mpOverrideViolations (bpMemoryPlan plan) `shouldBe` []

    it "warns on the in-memory queue rollover and names the depth it built with" $ do
        let envVars = withoutQueueUrl staticEnvVars
        config <- expectConfig envVars Nothing
        plan <- expectPlan envVars Nothing config noCeiling
        bpMirrorRuntime plan `shouldBe` MirrorWith MemoryBackend
        bpLines plan `shouldSatisfy` elem "mirror queue: in-memory (depth 50000)"
        bpWarnings plan `shouldBe` [memoryQueueBootWarning]

    it "reports a disabled mirror runtime in one wording for both entry points" $ do
        config <- expectConfig serveOnlyEnvVars Nothing
        plan <- expectPlan serveOnlyEnvVars Nothing config noCeiling
        bpMirrorRuntime plan `shouldBe` NoMirroring
        bpLines plan
            `shouldSatisfy` elem "mirror runtime disabled: no mount mirrors, so no queue is built and no worker starts"
        bpWarnings plan `shouldBe` []

    it "names the document an explicit ECLUSE_CONFIG points at" $ do
        let envVars = overrideEnv "ECLUSE_CONFIG" "/srv/ecluse.yaml" staticEnvVars
            document = "server:\n  helpMessage: from the document\n"
        config <- expectConfig envVars (Just document)
        let preamble = brProvenance (resolveBootPlan BootWithoutPipeline (bootInputsFor envVars (Just document) config noCeiling))
        listToMaybe preamble `shouldBe` Just "Config document: /srv/ecluse.yaml"
        configDocumentPath staticEnvVars `shouldBe` defaultConfigPath

    it "trims the surrounding whitespace an ECLUSE_CONFIG value carries" $
        configDocumentPath (overrideEnv "ECLUSE_CONFIG" "  /etc/x.yaml  " staticEnvVars)
            `shouldBe` "/etc/x.yaml"

    it "falls back to the default path when ECLUSE_CONFIG is all whitespace" $
        configDocumentPath (overrideEnv "ECLUSE_CONFIG" "   " staticEnvVars)
            `shouldBe` defaultConfigPath

    describe "refusals" $ do
        it "refuses a structural composition error" $ do
            let envVars = overrideEnv "ECLUSE_MOUNTS__RUBYGEMS__ENABLED" "true" staticEnvVars
            config <- expectConfig envVars Nothing
            refusalsOf (resolveBootPlan BootWithoutPipeline (bootInputsFor envVars Nothing config noCeiling))
                `shouldBe` Left [MissingAdapter RubyGems]

        it "refuses a queue URL whose shape names no backend" $ do
            let envVars = overrideEnv "ECLUSE_QUEUE__URL" "https://queue.example.test/q" staticEnvVars
            config <- expectConfig envVars Nothing
            refusalsOf (resolveBootPlan BootWithoutPipeline (bootInputsFor envVars Nothing config noCeiling))
                `shouldBe` Left [QueueUrlUnrecognised "https://queue.example.test/q"]

        it "refuses an explicit memory override the shed ladder cannot work around" $ do
            -- A 1 GiB explicit cache on a 256 MiB pod. The override-free plan fits, so
            -- the pin is the named cause.
            let envVars = overrideEnv "ECLUSE_CACHE__MAX_BYTES" "1073741824" serveOnlyEnvVars
            config <- expectConfig envVars Nothing
            case refusalsOf (resolveBootPlan BootWithoutPipeline (bootInputsFor envVars Nothing config tightPod)) of
                Left [MemoryPlanOverrideUnsafe violations] ->
                    violations `shouldSatisfy` any (T.isInfixOf "cache.maxBytes")
                other -> expectationFailure ("expected a refused override, got: " <> show other)

        it "names both groups of a configuration wrong in two independent ways" $ do
            -- A mount with no adapter and a queue URL naming no backend are decided by different
            -- groups. One run reports both, so an operator fixes both before the next boot.
            let envVars =
                    overrideEnv "ECLUSE_QUEUE__URL" "https://queue.example.test/q" $
                        overrideEnv "ECLUSE_MOUNTS__RUBYGEMS__ENABLED" "true" staticEnvVars
            config <- expectConfig envVars Nothing
            refusalsOf (resolveBootPlan BootWithoutPipeline (bootInputsFor envVars Nothing config noCeiling))
                `shouldBe` Left [MissingAdapter RubyGems, QueueUrlUnrecognised "https://queue.example.test/q"]

        it "reports the plan's own refusals and the ambient endpoint's in one aggregated list" $ do
            -- The ambient AWS_ENDPOINT_URL is settled over the environment the rest of the pass
            -- reads, so one launch names it beside whatever else the configuration got wrong.
            let envVars =
                    overrideEnv "AWS_ENDPOINT_URL" malformedAwsEndpoint $
                        overrideEnv "ECLUSE_MOUNTS__RUBYGEMS__ENABLED" "true" staticEnvVars
            config <- expectConfig envVars Nothing
            refusalsOf (resolveBootPlan BootWithoutPipeline (bootInputsFor envVars Nothing config noCeiling))
                `shouldBe` Left [MissingAdapter RubyGems, AwsEndpointMalformed (mkSecret (toText malformedAwsEndpoint))]

        it "adds no refusal when AWS_ENDPOINT_URL is unset" $ do
            let envVars = overrideEnv "ECLUSE_MOUNTS__RUBYGEMS__ENABLED" "true" staticEnvVars
            config <- expectConfig envVars Nothing
            refusalsOf (resolveBootPlan BootWithoutPipeline (bootInputsFor envVars Nothing config noCeiling))
                `shouldBe` Left [MissingAdapter RubyGems]

        it "reports a refused queue URL alone, because the memory plan is sized against the runtime" $ do
            -- The memory plan reads the resolved backend, so a backend that refuses leaves no
            -- plan to judge the override against. The same override reports once the URL parses.
            let unsafeCache = overrideEnv "ECLUSE_CACHE__MAX_BYTES" "1073741824" staticEnvVars
                refusedQueue = overrideEnv "ECLUSE_QUEUE__URL" "https://queue.example.test/q" unsafeCache
            refusedConfig <- expectConfig refusedQueue Nothing
            refusalsOf (resolveBootPlan BootWithoutPipeline (bootInputsFor refusedQueue Nothing refusedConfig tightPod))
                `shouldBe` Left [QueueUrlUnrecognised "https://queue.example.test/q"]
            cachedConfig <- expectConfig unsafeCache Nothing
            case refusalsOf (resolveBootPlan BootWithoutPipeline (bootInputsFor unsafeCache Nothing cachedConfig tightPod)) of
                Left [MemoryPlanOverrideUnsafe violations] ->
                    violations `shouldSatisfy` any (T.isInfixOf "cache.maxBytes")
                other -> expectationFailure ("expected the override refusal alone, got: " <> show other)

        it "refuses --no-worker over the in-memory queue rather than planning the role" $ do
            -- The config is otherwise complete, so nothing else would refuse: dropping the role
            -- guard would let this plan, and then boot, a runtime whose jobs nothing consumes.
            let envVars = withoutQueueUrl staticEnvVars
            config <- expectConfig envVars Nothing
            refusalsOf (resolveBootPlan (BootMirrorPipeline ServeOnly) (bootInputsFor envVars Nothing config noCeiling))
                `shouldBe` Left [SplitRoleNeedsDurableQueue "ecluse proxy --no-worker"]

    describe "the advisories a pass reports beside its verdict" $ do
        it "reports a writing role's advisory beside the plan it cleared" $ do
            config <- expectConfig collapsedMirrorEnv Nothing
            brAdvisories (resolveBootPlan BootWithoutPipeline (bootInputsFor collapsedMirrorEnv Nothing config noCeiling))
                `shouldBe` [mirrorCollapseAdvisory]

        it "keeps the advisories a refused configuration earned, so one run reports both" $ do
            -- An advisory an operator must act on survives the refusal, so one run reports both.
            let envVars = overrideEnv "ECLUSE_MOUNTS__RUBYGEMS__ENABLED" "true" collapsedMirrorEnv
            config <- expectConfig envVars Nothing
            let report = resolveBootPlan BootWithoutPipeline (bootInputsFor envVars Nothing config noCeiling)
            refusalsOf report `shouldBe` Left [MissingAdapter RubyGems]
            brAdvisories report `shouldBe` [mirrorCollapseAdvisory]

        it "gives the deleting role the refusal alone, never the writing roles' advisory too" $ do
            -- One rule turns the detected collapse into exactly one outcome per role, so the
            -- Dredger reports what it refuses and not what another role would have tolerated.
            -- The collapsed target is also one no backend here sweeps, and the pass reports both.
            config <- expectConfig collapsedMirrorEnv Nothing
            let report = resolveBootPlan BootStorePruner (bootInputsFor collapsedMirrorEnv Nothing config noCeiling)
            refusalsOf report `shouldBe` Left [collapsedMirrorRefusal, noMaintenanceBackend]
            brAdvisories report `shouldBe` []

    describe "the runtime posture each entry point sizes against" $
        it "decides an override against the posture its own entry point resolved, so the two sides can differ" $ do
            -- One set of process facts, resolved through the two functions the two entry points
            -- call: 'reconcileRuntimePlan' for the boot, which measures the posture it reached,
            -- and 'appliedRuntimePlan' for the checker, which predicts a full application. The
            -- pass is the same function, so its verdict agrees only where those two values agree.
            let envVars = overrideEnv "ECLUSE_CACHE__MAX_BYTES" "1073741824" serveOnlyEnvVars
            config <- expectConfig envVars Nothing
            let plan = resolveRuntimePlan roomyHeapOverride noCgroup ghcrtsBoundPosture
                verdictUnder effective =
                    refusalsOf (resolveBootPlan BootWithoutPipeline (bootInputsFor envVars Nothing config effective))
            verdictUnder (appliedRuntimePlan noCgroup plan ghcrtsBoundPosture) `shouldBe` Right ()
            case verdictUnder (reconcileRuntimePlan noCgroup plan ghcrtsBoundPosture) of
                Left [MemoryPlanOverrideUnsafe violations] ->
                    violations `shouldSatisfy` any (T.isInfixOf "cache.maxBytes")
                other -> expectationFailure ("expected the measured posture to refuse, got: " <> show other)

    describe "roleRefusalWarnings -- what a checker with no subcommand still reports" $ do
        it "names both split roles the in-memory queue strands, which its own pass boots" $ do
            let envVars = withoutQueueUrl codeArtifactEnvVars
            config <- expectConfig envVars Nothing
            roleRefusalWarnings BootWithoutPipeline (bootInputsFor envVars Nothing config noCeiling)
                `shouldBe` [ wouldRefuse "ecluse proxy --no-worker" (SplitRoleNeedsDurableQueue "ecluse proxy --no-worker")
                           , wouldRefuse "ecluse mirror" (SplitRoleNeedsDurableQueue "ecluse mirror")
                           ]

        it "names the dedicated worker where no mount declares a mirror target" $ do
            config <- expectConfig serveOnlyEnvVars Nothing
            roleRefusalWarnings BootWithoutPipeline (bootInputsFor serveOnlyEnvVars Nothing config noCeiling)
                `shouldBe` [wouldRefuse "ecluse mirror" MirrorRoleWithoutMirroring]

        it "names the Dredger on a collapse the writing roles only warn about" $ do
            config <- expectConfig collapsedMirrorEnv Nothing
            roleRefusalWarnings BootWithoutPipeline (bootInputsFor collapsedMirrorEnv Nothing config noCeiling)
                `shouldBe` [ wouldRefuse "ecluse dredger" collapsedMirrorRefusal
                           , wouldRefuse "ecluse dredger" noMaintenanceBackend
                           ]

        it "names the Dredger on a mirror target this build has no maintenance backend for" $ do
            -- The writing roles boot on such a target and log nothing, so this line is where an
            -- operator who never runs the Dredger against it still learns that they cannot.
            config <- expectConfig staticEnvVars Nothing
            roleRefusalWarnings BootWithoutPipeline (bootInputsFor staticEnvVars Nothing config noCeiling)
                `shouldBe` [wouldRefuse "ecluse dredger" noMaintenanceBackend]

        it "omits the role the caller already reported for" $ do
            let envVars = withoutQueueUrl codeArtifactEnvVars
            config <- expectConfig envVars Nothing
            roleRefusalWarnings (BootMirrorPipeline MirrorOnly) (bootInputsFor envVars Nothing config noCeiling)
                `shouldBe` [wouldRefuse "ecluse proxy --no-worker" (SplitRoleNeedsDurableQueue "ecluse proxy --no-worker")]

        it "reports nothing where every role boots the configuration" $ do
            config <- expectConfig codeArtifactEnvVars Nothing
            roleRefusalWarnings BootWithoutPipeline (bootInputsFor codeArtifactEnvVars Nothing config noCeiling) `shouldBe` []

-- | One warning line as a checker prints it: the command that refuses, and the refusal itself.
wouldRefuse :: Text -> BootError -> Text
wouldRefuse invocation err = invocation <> " would refuse to boot: " <> renderBootError err

-- | The npm mount mirroring where it reads: a writing role's advisory, the Dredger's refusal.
collapsedMirrorEnv :: [(String, String)]
collapsedMirrorEnv = overrideEnv "ECLUSE_MOUNTS__NPM__MIRROR_TARGET__REGISTRY__URL" "https://private.example.test" staticEnvVars

collapsedMirrorRefusal :: BootError
collapsedMirrorRefusal = MirrorTargetOnMountEndpoint Npm Npm "privateUpstream" "https://private.example.test"

mirrorCollapseAdvisory :: Text
mirrorCollapseAdvisory =
    "mount \"npm\": mirrorTarget and privateUpstream resolve to the same registry (https://private.example.test); the Dredger refuses this configuration, so pruning this mirror stays manual"

{- | A plan resolution reduced to its verdict. 'BootPlan' carries the cleared adapters, which are
records of functions, so the refusal is what an assertion compares.
-}
refusalsOf :: BootReport -> Either [BootError] ()
refusalsOf = void . brOutcome

-- | staticEnvVars with the mirror target and its write token dropped: the mount serves only.
serveOnlyEnvVars :: [(String, String)]
serveOnlyEnvVars =
    withoutMirrorTargetUrl (filter ((/= "ECLUSE_MOUNTS__NPM__MIRROR_TARGET__REGISTRY__TOKEN") . fst) staticEnvVars)

-- | The preamble's first line when no document exists at the default path.
absentDocumentLine :: Text
absentDocumentLine = "Config document: none at /etc/ecluse/config.yaml (defaults and environment only)"

-- | No cgroup of either kind, so the plan's heap ceiling rests on the configured override alone.
noCgroup :: CgroupLimits
noCgroup = CgroupLimits{cgCpuCores = Nothing, cgMemoryMaxBytes = Nothing}

-- | A 4 GiB configured ceiling on four cores, which a 256 MiB live posture falls well short of.
roomyHeapOverride :: RuntimeOverrides
roomyHeapOverride = RuntimeOverrides{roCores = Just 4, roCoresCeiling = Nothing, roMaxHeapBytes = Just (4096 * mib)}

{- | An operator @GHCRTS -M256m@ binding the heap below the plan. The capability count matches,
so the heap axis alone separates what the boot measures from what the checker predicts.
-}
ghcrtsBoundPosture :: RtsPosture
ghcrtsBoundPosture =
    RtsPosture
        { rpCapabilities = 4
        , rpProcessors = 4
        , rpAllocAreaBytes = 4 * mib
        , rpNurseryChunkBytes = Nothing
        , rpMaxHeapBytes = Just (256 * mib)
        }

-- | A 256 MiB pod on four capabilities: the computed tenants shed to fit, and nothing refuses.
tightPod :: EffectiveRuntimePlan
tightPod =
    noCeiling
        { erpCapabilities = EffectiveAxis{axDesired = 4, axObserved = 4, axProvenance = FromCgroup}
        , erpMaxHeapBytes =
            EffectiveAxis{axDesired = Just (256 * mib), axObserved = Just (256 * mib), axProvenance = FromCgroup}
        }

-- | The provenance clause every memory-plan line carries with no heap-ceiling datapoint.
fallbackClause :: Text
fallbackClause = " (built-in default; no heap-ceiling datapoint)"

mib :: Int
mib = 1024 * 1024
