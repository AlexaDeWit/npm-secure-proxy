-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Whole-system scenarios share local stores and run real npm clients against the product image.
Each scenario group boots its own proxy. Missing prerequisites report pending cases.
-}
module Ecluse.E2ESpec (spec) where

import Data.Text qualified as T

import Test.Hspec
import UnliftIO.Concurrent (threadDelay)

import Ecluse.E2E.Fixtures (
    PkgSpec,
    allowPkg,
    denyPkg,
    headPkg,
    mirrorPkg,
    psName,
    psVersion,
    tamperPkg,
    telemetryDdPkg,
    telemetryPkg,
 )
import Ecluse.E2E.Harness

-- | Drive the product image with real npm clients and local stores.
spec :: Spec
spec = do
    unavailable <- runIO e2eUnavailable
    case unavailable of
        Just reason -> it "end-to-end suite (environment unavailable)" (pendingWith reason)
        Nothing -> aroundAll withGlobalDataPlane $ do
            scenarios
            telemetryScenarios
            publishScenarios
            pendingScenarios

scenarios :: SpecWith GlobalDataPlane
scenarios = do
    describe "read-only and non-interfering scenarios (shared environment)" $ aroundAllWith withE2E $ do
        describe "public surface -- install and policy" $ do
            it "installs an allow-listed package end to end" $ \e2e -> do
                void $ npmInstall e2e (psName allowPkg) >>= shouldSucceed

            it "blocks a package that declares an install script, and never mirrors it" $ \e2e -> do
                void $ npmInstall e2e (psName denyPkg) >>= shouldFail
                -- Give the worker a 1.5s window to erroneously mirror it, then assert absence.
                -- Using verdaccioHasVersion here would incur a 20-second timeout penalty.
                threadDelay 1500000
                mirrored <- verdaccioHasVersionNow e2e (psName denyPkg) (psVersion denyPkg)
                mirrored `shouldBe` False

            it "runs no package lifecycle script during a harness install (defence in depth)" $ \e2e -> do
                (installed, scriptRan) <- installWithLifecycleProbe e2e
                void $ shouldSucceed installed
                scriptRan `shouldBe` False

        describe "server↔worker -- the integrity gate" $
            it "refuses to mirror an artifact whose bytes fail the integrity gate" $ \e2e -> do
                -- A tarball request enqueues a mirror on demand. The worker's digest gate must
                -- reject the tampered bytes, so the version never reaches the private mirror.
                _ <- proxyGet e2e (tarballPath tamperPkg)
                threadDelay 1500000
                mirrored <- verdaccioHasVersionNow e2e (psName tamperPkg) (psVersion tamperPkg)
                mirrored `shouldBe` False

        describe "protocol behaviours" $
            it "answers HEAD on a tarball with its size but no body, and enqueues no mirror" $ \e2e -> do
                -- A HEAD relays the upstream headers with no body, so it declares a
                -- Content-Length yet enqueues no mirror. Only this case touches headPkg.
                (status, declared, bodyBytes) <- proxyHead e2e (tarballPath headPkg)
                status `shouldBe` 200
                bodyBytes `shouldBe` 0
                declared `shouldSatisfy` maybe False (> 0)
                threadDelay 1500000
                mirrored <- verdaccioHasVersionNow e2e (psName headPkg) (psVersion headPkg)
                mirrored `shouldBe` False

        describe "server↔worker -- the full mirror lifecycle" $
            it "mirrors a package served from public, then installs it from the mirror with public down" $ \e2e -> do
                let name = psName mirrorPkg
                    ver = psVersion mirrorPkg
                presentBefore <- verdaccioHasVersionNow e2e name ver -- (1) a miss in the private mirror
                presentBefore `shouldBe` False
                withNpmProject e2e $ \proj -> do
                    void $ npmInstallIn proj name >>= shouldSucceed -- (2,3) served from public, writes the lockfile
                    mirrored <- verdaccioHasVersion e2e name ver -- (4) the worker mirrors it to private
                    mirrored `shouldBe` True
                    void $ withUpstreamPaused e2e (npmCiIn proj) >>= shouldSucceed -- (5) public down → from the mirror
        describe "first-party publish -- opt-in posture" $
            it "answers a publish with 405 when no publication target is configured" $ \e2e -> do
                -- The base topology declares no ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET, so PUT is not an allowed
                -- method. A raw PUT suffices because the 405 precedes any body read.
                status <- proxyPut e2e ("/npm/" <> publishInScopeName)
                status `shouldBe` 405

telemetryScenarios :: SpecWith GlobalDataPlane
telemetryScenarios = do
    -- Real healthy OTLP publication: with telemetry on and an OTLP endpoint, a real npm
    -- request's ecluse.* metrics and its span actually reach a collector.
    describe "telemetry -- OTLP healthy publication (#324) and domain-span emission (#307)" $
        aroundAllWith (withE2EWith E2EConfig{ecCollector = True, ecExtraEnv = otlpCollectorEnv}) $ do
            it "exports ecluse.* metrics and a span to the collector on a real npm request" $ \e2e -> do
                void $ npmInstall e2e (psName allowPkg) >>= shouldSucceed
                -- The assertion keys on the catalogue metric name and the exporter's per-span
                -- marker, so it proves both signals reached the collector.
                delivered <-
                    awaitCollectorLog
                        e2e
                        (\logs -> "ecluse.serve.decision" `T.isInfixOf` logs && "Span #" `T.isInfixOf` logs)
                        80
                delivered `shouldBe` True

            it "emits the rule-eval, mirror-enqueue, and mirror-job domain spans to the collector on a mirror round-trip" $ \e2e -> do
                -- A public-served install gates the version (rule-eval span) and enqueues a
                -- mirror (enqueue span). The worker then mirrors it (job span).
                withNpmProject e2e $ \proj -> do
                    void $ npmInstallIn proj (psName telemetryPkg) >>= shouldSucceed
                -- The worker mirrors asynchronously, so the mirror-job span lands after the
                -- install returns. The published mirror is the cue that the job ran.
                mirrored <- verdaccioHasVersion e2e (psName telemetryPkg) (psVersion telemetryPkg)
                mirrored `shouldBe` True
                emitted <-
                    awaitCollectorLog
                        e2e
                        ( \logs ->
                            all
                                (`T.isInfixOf` logs)
                                ["ecluse.rule.eval", "ecluse.mirror.enqueue", "ecluse.mirror.job"]
                        )
                        120
                emitted `shouldBe` True

    -- OTLP absent and telemetry off: the real image still boots, serves a real install,
    -- and logs JSONL to stdout/stderr, with no collector anywhere.
    describe "telemetry -- OTLP off, no collector (#325)" $
        aroundAllWith (withE2EWith E2EConfig{ecCollector = False, ecExtraEnv = [("ECLUSE_OBSERVABILITY__TELEMETRY", "off")]}) $
            it "starts, serves a real install, and logs JSONL to stdout -- no collector needed" $ \e2e -> do
                void $ npmInstall e2e (psName allowPkg) >>= shouldSucceed
                -- This awaits any log object, keyed on the message field every JSONL line
                -- carries. The worker's async publish line reliably provides one.
                logged <- awaitProxyLog e2e (T.isInfixOf "\"message\":") 80
                logged `shouldBe` True

    describe "telemetry -- OTLP on but the collector unreachable (#325)" $
        aroundAllWith (withE2EWith E2EConfig{ecCollector = False, ecExtraEnv = otlpCollectorEnv}) $
            it "surfaces a throttled export-failure warning yet keeps serving -- an absent collector degrades visibly, no crash" $ \e2e -> do
                void $ npmInstall e2e (psName allowPkg) >>= shouldSucceed
                logged <- awaitProxyLog e2e (T.isInfixOf "\"message\":") 80
                logged `shouldBe` True
                -- Spans (1s batch flush) and metrics (1s reader) fail against the unreachable
                -- endpoint, and the throttle's first-failure warning reaches the proxy's JSONL.
                exportWarned <- awaitProxyLog e2e (T.isInfixOf "telemetry export error") 80
                exportWarned `shouldBe` True
                -- It KEEPS serving: still ready, and still serving a fresh install. The
                -- failed-and-surfaced export never took the proxy down or blocked a request.
                stillReady <- proxyStatus e2e "/readyz"
                stillReady `shouldBe` 200
                void $ npmInstall e2e (psName mirrorPkg) >>= shouldSucceed

    -- DD_SERVICE, DD_ENV, DD_VERSION and DD_AGENT_HOST flow through the self-aligning resolver.
    -- They become unified-service-tag resource attributes and the dd object on the JSONL logs.
    describe "telemetry -- Datadog pattern (#323)" $
        aroundAllWith (withE2EWith E2EConfig{ecCollector = True, ecExtraEnv = datadogCollectorEnv}) $
            it "carries the Datadog unified-service tags to the collector and the dd object onto the logs" $ \e2e -> do
                -- A mirror round-trip drives request spans plus a worker job span, the
                -- span-scoped path whose log line carries a populated dd.trace_id.
                withNpmProject e2e $ \proj -> do
                    void $ npmInstallIn proj (psName telemetryDdPkg) >>= shouldSucceed
                -- The resolver derives service.name, deployment.environment and service.version
                -- from the DD_* identity. The assertion checks both the key and the value.
                ust <-
                    awaitCollectorLog
                        e2e
                        ( \logs ->
                            all
                                (`T.isInfixOf` logs)
                                [ "service.name"
                                , ddTagService
                                , "deployment.environment"
                                , ddTagEnv
                                , "service.version"
                                , ddTagVersion
                                ]
                        )
                        80
                ust `shouldBe` True
                -- The proxy's JSONL lines carry the dd object: the same UST identity plus a
                -- populated trace_id, the active-span log↔trace correlation.
                correlated <-
                    awaitProxyLog
                        e2e
                        ( \logs ->
                            hasPopulatedTraceId logs
                                && ("\"service\":\"" <> ddTagService <> "\"") `T.isInfixOf` logs
                                && ("\"env\":\"" <> ddTagEnv <> "\"") `T.isInfixOf` logs
                                && ("\"version\":\"" <> ddTagVersion <> "\"") `T.isInfixOf` logs
                        )
                        80
                correlated `shouldBe` True

publishScenarios :: SpecWith GlobalDataPlane
publishScenarios = do
    describe "first-party publish -- publication target enabled" $
        aroundAllWith (withE2EWith E2EConfig{ecCollector = False, ecExtraEnv = publishTargetEnv}) $ do
            it "publishes an in-scope package, then installs it back through the private leg" $ \e2e -> do
                let name = publishInScopeName
                    ver = publishVersion
                -- The guard admits an in-scope publish and the relay forwards it to the
                -- publication target (Verdaccio)...
                void $ withPublishProject e2e name ver npmPublishIn >>= shouldSucceed
                onTarget <- verdaccioHasVersion e2e name ver
                onTarget `shouldBe` True
                -- ...and readable back: the proxy serves it over the private leg, so a fresh
                -- install through the proxy succeeds.
                void $ npmInstall e2e name >>= shouldSucceed

            it "refuses an out-of-scope publish before any upstream write (anti-shadowing guard)" $ \e2e -> do
                let name = publishOutOfScopeName
                    ver = publishVersion
                -- Precondition: no other case publishes this out-of-scope name, so the absence
                -- below is attributable to the refusal, not to stale state.
                absentBefore <- verdaccioHasVersionNow e2e name ver
                absentBefore `shouldBe` False
                withPublishProject e2e name ver $ \proj -> do
                    void $ npmPublishIn proj >>= shouldFail
                    threadDelay 1500000
                    reached <- verdaccioHasVersionNow e2e name ver
                    reached `shouldBe` False

pendingScenarios :: SpecWith GlobalDataPlane
pendingScenarios =
    describe "graceful shutdown" $
        it "drains in-flight work on SIGTERM" $ \_ ->
            pendingWith "activates with the #160 graceful-drain work"

tarballPath :: PkgSpec -> Text
tarballPath p = "/npm/" <> psName p <> "/-/" <> psName p <> "-" <> psVersion p <> ".tgz"
