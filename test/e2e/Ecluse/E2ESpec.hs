-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The end-to-end scenarios, driven through the real @npm@ CLI against the real image.

__One data plane, shared per-describe proxies__. The whole suite shares a single data
plane: the docker network plus the Verdaccio, nginx, and ministack containers, booted once
by 'withGlobalDataPlane' under @aroundAll@. On top of it each @describe@ block boots its
own proxy under @aroundAllWith@ ('withE2E' \/ 'withE2EWith'). A telemetry scenario also
gets its own OTLP collector. A block's cases share that proxy rather than booting one per
case. Cases stay independent by acting on __distinct fixture packages__, not by
a fresh environment each. The scenarios use @allowPkg@, @denyPkg@, @tamperPkg@, @headPkg@,
@mirrorPkg@, and others, so no case observes another's mirror state or its bracketed
(paused-then-resumed) upstream. When the environment is unavailable (no docker or image),
every case reports @pending@ rather than failing.

Graceful drain is @pending@ here, and it sits outside the @aroundAll@ so it boots no
environment until the drain path exists.
-}
module Ecluse.E2ESpec (spec) where

import Data.Text qualified as T

import System.Exit (ExitCode (ExitSuccess))
import Test.Hspec
import UnliftIO.Concurrent (threadDelay)

import Ecluse.E2E.Fixtures (
    PkgSpec,
    allowPkg,
    denyPkg,
    dredgerKeepPkg,
    dredgerPkg,
    headPkg,
    mirrorPkg,
    psName,
    psVersion,
    tamperPkg,
    telemetryDdPkg,
    telemetryPkg,
 )
import Ecluse.E2E.Harness

spec :: Spec
spec = do
    unavailable <- runIO e2eUnavailable
    case unavailable of
        Just reason -> it "end-to-end suite (environment unavailable)" (pendingWith reason)
        Nothing -> aroundAll withGlobalDataPlane $ do
            scenarios
            telemetryScenarios
            publishScenarios
            dredgerScenarios
            pendingScenarios

{- | The active scenarios, grouped into @describe@ blocks that each share one proxy under
@aroundAllWith@. Cases stay independent through distinct fixture packages, not a fresh
environment each (see the module header).
-}
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
                -- This proves our own npm CLI runs no lifecycle script even when one is present,
                -- closing the arbitrary-code-execution surface in Écluse's own CI. The probe
                -- project's postinstall creates a sentinel, so none means ignore-scripts held.
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
                -- The core resilience loop: the proxy serves a package from public, the worker
                -- mirrors it, then an npm ci succeeds with public paused. npm ci fetches from the
                -- lockfile's resolved URL without re-resolving, so the bytes came from the mirror.
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

{- | The whole-system telemetry scenarios. Each @describe@ block boots its own proxy under
@aroundAllWith@ with its own telemetry topology ('E2EConfig'), which no sibling block sees.
-}
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

    -- OTLP on with no collector standing, so its alias does not resolve. The batch exporter
    -- fails off the request path, so an absent collector never takes the proxy down. The
    -- runtime wraps the exporters because hs-opentelemetry 1.0.0.0 drops a failed export silently.
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

{- | The first-party publish scenarios. The round-trip and the anti-shadowing refusal share one
proxy with 'publishTargetEnv' layered in, where Verdaccio is both the publication target and the
private upstream. The cases use distinct package names, so neither observes the other's publish.
-}
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
                -- The proxy refuses a name outside ECLUSE_MOUNTS__NPM__FIRST_PARTY with a 403
                -- before the relay. The harness lets Verdaccio accept anonymous publishes, so it
                -- would store anything that reached it, so a False proves nothing left the proxy.
                withPublishProject e2e name ver $ \proj -> do
                    void $ npmPublishIn proj >>= shouldFail
                    threadDelay 1500000
                    reached <- verdaccioHasVersionNow e2e name ver
                    reached `shouldBe` False

{- | The Dredger against the store the proxy mirrors into. Its own proxy seeds the store, and the
sweep then runs as a one-shot container on the same data plane. Both cases act on fixture packages
no other block installs, so an absence after a sweep is attributable to that sweep.
-}
dredgerScenarios :: SpecWith GlobalDataPlane
dredgerScenarios =
    describe "the Dredger against the mirror store" $ aroundAllWith withPlaneAndProxy $ do
        it "lists the names a seeded store holds, and buckets them by their base component" $ \(_, e2e) -> do
            -- The protocol leaf reads this document and projects it with this parser, so a
            -- Verdaccio image bump that changed the shape would fail here rather than in a sweep.
            void $ npmInstall e2e (psName dredgerPkg) >>= shouldSucceed
            mirrored <- verdaccioHasVersion e2e (psName dredgerPkg) (psVersion dredgerPkg)
            mirrored `shouldBe` True
            names <- verdaccioListing e2e
            names `shouldSatisfy` elem (psName dredgerPkg)
            bucketed <- verdaccioNamesUnder e2e "e"
            bucketed `shouldSatisfy` elem (psName dredgerPkg)
            outside <- verdaccioNamesUnder e2e "z"
            outside `shouldBe` []

        it "deletes the mirrored version an identity deny names, and keeps the one it does not" $ \(gdp, e2e) -> do
            -- Both packages are mirrored, and the sweep's rule set names only one of them, so the
            -- survivor is what shows the cap and the verdict bound what the cycle did.
            void $ npmInstall e2e (psName dredgerPkg) >>= shouldSucceed
            void $ npmInstall e2e (psName dredgerKeepPkg) >>= shouldSucceed
            condemned <- verdaccioHasVersion e2e (psName dredgerPkg) (psVersion dredgerPkg)
            survivor <- verdaccioHasVersion e2e (psName dredgerKeepPkg) (psVersion dredgerKeepPkg)
            (condemned, survivor) `shouldBe` (True, True)
            run <- runDredgerOnce gdp ["--once"] [("ECLUSE_RULES", identityDenyOf dredgerPkg)]
            -- The Dredger's own log carries why a cycle swept nothing: a halt, a refused delete,
            -- an empty candidate set, or a boot it never got past. Report it rather than a bare
            -- False, so one run is enough to say what happened.
            unless (dredgerExit run == ExitSuccess) (failWithLog run "the sweep exited non-zero")
            gone <- verdaccioHasVersionNow e2e (psName dredgerPkg) (psVersion dredgerPkg)
            when gone (failWithLog run "the condemned version is still served")
            kept <- verdaccioHasVersionNow e2e (psName dredgerKeepPkg) (psVersion dredgerKeepPkg)
            unless kept (failWithLog run "the version no rule named was deleted too")

-- Fail with what the sweep itself reported, so the next run needs no second look.
failWithLog :: DredgerRun -> Text -> Expectation
failWithLog run reason =
    expectationFailure (toString (reason <> ", and the sweep reported:\n" <> dredgerOutput run))

-- The proxy that seeds the store, beside the data plane the sweep container joins.
withPlaneAndProxy :: ((GlobalDataPlane, E2E) -> IO ()) -> GlobalDataPlane -> IO ()
withPlaneAndProxy action gdp = withE2E (\e2e -> action (gdp, e2e)) gdp

{- | A rule set with one identity deny and no advisory rule, so the sweep needs no advisory
database and only the named version is condemned.
-}
identityDenyOf :: PkgSpec -> Text
identityDenyOf p =
    "{\"revoke-swept\":{\"type\":\"DenyByIdentity\",\"identity\":\""
        <> psName p
        <> "@"
        <> psVersion p
        <> "\"}}"

{- | Placeholders for unimplemented work, kept outside @aroundAll@ so they boot no environment.
Graceful drain @SIGTERM@s the proxy, so when written it needs its own @describe@ block and proxy.
-}
pendingScenarios :: SpecWith GlobalDataPlane
pendingScenarios =
    describe "graceful shutdown" $
        it "drains in-flight work on SIGTERM" $ \_ ->
            pendingWith "activates with the #160 graceful-drain work"

-- | The mount-relative tarball path for a fixture package's single version.
tarballPath :: PkgSpec -> Text
tarballPath p = "/npm/" <> psName p <> "/-/" <> psName p <> "-" <> psVersion p <> ".tgz"
