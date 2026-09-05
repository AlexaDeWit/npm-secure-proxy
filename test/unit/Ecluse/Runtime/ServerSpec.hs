-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Runtime.ServerSpec (spec) where

import Prelude hiding (get)

import Network.HTTP.Types (hConnection, methodDelete, methodHead, methodPut, status200, status500, statusCode)
import Network.Wai (
    Application,
    Response,
    ResponseReceived,
    responseLBS,
    responseStatus,
 )
import Network.Wai.Internal (ResponseReceived (ResponseReceived))
import Test.Hspec
import Test.Hspec.Wai
import UnliftIO (timeout)
import UnliftIO.Concurrent (threadDelay)
import UnliftIO.Exception (finally, throwIO, try)

import Data.Time (addUTCTime, getCurrentTime)

import Ecluse.Core.Credential (mkSecret)
import Ecluse.Core.Package (mkScope)
import Ecluse.Core.Registry.Adapter.Types (AdapterPublish (publishRelay), RegistryAdapter (adapterProjectName, adapterPublish))
import Ecluse.Core.Registry.Npm.Adapter (npmAdapter)
import Ecluse.Core.Registry.Npm.Credential (npmCredential)
import Ecluse.Core.Registry.Npm.Publish qualified as NpmPublish
import Ecluse.Core.Registry.Npm.Route (npmNotFound, npmRouter)
import Ecluse.Core.Security (defaultLimits)
import Ecluse.Core.Security.Egress.DevHttp (loopbackRegistryUrl)
import Ecluse.Core.Server.Admission.Bytes (ByteAdmission, newByteAdmission)
import Ecluse.Core.Server.Context (MountRouter, PublishDeps (..), ResponseAction (AnswerLocally), RouteAction (RouteAction))
import Ecluse.Core.Server.Contract (ResponseContract, VariableResponse, variableOpaqueContract, variableResponse)
import Ecluse.Core.Server.Fault (RequestFault (rqCause))
import Ecluse.Core.Telemetry.Metrics (RequestFaultCause (UnclassifiedFault))
import Ecluse.Core.Worker (Liveness (Liveness, liveHealthy, liveLastPoll), heartbeatLivenessNow, workerHeartbeatStaleAfter)
import Ecluse.Runtime.Env (envWorkerHeartbeat, recordPoll)
import Ecluse.Runtime.Server (
    DrainSignal,
    MountBinding (..),
    ServerConfig (..),
    ShutdownDrainTimeout (..),
    application,
    beginDrain,
    defaultPort,
    defaultShutdownDrainTimeout,
    isDraining,
    mkServerConfig,
    newDrainSignal,
    perimeterGuard,
    probeOnlyApplication,
    raceServerAgainstLoop,
    runWarp,
 )
import Ecluse.Runtime.Test.Support (newTestEnv)
import Ecluse.Test.Server.Mount (inertPackumentDeps)
import Ecluse.Test.Wai (bodyContainsAll)

{- | A registry-handle double whose effectful fields refuse loudly. The web layer only
routes and renders, so a refusal surfaces any leak into the data plane.
-}

-- | A credential-handle double: a fixed, non-expiring token, never read here.

{- | A test mount binding with the given prefix and router, and __inert__ packument-serve
dependencies. These specs exercise routing, not the data plane.
-}
mountAt :: NonEmpty Text -> MountRouter -> MountBinding
mountAt prefix router =
    publishMountAt prefix router Nothing

{- | A test mount binding like 'mountAt' but with the given (optional) first-party
publish dependencies. 'Nothing' leaves a @PUT \/{pkg}@ the @405@ opt-out. 'Just'
turns on the publish path: the scope guard and the relay.
-}
publishMountAt :: NonEmpty Text -> MountRouter -> Maybe PublishDeps -> MountBinding
publishMountAt prefix router publishDeps =
    MountBinding
        { bindingPrefix = prefix
        , bindingRouter = router
        , bindingCredential = npmCredential
        , bindingPackumentDeps = inertPackumentDeps
        , bindingPublishDeps = publishDeps
        }

{- | The 'application' under a single @\/npm@ mount carrying npm's path grammar, for the
prefix-strip dispatch and npm routing-table assertions.
-}
npmMountApp :: IO Application
npmMountApp = application (mkServerConfig [mountAt ("npm" :| []) npmRouter]) <$> newTestEnv

{- | The 'application' under a single @\/npm@ mount with the publish path __enabled__: one
allowed scope, @\@acme@, and an __unconnectable__ publication target. An in-scope publish
then reaches the relay and fails with @502@, while an out-of-scope publish stops at the
guard with @403@, which proves the guard fires before any upstream write.
-}
publishMountApp :: IO Application
publishMountApp = publishAppWith basePublishDeps

{- | The base publish dependencies these tests build on: an @\@acme@ scope allow-list and
an unconnectable publication target, so an in-scope publish reaches the relay and fails
with @502@. It takes the body-byte budget because 'publishAppWith' allocates one
admission per application.
-}
basePublishDeps :: ByteAdmission -> PublishDeps
basePublishDeps bodyBudget =
    PublishDeps
        { pubTargetUrl = loopbackRegistryUrl "http://127.0.0.1:1" -- an unconnectable port
        , pubAllowed = NpmPublish.npmPublishAllowed [mkScope "acme"]
        , pubStaticToken = Nothing
        , pubInboundToken = Nothing
        , pubLimits = defaultLimits
        , pubBodyBudget = bodyBudget
        , pubMaxRequestBytes = 26214400
        , pubHelp = Nothing
        , pubProjectName = adapterProjectName npmAdapter
        , pubAdapter = adapterPublish npmAdapter
        }

{- | The 'application' under a single @\/npm@ mount carrying the given publish deps,
handed a generously-sized body-byte budget these routing tests never contend on.
-}
publishAppWith :: (ByteAdmission -> PublishDeps) -> IO Application
publishAppWith mkDeps = do
    bodyBudget <- newByteAdmission (128 * 1024 * 1024)
    application (mkServerConfig [publishMountAt ("npm" :| []) npmRouter (Just (mkDeps bodyBudget))]) <$> newTestEnv

{- | The 'application' under a single @\/npm@ mount whose router is a __fake__, proving
dispatch follows the binding's router rather than a hardwired npm grammar.
-}
fakeRouterApp :: IO Application
fakeRouterApp = application (mkServerConfig [mountAt ("npm" :| []) fakeRouter]) <$> newTestEnv
  where
    -- npm's @is-odd@ would be a packument read. Under this router it is a miss, so the two
    -- routers give observably different answers.
    fakeRouter :: MountRouter
    fakeRouter _method ["beep"] = RouteAction fakeContract (AnswerLocally (variableResponse status200 [] "{}"))
    fakeRouter _method _ = npmNotFound

    fakeContract :: ResponseContract (VariableResponse LByteString)
    fakeContract = variableOpaqueContract "application/json" "The fake router's response."

{- | The 'application' with __no mounts__: every path but the control-plane health
probes matches no mount and is the neutral @404@.
-}
neutralApp :: IO Application
neutralApp = application (mkServerConfig []) <$> newTestEnv

-- | The probe-only front door the Dredger and Pilot worker roles run.
probeOnlyApp :: IO Application
probeOnlyApp = probeOnlyApplication (mkServerConfig [])

-- | 'probeOnlyApp' with the injected liveness check failing, which only @\/livez@ reads.
deadProbeOnlyApp :: IO Application
deadProbeOnlyApp = probeOnlyApplication ((mkServerConfig []){scCheckLive = pure notLive})

-- | A failing liveness verdict with no poll recorded, standing in for a stalled loop.
notLive :: Liveness
notLive = Liveness{liveHealthy = False, liveLastPoll = Nothing}

{- | An npm-mount 'application' whose 'DrainSignal' is __already raised__, standing in for
an instance mid-graceful-shutdown without binding a socket.
-}
drainingApp :: IO Application
drainingApp = do
    drain <- raisedDrain
    application (mkServerConfig [mountAt ("npm" :| []) npmRouter]){scDrain = drain} <$> newTestEnv

-- | A live 'DrainSignal' raised into the draining state.
raisedDrain :: IO DrainSignal
raisedDrain = do
    drain <- newDrainSignal
    beginDrain drain
    pure drain

{- | An npm-mount 'application' whose worker heartbeat is older than
'workerHeartbeatStaleAfter', driving the liveness probe to its @503@ "worker stalled" arm.
-}
stalledWorkerApp :: IO Application
stalledWorkerApp = do
    env <- newTestEnv
    now <- getCurrentTime
    -- A poll older than the staleness threshold: the loop did not advance its
    -- heartbeat within the window, so liveness must read it as stalled.
    recordPoll (envWorkerHeartbeat env) (addUTCTime (negate (workerHeartbeatStaleAfter + 60)) now)
    -- The composition root folds the heartbeat into /livez only when a worker
    -- runs. This fixture models that mirrored-deployment wiring explicitly.
    let cfg = (mkServerConfig [mountAt ("npm" :| []) npmRouter]){scCheckLive = heartbeatLivenessNow (envWorkerHeartbeat env)}
    pure (application cfg env)

{- | A header matcher that passes only when the response carries __no__ @Connection@
header. @hspec-wai@'s '<:>' can only assert that a header is present.
-}
matchNoConnectionHeader :: MatchHeader
matchNoConnectionHeader = MatchHeader $ \headers _body ->
    if any ((== hConnection) . fst) headers
        then Just "expected no Connection header, but one was present"
        else Nothing

spec :: Spec
spec = do
    perimeterGuardSpec
    runWarpDrainWiringSpec
    raceServerAgainstLoopSpec
    describe "control-plane health probes (above any mount)" $
        with npmMountApp $ do
            it "answers /livez with 200" $
                get "/livez" `shouldRespondWith` 200

            it "reports a null last poll when no background loop is wired behind /livez" $
                get "/livez" `shouldRespondWith` 200{matchBody = bodyContainsAll ["\"lastPoll\":null"]}

            it "answers /readyz with 200" $
                get "/readyz" `shouldRespondWith` 200

    describe "liveness -- worker-stall arm of /livez" $
        with stalledWorkerApp $ do
            it "fails /livez with 503 once the worker heartbeat is stale" $
                -- Liveness folds in the mirror worker's consume-loop heartbeat, so a loop quiet
                -- past the threshold flips /livez to 503 even while the front door still serves.
                get "/livez" `shouldRespondWith` 503

            it "keeps /readyz at 200 (readiness ignores worker staleness; it is not draining)" $
                -- Readiness gates only on the drain signal, so a stalled worker fails /livez and
                -- never /readyz.
                get "/readyz" `shouldRespondWith` 200

    describe "graceful shutdown -- readiness flip while draining" $
        with drainingApp $ do
            it "fails /readyz with 503 (the LB stops routing new traffic here)" $
                get "/readyz" `shouldRespondWith` 503

            it "keeps /livez at 200 (a draining instance is alive, not unhealthy)" $
                get "/livez" `shouldRespondWith` 200

    describe "graceful shutdown -- going-away header" $ do
        with drainingApp $
            it "stamps Connection: close on a response while draining" $
                -- A keep-alive pool (a client's, or a mesh's) must not reuse a socket
                -- on a closing instance. The header is what tells it to close.
                get "/npm/-/ping"
                    `shouldRespondWith` 200{matchHeaders = ["Connection" <:> "close"]}

        with npmMountApp $
            it "adds no Connection header when not draining" $
                get "/npm/-/ping" `shouldRespondWith` 200{matchHeaders = [matchNoConnectionHeader]}

    describe "meta-routes under a mount" $
        with npmMountApp $ do
            it "answers /npm/-/ping locally with 200 {}" $
                get "/npm/-/ping" `shouldRespondWith` "{}"{matchStatus = 200}

            it "answers /npm/-/v1/search with 501 (search is not an install path)" $
                get "/npm/-/v1/search" `shouldRespondWith` 501

            it "answers a dist-tag read with 501, not the deny-by-default 404" $
                -- A 404 would read as the package being absent. The 501 says the operation
                -- is not implemented, which is what an operator needs to see.
                get "/npm/-/package/is-odd/dist-tags" `shouldRespondWith` 501

            it "answers a dist-tag write with 501, without reading the body" $
                request methodPut "/npm/-/package/is-odd/dist-tags/latest" [] "\"1.0.0\""
                    `shouldRespondWith` 501

            it "answers a dist-tag removal with 501, the same boundary as the write" $
                request methodDelete "/npm/-/package/is-odd/dist-tags/latest" [] ""
                    `shouldRespondWith` 501

            it "still denies a DELETE outside the dist-tag path with the 404" $
                -- The method claims one route, not a class of paths, so a package path
                -- under DELETE stays deny-by-default.
                request methodDelete "/npm/is-odd" [] "" `shouldRespondWith` 404

    describe "dispatch -- /npm mount (prefix strip + npm grammar)" $
        with npmMountApp $ do
            it "accepts the bare mount prefix with a trailing slash (empty path → 404)" $
                get "/npm/" `shouldRespondWith` 404

            it "normalises repeated trailing slashes the same as one (empty path → 404)" $
                -- @/npm//@ collapses its run of trailing empty segments to the bare mount,
                -- exactly like @/npm/@, rather than leaving a spurious empty path component.
                get "/npm//" `shouldRespondWith` 404

            it "leaves an internal empty segment for the router to reject (404, not collapsed)" $
                -- The router drops only /trailing/ empties, so the leading empty segment stays and
                -- @/npm//is-odd@ never normalises to the @/npm/is-odd@ packument route.
                get "/npm//is-odd" `shouldRespondWith` 404

            it "404s an unknown /-/… meta-route under the mount" $
                get "/npm/-/whoami" `shouldRespondWith` 404

            it "404s a hostile traversal path rather than routing it" $
                -- @%2F@ decodes to one segment carrying a slash, so the router denies it.
                get "/npm/foo%2Fbar" `shouldRespondWith` 404

    describe "first-party publish path (PUT /{pkg})" $ do
        with npmMountApp $
            it "405s a publish when no publication target is configured (the opt-in is off)" $
                -- This mount wires no publish dependencies, so there is no implicit write
                -- path. A PUT /{pkg} is Method Not Allowed.
                request methodPut "/npm/widget" [] "" `shouldRespondWith` 405

        with publishMountApp $ do
            it "refuses an out-of-scope publish with 403, before any upstream write (anti-shadowing)" $
                -- Nothing contacts the unconnectable target, so a 403 rather than a 502 proves the
                -- guard fired before the relay.
                request methodPut "/npm/@other/widget" [] "" `shouldRespondWith` 403

            it "refuses an unscoped publish with 403 (an unscoped name is within no scope)" $
                request methodPut "/npm/widget" [] "" `shouldRespondWith` 403

            it "lets an in-scope publish through the guard to the relay (502 when the target is unreachable)" $
                -- The target is unconnectable, so the 502 proves the guard let the write through to
                -- the relay rather than refusing it at the scope check.
                request methodPut "/npm/@acme/widget" [] "" `shouldRespondWith` 502

            -- The body-name agreement leg of the anti-shadowing guard: a relay would otherwise
            -- write a name the scope guard never authorised. The 403 rather than the unconnectable
            -- target's 502 proves the relay never ran.
            it "refuses an in-scope publish whose body _id / name disagree with the URL with 403, before any relay" $
                request methodPut "/npm/@acme/widget" [] "{\"_id\":\"@victim/target\",\"name\":\"@victim/target\",\"versions\":{}}" `shouldRespondWith` 403

            it "refuses an in-scope publish whose body versions[].name disagrees with the URL with 403, before any relay" $
                request methodPut "/npm/@acme/widget" [] "{\"_id\":\"@acme/widget\",\"name\":\"@acme/widget\",\"versions\":{\"1.0.0\":{\"name\":\"@victim/target\",\"version\":\"1.0.0\"}}}" `shouldRespondWith` 403

            -- The wire manifest is the publish path's other name. A declared name the npm grammar
            -- refuses canonicalises to nothing, which is a disagreement, so it never reaches a write.
            it "refuses an in-scope publish whose body declares a non-ASCII name with 403, before any relay" $
                request methodPut "/npm/@acme/widget" [] "{\"_id\":\"@acme/widget\",\"name\":\"@acme/wid\\u3164get\",\"versions\":{}}" `shouldRespondWith` 403

            it "lets an in-scope publish whose body _id / name / versions[].name all agree with the URL through to the relay (502 when unreachable)" $
                -- The guard does not over-refuse a body whose every declared name matches
                -- the URL. It reaches the relay (502 to the unconnectable target), not a 403.
                request methodPut "/npm/@acme/widget" [] "{\"_id\":\"@acme/widget\",\"name\":\"@acme/widget\",\"versions\":{\"1.0.0\":{\"name\":\"@acme/widget\",\"version\":\"1.0.0\"}}}" `shouldRespondWith` 502

        with (publishAppWith (\b -> (basePublishDeps b){pubAdapter = (adapterPublish npmAdapter){publishRelay = \_ _ _ -> throwIO (RelayContractEscape "simulated relay contract escape")}})) $
            it "answers a relay contract escape with the route's declared 500 (not a torn session, not a 502)" $
                -- The relay reports its failures as typed values, so a throw is an invariant break.
                -- The perimeter answers it with the neutral 500 and the session survives.
                request methodPut "/npm/@acme/widget" [] "" `shouldRespondWith` 500

        with (publishAppWith (\b -> (basePublishDeps b){pubTargetUrl = loopbackRegistryUrl ""})) $
            it "500s an in-scope publish when the publication target URL is unformable (misconfig)" $
                -- An empty target URL cannot form a request, a configuration fault rather
                -- than a transient outage, so the publish is a 500 (not a 502).
                request methodPut "/npm/@acme/widget" [] "" `shouldRespondWith` 500

        with (publishAppWith (\b -> (basePublishDeps b){pubInboundToken = Just (mkSecret "edge-token")})) $ do
            it "401s a publish that fails the edge token gate (before the scope guard)" $
                -- With an edge token configured, the edge rejects a publish that carries
                -- none. It is the same gate the read paths apply.
                request methodPut "/npm/@acme/widget" [] "" `shouldRespondWith` 401

    describe "the two response tiers (neutral above mounts, route contract within)" $
        with npmMountApp $ do
            it "renders an UNMOUNTED path as a neutral text/plain 404" $
                -- No mount matches @/pypi/...@, so there is no ecosystem to shape it. The
                -- body is the generic plain-text Not Found, not an npm error object.
                get "/pypi/is-odd" `shouldRespondWith` "Not Found\n"{matchStatus = 404}

            it "renders an unrecognised IN-MOUNT path through npm's fallback contract" $
                -- The body is npm's error object, the mount's own surface, rather than the neutral
                -- plain-text 404 above.
                get "/npm/is-odd/3.0.1" `shouldRespondWith` "{\"error\":\"not found\"}"{matchStatus = 404}

            it "derives a bodiless response for an unrecognised HEAD path" $
                request methodHead "/npm/is-odd/3.0.1" [] ""
                    `shouldRespondWith` ""{matchStatus = 404}

    describe "dispatch -- injected router (the routing boundary)" $
        -- Dispatch runs under a FAKE router, not npm's, so the action a request takes must
        -- follow the injected function.
        with fakeRouterApp $ do
            it "routes the fake router's recognised path (/npm/beep → answered locally → 200 {})" $
                get "/npm/beep" `shouldRespondWith` "{}"{matchStatus = 200}

            it "denies a path npm would accept but the fake does not (/npm/is-odd → 404)" $
                -- Under npm's router @is-odd@ is a packument read, so this 404 proves dispatch
                -- followed the injected function.
                get "/npm/is-odd" `shouldRespondWith` 404

            it "denies npm's ping meta-route (the fake router does not recognise it)" $
                get "/npm/-/ping" `shouldRespondWith` 404

    describe "no mounts -- neutral by default" $
        -- With no mount wired, the web layer serves nothing but the health probes.
        -- Every other path matches no mount and is the neutral 404.
        with neutralApp $ do
            it "404s a package-shaped path (no mount is configured)" $
                get "/npm/is-odd" `shouldRespondWith` "Not Found\n"{matchStatus = 404}

            it "still answers the control-plane health probes (above any mount)" $ do
                get "/livez" `shouldRespondWith` 200
                get "/readyz" `shouldRespondWith` 200

    describe "probeOnlyApplication (the worker roles' front door)" $ do
        with probeOnlyApp $ do
            it "answers /livez with 200" $
                get "/livez" `shouldRespondWith` 200

            it "answers /readyz with 200" $
                get "/readyz" `shouldRespondWith` 200

            it "404s every other path (a worker role serves no mount)" $
                get "/npm/is-odd" `shouldRespondWith` "Not Found\n"{matchStatus = 404}

        with deadProbeOnlyApp $ do
            it "fails /livez with 503 when the injected liveness check fails" $
                get "/livez" `shouldRespondWith` 503

            it "keeps /readyz at 200 (readiness does not read the liveness check)" $
                get "/readyz" `shouldRespondWith` 200

    describe "mkServerConfig -- defaults" $ do
        it "listens on the conventional npm proxy port" $
            scPort (mkServerConfig []) `shouldBe` defaultPort

        it "the default port is 4873" $
            defaultPort `shouldBe` 4873

        it "defaults the graceful-drain timeout to 30 seconds" $
            scDrainTimeout (mkServerConfig []) `shouldBe` defaultShutdownDrainTimeout

        it "the default graceful-drain timeout is 30 seconds" $
            defaultShutdownDrainTimeout `shouldBe` ShutdownDrainTimeout 30

        it "path-mounts a binding under its prefix (never the root)" $
            bindingPrefix (mountAt ("npm" :| []) npmRouter) `shouldBe` "npm" :| []

-- | A typed stand-in for a relay implementation escaping its typed contract.
newtype RelayContractEscape = RelayContractEscape Text
    deriving stock (Show)

instance Exception RelayContractEscape

{- | Drive 'perimeterGuard' over a recording respond and observation channel. Returns
the statuses answered (in order), the classified causes observed, and the guard's own
outcome. A rethrow arrives as 'Left'.
-}
driveGuard :: ((Response -> IO ResponseReceived) -> IO ResponseReceived) -> IO ([Int], [RequestFaultCause], Either SomeException ())
driveGuard handler = do
    responses <- newIORef []
    observed <- newIORef []
    let respond response = do
            modifyIORef' responses (<> [statusCode (responseStatus response)])
            pure ResponseReceived
    outcome <- try (void (perimeterGuard (\fault -> modifyIORef' observed (<> [rqCause fault])) respond fallback handler))
    (,,) <$> readIORef responses <*> readIORef observed <*> pure outcome
  where
    fallback = responseLBS status500 [] "internal server error"

perimeterGuardSpec :: Spec
perimeterGuardSpec = describe "perimeterGuard (the typed request perimeter)" $ do
    it "passes a committed response through untouched, observing nothing" $ do
        (statuses, observed, outcome) <- driveGuard (\respond -> respond (responseLBS status200 [] "ok"))
        statuses `shouldBe` [200]
        observed `shouldBe` []
        outcome `shouldSatisfy` isRight

    it "answers an unrecognised pre-commit escape with the neutral 500, observed as UnclassifiedFault" $ do
        (statuses, observed, _) <- driveGuard (\_respond -> throwIO (RelayContractEscape "boom"))
        statuses `shouldBe` [500]
        observed `shouldBe` [UnclassifiedFault]

    it "rethrows a post-commit escape: one response, nothing observed, the fault propagates" $ do
        (statuses, observed, outcome) <- driveGuard $ \respond -> do
            received <- respond (responseLBS status200 [] "committed")
            _ <- throwIO (RelayContractEscape "post-commit teardown")
            pure received
        statuses `shouldBe` [200]
        observed `shouldBe` []
        case outcome of
            Left escape -> fmap (\(RelayContractEscape detail) -> detail) (fromException escape) `shouldBe` Just "post-commit teardown"
            Right () -> expectationFailure "expected the post-commit escape to rethrow"

{- | A control-flow abort the application builder raises the instant it receives its
config, so 'runWarp' unwinds before @warp@ binds a socket.
-}
data AbortLaunch = AbortLaunch
    deriving stock (Eq, Show)

instance Exception AbortLaunch

{- | Pin the 'runWarp' drain wiring: it must hand the application builder the live
'DrainSignal', not the inert 'neverDraining' a bare 'mkServerConfig' carries. Every other
draining spec sets 'scDrain' by hand, so this is the only one exercising 'runWarp''s
allocate-then-build path.
-}
runWarpDrainWiringSpec :: Spec
runWarpDrainWiringSpec = describe "runWarp -- graceful-drain wiring (issue #841)" $
    it "hands the application builder the live drain, not the inert neverDraining" $ do
        captured <- newEmptyMVar
        -- The scDrain from mkServerConfig is neverDraining, so an app closed over that inert
        -- signal would never see a drain. Abort before warp binds a socket.
        let getApp cfg = putMVar captured (scDrain cfg) >> throwIO AbortLaunch
        runWarp (mkServerConfig []) getApp `shouldThrow` (== AbortLaunch)
        drain <- takeMVar captured
        -- A live, lowered signal: raising it is observable. neverDraining's raise is a
        -- no-op, so an inert signal would stay False where this one flips True.
        isDraining drain `shouldReturn` False
        beginDrain drain
        isDraining drain `shouldReturn` True

{- | A typed fault thrown from one arm of 'raceServerAgainstLoop', to assert the race
re-raises it (fails the process up) rather than swallowing it.
-}
newtype RaceBoom = RaceBoom Text
    deriving stock (Eq, Show)

instance Exception RaceBoom

{- | Pin the shutdown-race invariant 'raceServerAgainstLoop' carries. The server arm's
return must cancel the never-returning loop, and a fault from either arm must re-raise.
-}
raceServerAgainstLoopSpec :: Spec
raceServerAgainstLoopSpec = describe "raceServerAgainstLoop -- shutdown-race invariant (issue #842)" $ do
    it "returns when the server arm returns, cancelling the never-returning loop" $ do
        -- A `concurrently_` would keep waiting on the never-returning loop and time out. Under
        -- `race_` the server's return cancels it, so the loop's `finally` cleanup runs.
        cancelled <- newIORef False
        let server = pass
            loop = forever (threadDelay 1_000_000) `finally` writeIORef cancelled True
        outcome <- timeout 2_000_000 (raceServerAgainstLoop server loop)
        outcome `shouldBe` Just ()
        readIORef cancelled `shouldReturn` True

    it "re-raises a fault thrown by the server arm (fails the process up)" $ do
        let server = throwIO (RaceBoom "server")
            loop = forever (threadDelay 1_000_000)
        raceServerAgainstLoop server loop `shouldThrow` (== RaceBoom "server")

    it "re-raises a fault thrown by the loop arm (fails the process up)" $ do
        let server = forever (threadDelay 1_000_000)
            loop = throwIO (RaceBoom "loop")
        raceServerAgainstLoop server loop `shouldThrow` (== RaceBoom "loop")
