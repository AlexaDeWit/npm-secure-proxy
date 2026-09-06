-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT
-- TupleSections: pairing a matched mount with its router's verdict on the remainder
-- in 'matchMount' ((mount,) . router). See STYLE.md §2.
{-# LANGUAGE TupleSections #-}

{- | The HTTP front door: the raw @wai@ 'Application', its dispatch, the
meta-routes, the middleware stack, and 'runServer'.

The proxy is a passthrough over a small, irregular URL surface, so the front door
is a raw 'Application' rather than a web framework. Matching on @pathInfo@ keeps the
encoded-slash handling and the streaming control the proxy depends on (see
@docs\/architecture\/web-layer.md@). Routing is two layers:

* __Mount dispatch__: match a request's leading path segments to a configured
  'MountBinding' and strip the prefix. That mount's
  'Ecluse.Core.Server.Context.MountRouter' then takes the remainder, an
  ecosystem-native path. A binding carries a
  mount's __complete__ ecosystem wiring: its router and serve dependencies. The web
  layer is closed over the agnostic 'Ecluse.Core.Server.Context.RouteAction'
  vocabulary and holds no ecosystem's path grammar or body shape of its own. Every
  registry is __path-mounted__ (e.g. @\/npm@). There is no root mount, so adding an
  ecosystem never changes an existing consumer's URLs. A mount prefix is accepted
  with or without a trailing slash (see @docs\/architecture\/web-layer.md@ →
  "Multi-ecosystem mounts").

Responses split into __two tiers__:

* __Above the mounts, neutral and server-owned.__ The top level answers the
  orchestration health probes (@\/livez@, @\/readyz@). A path matching __no__
  configured mount is a generic @404 Not Found@ in @text\/plain@: there is no
  ecosystem to shape it.

* __Within a matched mount.__ The mount's router
  ('Ecluse.Core.Server.Context.MountRouter', supplied by its ecosystem adapter) says what
  the request names, as an 'Ecluse.Core.Server.Context.RouteAction'. That action is a
  route-scoped response contract. It pairs existentially with either a pure response
  value or a data-plane handler that can produce only that value type.

This module holds __no route knowledge of its own__. It does not name a route, a path
grammar, or a status. It asks the matched mount's router for an action, then either
responds with it or runs it under the request perimeter. Adding an ecosystem adds a
router and changes nothing here.

Cross-cutting concerns are middleware composed around the 'Application' (see
@docs\/architecture\/web-layer.md@ → "Middleware"): correct client-IP recovery behind
a load balancer, and a request timeout. The request-body cap is not cross-cutting. It
is a route concern, enforced at the read site by the only body-consuming route
(publish). The middleware pieces and the health probes live in
"Ecluse.Runtime.Server.Middleware", the graceful-shutdown drain vocabulary in
"Ecluse.Runtime.Server.Drain", and the local-dev quit key in
"Ecluse.Runtime.Server.Halt". This module composes them and re-exports their surface.
Dispatch builds a per-request 'Ecluse.Core.Server.Context.RequestCtx': the request
runtime ('serveRuntimeOf') paired with the matched 'MountBinding'. The effectful
routes run in the 'Ecluse.Core.Server.Context.Handler' reader over it. A handler
therefore reads its mount's wiring and the request runtime from context, not from
threaded arguments.
-}
module Ecluse.Runtime.Server (
    -- * The WAI application
    ServerConfig (..),
    mkServerConfig,
    defaultPort,
    MountBinding (..),
    application,
    tracedApplication,

    -- * Running the server
    runWarp,
    raceServerAgainstLoop,
    probeApplication,
    probeOnlyApplication,

    -- * The typed request perimeter
    perimeterGuard,

    -- * Graceful shutdown
    DrainSignal,
    newDrainSignal,
    neverDraining,
    beginDrain,
    isDraining,
    ShutdownDrainTimeout (..),
    defaultShutdownDrainTimeout,

    -- * Local-dev immediate halt
    InteractiveHalt (..),
    defaultInteractiveHalt,
    withInteractiveHalt,

    -- * Middleware
    serverMiddleware,
) where

import Data.List (dropWhileEnd)
import Katip (Severity (ErrorS), katipAddContext, logFM, sl)
import Network.HTTP.Types (Method, status500)
import Network.HTTP.Types.Header (RequestHeaders)
import Network.Wai (Application, Middleware, Request, Response, ResponseReceived, pathInfo, rawPathInfo, requestHeaders, requestMethod)
import Network.Wai.Handler.Warp qualified as Warp
import Network.Wai.Middleware.RealIp (realIp)
import Network.Wai.Middleware.Timeout (timeout)
import System.Posix.Signals (Handler (CatchOnce), installHandler, sigINT, sigTERM)
import UnliftIO (MonadUnliftIO)
import UnliftIO.Async (race_)
import UnliftIO.Exception (catchAny, throwIO)

import Ecluse.Core.Server.Context (
    MountBinding (..),
    RequestCtx (RequestCtx),
    ResponseAction (AnswerLocally, AnswerRefusal, RunPipeline),
    RouteAction (RouteAction),
    ServeRuntime (srMetrics),
    pdHelp,
    runHandler,
 )
import Ecluse.Core.Server.Contract (responseToWai)
import Ecluse.Core.Server.Fault (RequestFault (rqCause, rqDetail), classifyEscape)
import Ecluse.Core.Telemetry.Record (MetricsPort (mpRequestPerimeterFault))
import Ecluse.Core.Worker (Liveness, alwaysLive)
import Ecluse.Runtime.Env (Env, envDdContext, envLogEnv, envTelemetry, serveRuntimeOf)
import Ecluse.Runtime.Server.Drain (
    DrainSignal,
    ShutdownDrainTimeout (..),
    beginDrain,
    defaultShutdownDrainTimeout,
    isDraining,
    neverDraining,
    newDrainSignal,
 )
import Ecluse.Runtime.Server.Halt (
    InteractiveHalt (..),
    defaultInteractiveHalt,
    withInteractiveHalt,
 )
import Ecluse.Runtime.Server.Middleware (
    goingAwayMiddleware,
    jsonResponse,
    probeApplication,
    timeoutSeconds,
 )
import Ecluse.Runtime.Telemetry.Correlation (ddPayloadNow)
import Ecluse.Runtime.Telemetry.Tracing (telemetryWaiMiddleware)

{- | The settings the web layer needs to serve that the composition-root 'Env' does not
carry. The request-body cap is not here: the publish route bounds its own body against
'Ecluse.Core.Server.Context.pubMaxRequestBytes'.
-}
data ServerConfig = ServerConfig
    { scPort :: Int
    -- ^ The TCP port @warp@ listens on.
    , scMounts :: [MountBinding]
    {- ^ The mounts served. The first whose prefix matches the request's leading segments
    wins, and a path under no mount is the neutral @404@.
    -}
    , scDrain :: DrainSignal
    {- ^ The shutdown-drain flag the front door observes. Once raised, the readiness probe
    fails and every response carries @Connection: close@. Defaults to 'neverDraining'.
    -}
    , scDrainTimeout :: ShutdownDrainTimeout
    {- ^ How long the graceful drain waits for in-flight requests and in-progress
    artifact streams to finish before the process exits ('defaultShutdownDrainTimeout').
    -}
    , scCheckReady :: IO Bool
    {- ^ A second readiness gate the composition root installs, ANDed with the drain check by
    @\/readyz@. It must be a one-way flip (today the advisory database's first sync), so readiness
    never flaps a pod out of rotation. It gates routing, not whether the process answers.
    -}
    , scCheckLive :: IO Liveness
    {- ^ The liveness check @\/livez@ answers from, beyond the listener itself. A worker
    heartbeat is wired here only when a worker runs, so a serve-only deployment stays live.
    -}
    , scOnException :: Maybe Request -> SomeException -> IO ()
    {- ^ @warp@'s exception hook, for a post-commit escape the request perimeter rethrew or a
    fault in warp's own connection handling. The 'mkServerConfig' default is inert.
    -}
    }

{- | Build a 'ServerConfig' over the given mount bindings, taking the default listen port
('defaultPort'). There is no built-in mount: the web layer serves only the ecosystems the
composition root binds here.
-}
mkServerConfig :: [MountBinding] -> ServerConfig
mkServerConfig mounts =
    ServerConfig
        { scPort = defaultPort
        , scMounts = mounts
        , scDrain = neverDraining
        , scDrainTimeout = defaultShutdownDrainTimeout
        , scCheckReady = pure True
        , scCheckLive = pure alwaysLive
        , scOnException = \_ _ -> pass
        }

-- | The conventional npm proxy listen port (4873), the 'mkServerConfig' default.
defaultPort :: Int
defaultPort = 4873

{- | The proxy's WAI 'Application': the request dispatch under the cross-cutting
middleware stack ('serverMiddleware').
-}
application :: ServerConfig -> Env -> Application
application cfg env = serverMiddleware cfg (dispatch cfg env)

{- | The WAI 'Application' of a role that serves the health probes and nothing else. Every
path outside @\/livez@ and @\/readyz@ is the neutral @404@.
-}
probeOnlyApplication :: ServerConfig -> IO Application
probeOnlyApplication cfg =
    pure (serverMiddleware cfg (probeApplication (scDrain cfg) (scCheckReady cfg) (scCheckLive cfg)))

{- | 'application' with the OpenTelemetry server-span middleware wrapped __outermost__, so
one server span covers the whole request. The wrapper is 'id' when telemetry is off.
-}
tracedApplication :: ServerConfig -> Env -> IO Application
tracedApplication cfg env = do
    traceMiddleware <- telemetryWaiMiddleware (envTelemetry env)
    pure (traceMiddleware (application cfg env))

{- Route a request: the first matching mount wins, and every other path falls to the
health probes, which answer @\/livez@ and @\/readyz@ and give the rest the neutral @404@.
-}
dispatch :: ServerConfig -> Env -> Application
dispatch cfg env request respond =
    case matchMount (requestMethod request) (requestHeaders request) (scMounts cfg) (pathInfo request) of
        Just (binding, action) -> serve env binding action request respond
        Nothing -> probeApplication (scDrain cfg) (scCheckReady cfg) (scCheckLive cfg) request respond

{- Carry out the action the matched mount's router named. A 'RunPipeline' action runs
under the typed request perimeter, over the 'RequestCtx' this function builds once.
-}
serve :: Env -> MountBinding -> RouteAction -> Request -> (Response -> IO ResponseReceived) -> IO ResponseReceived
serve env binding (RouteAction contract action) request respond =
    case action of
        AnswerLocally answer -> send answer
        -- This is where a route's own refusal meets the mount's help message: the table decides
        -- the refusal, and the binding beside it renders the body.
        AnswerRefusal render -> send (render (pdHelp (bindingPackumentDeps binding)))
        RunPipeline fallback handler -> perimeterGuard observeFault send fallback (run . handler request)
  where
    send value = respond (responseToWai contract value)

    observeFault fault = do
        mpRequestPerimeterFault (srMetrics runtime) (rqCause fault)
        run . katipAddContext (perimeterPayload fault) $
            logFM ErrorS "the request perimeter answered an escaped pre-commit fault with the neutral 500"

    -- The fields mirror the denial audit line, so an operator triages both surfaces with one
    -- vocabulary.
    perimeterPayload fault =
        sl "module" ("Ecluse.Runtime.Server" :: Text)
            <> sl "path" (decodeUtf8 (rawPathInfo request) :: Text)
            <> sl "perimeterCause" (show (rqCause fault) :: Text)
            <> sl "perimeterDetail" (rqDetail fault)

    -- Discharge a 'Handler' to 'IO' over the per-request context. Resolving @dd@ here is what
    -- makes every serve-path log line carry its trace correlation.
    run handlerAction = do
        dd <- ddPayloadNow (envDdContext env)
        runHandler (envLogEnv env) dd ctx handlerAction

    runtime :: ServeRuntime
    runtime = serveRuntimeOf env

    ctx :: RequestCtx
    ctx = RequestCtx runtime binding

{- | Run one route's handler behind a commit-tracking respond, catching __synchronous__
escapes only. Asynchronous cancellation tears the request down like any other thread.

Pre-commit, the perimeter classifies the escape, hands it to the observation channel, and
answers the route's neutral fallback, so no fault detail ever reaches the client.
Post-commit there is no second response to give: the escape rethrows and 'scOnException'
logs it.
-}
perimeterGuard ::
    -- | Observe a classified pre-commit fault (the metric and the audit line).
    (RequestFault -> IO ()) ->
    -- | The route-scoped response continuation.
    (response -> IO ResponseReceived) ->
    -- | The route's declared neutral pre-commit fallback.
    response ->
    -- | The route's handler, discharged to 'IO', awaiting the tracked respond.
    ((response -> IO ResponseReceived) -> IO ResponseReceived) ->
    IO ResponseReceived
perimeterGuard observeFault respond fallback handlerOn = do
    committed <- newIORef False
    let respondCommitted response = do
            atomicWriteIORef committed True
            respond response
    handlerOn respondCommitted `catchAny` \escape -> do
        wasCommitted <- readIORef committed
        if wasCommitted
            then throwIO escape
            else do
                observeFault (classifyEscape escape)
                respond fallback

{- Match a request path to a mount: the first binding whose prefix the path begins with,
paired with the action its router names for the remainder. A prefix matches with or
without a trailing slash, so @\/npm\/pkg@ and a bare @\/npm@ both hit the @\/npm@ mount.
-}
matchMount :: Method -> RequestHeaders -> [MountBinding] -> [Text] -> Maybe (MountBinding, RouteAction)
matchMount method headers mounts segments = asum (map match mounts)
  where
    {- The method is part of the mapping: the npm router tells a @PUT@ publish from a @GET@
    read over the same path, and a @HEAD@ from the @GET@ it varies. The headers are too: a
    route serving one media type refuses a client that admits no such thing. -}
    match :: MountBinding -> Maybe (MountBinding, RouteAction)
    match binding =
        (binding,) . bindingRouter binding method headers
            <$> stripPrefixSegments (toList (bindingPrefix binding)) segments

{- Strip a mount's prefix segments off the front of a request path. The root mount (an
empty prefix) consumes nothing and always matches.
-}
stripPrefixSegments :: [Text] -> [Text] -> Maybe [Text]
stripPrefixSegments [] segs = Just (dropTrailingSlashes segs)
stripPrefixSegments (p : ps) (s : ss)
    | p == s = stripPrefixSegments ps ss
stripPrefixSegments _ _ = Nothing

-- A trailing slash arrives as an empty final segment (@\/npm\/@ as @["npm",""]@). An
-- internal empty segment is left untouched for the router to reject.
dropTrailingSlashes :: [Text] -> [Text]
dropTrailingSlashes = dropWhileEnd (== "")

{- | The cross-cutting middleware stack composed around the proxy 'Application': client-IP
recovery behind a load balancer (@X-Forwarded-For@ \/ @X-Real-IP@), a per-request timeout,
and the going-away header. While the drain is raised that header stamps @Connection:
close@, so a keep-alive pool stops reusing a socket into an instance that is shutting down
(@docs\/architecture\/web-layer.md@).

The request-body cap is __not__ a middleware. A middleware would have to throw across the
request perimeter, so the publish route bounds its own body as a value
('Ecluse.Core.Server.Pipeline.Publish').

@wai-extra@'s @Autohead@ and @Gzip@ stay out on purpose. @Autohead@ would answer a HEAD by
running the GET handler, streaming a whole tarball to nowhere, and @Gzip@ would re-compress
artifacts and fight the streaming backpressure the serve path relies on.
-}
serverMiddleware :: ServerConfig -> Middleware
serverMiddleware cfg =
    realIp
        . timeout timeoutSeconds
        . goingAwayMiddleware (scDrain cfg)

{- | Serve the proxy's HTTP front door. This allocates the launch's live 'DrainSignal' and
hands the builder a 'ServerConfig' carrying it, so the readiness probe and the going-away
middleware read the same drain the shutdown handler raises.

@warp@ stops accepting on that signal and waits for in-flight requests and in-progress
artifact streams, bounded by 'scDrainTimeout'.

Attached to an interactive terminal, 'withInteractiveHalt' also makes Ctrl-D force an
immediate halt, bypassing the drain. Outside a TTY it installs nothing.
-}
runWarp :: ServerConfig -> (ServerConfig -> IO Application) -> IO ()
runWarp cfg0 getApp = do
    drain <- newDrainSignal
    let cfg = cfg0{scDrain = drain}
        ShutdownDrainTimeout timeoutSecs = scDrainTimeout cfg
        settings =
            Warp.setPort (scPort cfg)
                . Warp.setInstallShutdownHandler (installShutdownHandler drain)
                . Warp.setGracefulShutdownTimeout (Just timeoutSecs)
                . Warp.setOnException (scOnException cfg)
                -- Defence in depth for a fault with no mount context, from a middleware or warp
                -- itself: a neutral JSON 500 carrying no exception detail. A handler escape answers
                -- through the request perimeter instead and never reaches here.
                . Warp.setOnExceptionResponse (const onExceptionResponse)
                $ Warp.defaultSettings
    app <- getApp cfg
    withInteractiveHalt defaultInteractiveHalt (Warp.runSettings settings app)

-- The neutral response for a fault that escapes to warp's own handler (see 'runWarp'):
-- a deny-shaped 500 carrying no exception detail.
onExceptionResponse :: Response
onExceptionResponse = jsonResponse status500 "{\"error\":\"internal server error\"}"

{- On @SIGTERM@ or @SIGINT@, raise the drain before closing the listen socket, so
readiness fails and responses carry @Connection: close@ before @warp@ stops accepting.
'CatchOnce' leaves a second signal to the runtime default, which hard-stops a slow drain.
-}
installShutdownHandler :: DrainSignal -> IO () -> IO ()
installShutdownHandler drain closeSocket =
    traverse_ install [sigTERM, sigINT]
  where
    install sig = installHandler sig (CatchOnce (beginDrain drain >> closeSocket)) Nothing

{- | Race a server arm against a never-returning background loop, the shutdown shape the
single-process composition roots share.

'race_' rather than 'concurrently_' is the invariant: the loop never returns, so
'concurrently_' would keep waiting after the server drained and leave the surrounding
telemetry and resource brackets un-unwound, with no exporter flush. A fault from either arm
still propagates.
-}
raceServerAgainstLoop :: (MonadUnliftIO m) => m () -> m () -> m ()
raceServerAgainstLoop = race_
