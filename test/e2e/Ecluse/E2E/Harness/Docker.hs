-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.E2E.Harness.Docker (
    e2eUnavailable,
    withGlobalDataPlane,
    withE2E,
    withE2EWith,

    -- * Telemetry topology
    collectorOtlpEndpoint,
    otlpCollectorEnv,
    datadogCollectorEnv,
    ddTagService,
    ddTagEnv,
    ddTagVersion,

    -- * Observability
    withUpstreamPaused,

    -- * The Dredger, run to completion
    DredgerRun (..),
    runDredgerOnce,

    -- * Container logs
    awaitContainerLog,
    containerLogs,

    -- * Utilities
    uniqueSuffix,
) where

import Data.ByteString.Lazy qualified as LBS
import Data.Text qualified as T
import Data.Time.Clock.POSIX (getPOSIXTime)
import Network.HTTP.Client (
    Manager,
    Request (method),
    Response,
    defaultManagerSettings,
    httpLbs,
    newManager,
    parseRequest,
    responseBody,
    responseStatus,
 )
import Network.HTTP.Types (statusCode)
import Network.Socket (
    Family (AF_INET),
    SockAddr (SockAddrInet),
    SocketType (Stream),
    bind,
    close,
    defaultProtocol,
    getSocketName,
    socket,
    tupleToHostAddress,
 )
import System.Directory (createDirectoryIfMissing, getTemporaryDirectory, removePathForcibly)
import System.Exit (ExitCode (ExitSuccess))
import System.FilePath ((</>))
import System.Process.Typed (proc, readProcess, readProcessStdout)
import UnliftIO (bracket, bracket_, handleAny)

import Ecluse.E2E.Fixtures (buildFixtures, fixturePackages)
import Ecluse.E2E.Harness.Types
import Ecluse.Test.Container.Image (
    ImageRef (LocallyBuilt, PinnedExternal),
    PinnedImageRef,
    collectorImage,
    ministackImage,
    nginxImage,
    renderImageRef,
    verdaccioImage,
 )
import Ecluse.Test.Containers (dockerLabelArgs)
import Ecluse.Test.Poll (pollUntil)

{- | 'Nothing' when the suite can run. @Just reason@ when it must skip: no docker daemon,
or @ECLTEST_E2E_IMAGE@ unset. @task test-e2e@ and the CI e2e job build and name the image.
-}
e2eUnavailable :: IO (Maybe String)
e2eUnavailable = do
    useExisting <- lookupEnv "ECLTEST_E2E_USE_EXISTING"
    case useExisting of
        Just "1" -> pure Nothing
        _ ->
            lookupEnv imageVar >>= \case
                Nothing -> pure (Just (imageVar <> " is unset -- run via `task test-e2e`"))
                Just "" -> pure (Just (imageVar <> " is empty -- run via `task test-e2e`"))
                Just _ -> do
                    ok <- dockerDaemonReachable
                    pure (if ok then Nothing else Just "no reachable docker daemon")

imageVar :: String
imageVar = "ECLTEST_E2E_IMAGE"

dockerDaemonReachable :: IO Bool
dockerDaemonReachable =
    handleAny (\_ -> pure False) (exitOk <$> readProcess (proc "docker" ["info"]))

{- | Build the shared fixture tree in a per-run temp directory, then remove it on every
exit path. The name is unique per run, so two worktrees never share or delete fixtures.
-}
withFixtureDir :: (FilePath -> IO a) -> IO a
withFixtureDir = bracket acquire (handleAny (const pass) . removePathForcibly)
  where
    acquire = do
        tmpRoot <- getTemporaryDirectory
        sfx <- uniqueSuffix
        let workDir = tmpRoot </> ("ecluse-e2e-fixtures-" <> sfx)
            htmlDir = workDir </> "html"
        createDirectoryIfMissing True htmlDir
        buildFixtures htmlDir fixturePackages
        writeFileText (workDir </> "verdaccio.yaml") verdaccioConfig
        writeFileText (workDir </> "nginx.conf") nginxStubConfig
        generateCerts (workDir </> "certs")
        pure workDir

withGlobalDataPlane :: (GlobalDataPlane -> IO ()) -> IO ()
withGlobalDataPlane action = do
    useExisting <- lookupEnv "ECLTEST_E2E_USE_EXISTING"
    case useExisting of
        Just "1" -> do
            -- Local development escape hatch: use existing ports on localhost.
            action GlobalDataPlane{gdpNet = "", gdpStub = "upstream", gdpVerd = "verdaccio", gdpMini = "ministack", gdpVerdPort = 4873, gdpMiniPort = 4566, gdpWorkDir = ""}
        _ -> do
            sfx <- uniqueSuffix
            -- Every container and the network carries the reaping labels, so `task test-clean` can
            -- sweep a run that is hard-killed past these brackets (see "Ecluse.Test.Containers").
            labelArgs <- dockerLabelArgs "e2e"
            withFixtureDir $ \workDir -> do
                -- Resolve each pin up front, so an unvalidated one aborts the suite before any
                -- pull. A tag can be re-pointed at a poisoned image, a digest cannot.
                verdImage <- pinnedExternal verdaccioImage
                stubImage <- pinnedExternal nginxImage
                miniImage <- pinnedExternal ministackImage
                let net = "ecluse-e2e-global-net-" <> sfx
                    verd = "ecluse-e2e-global-verd-" <> sfx
                    stub = "ecluse-e2e-global-stub-" <> sfx
                    mini = "ecluse-e2e-global-mini-" <> sfx
                    verdRun =
                        (dockerRun verd net verdImage)
                            { drAliases = ["verdaccio"]
                            , drPorts = ["127.0.0.1:0:4873"]
                            , drMounts = [(workDir </> "verdaccio.yaml", "/verdaccio/conf/config.yaml:ro")]
                            }
                    -- One nginx terminates TLS for every registry stub, so it answers to three
                    -- in-network aliases (`upstream`, `mirror`, and `private-upstream`). The raw
                    -- docker CLI supports that multi-alias and testcontainers 0.5.3.0 does not.
                    stubRun =
                        (dockerRun stub net stubImage)
                            { drAliases = ["upstream", "mirror", "private-upstream"]
                            , drMounts =
                                [ (workDir </> "html", "/usr/share/nginx/html:ro")
                                , (workDir </> "nginx.conf", "/etc/nginx/conf.d/default.conf:ro")
                                , (workDir </> "certs", "/certs:ro")
                                ]
                            }
                    miniRun =
                        (dockerRun mini net miniImage)
                            { drAliases = ["ministack"]
                            , drPorts = ["127.0.0.1:0:4566"]
                            }
                -- RFC 5737 TEST-NET-3: an external-looking range the egress guard never blocks (see
                -- "Ecluse.Core.Security.Host"). The real image runs with no production escape
                -- hatch.
                withDockerNetwork labelArgs net ["--subnet", "203.0.113.0/24"] $ \_ ->
                    withDockerContainer labelArgs verdRun $ \_ ->
                        withDockerContainer labelArgs stubRun $ \_ ->
                            withDockerContainer labelArgs miniRun $ \_ -> do
                                miniPort <- publishedPort mini "4566/tcp"
                                verdPort <- publishedPort verd "4873/tcp"
                                action GlobalDataPlane{gdpNet = net, gdpStub = stub, gdpVerd = verd, gdpMini = mini, gdpVerdPort = verdPort, gdpMiniPort = miniPort, gdpWorkDir = workDir}

{- | Bring a proxy up on the shared data plane, wait for readiness, run the action, then
tear it down on every exit path. Plain topology ('defaultE2EConfig'), with no collector.
-}
withE2E :: (E2E -> IO ()) -> GlobalDataPlane -> IO ()
withE2E = withE2EWith defaultE2EConfig

{- | 'withE2E' parameterised by an 'E2EConfig', layering extra proxy environment. It may
stand up an OTLP collector at @otelcol@, up before the proxy so no export is missed.
-}
withE2EWith :: E2EConfig -> (E2E -> IO ()) -> GlobalDataPlane -> IO ()
withE2EWith cfg action gdp = do
    useExisting <- lookupEnv "ECLTEST_E2E_USE_EXISTING"
    case useExisting of
        Just "1" -> do
            manager <- newManager defaultManagerSettings
            let base = "http://127.0.0.1:4873"
            action
                E2E
                    { e2eRegistry = base <> "/npm/"
                    , e2eBaseUrl = base
                    , e2eVerdaccio = "http://127.0.0.1:4874" -- Assuming local verdaccio is on 4874 in local dev
                    , e2eStubContainer = gdpStub gdp
                    , e2eProxyContainer = "ecluse-proxy" -- Placeholder for local dev
                    , e2eCollectorContainer = if ecCollector cfg then Just "otelcol" else Nothing
                    , e2eManager = manager
                    }
        _ -> do
            image <- maybe (fail (imageVar <> " unset")) pure =<< lookupEnv imageVar
            sfx <- uniqueSuffix
            labelArgs <- dockerLabelArgs "e2e"
            let net = gdpNet gdp
                stub = gdpStub gdp
                prox = "ecluse-e2e-proxy-" <> sfx
                coll = "ecluse-e2e-otelcol-" <> sfx
                certsDir = gdpWorkDir gdp </> "certs"
            withOptionalCollector cfg labelArgs net coll $ \collectorName -> do
                manager <- newManager defaultManagerSettings
                -- The proxy routes to ministack via AWS_ENDPOINT_URL_SQS and matches the queue by
                -- its path, so this URL's host (ministack's own `localhost:4566`) is immaterial.
                let queueName = "ecluse-e2e-queue-" <> T.pack sfx
                queueUrl <- createMinistackQueue manager (gdpMiniPort gdp) queueName
                -- Pick the host port up front: ECLUSE_SERVER__PUBLIC_URL must be known before the
                -- container starts, and it makes the proxy rewrite dist.tarball to an absolute URL.
                proxyPort <- freeHostPort
                -- The product image is built by `task test-e2e` or the CI e2e job, never pulled, so
                -- it is 'LocallyBuilt' and unpinned: the pin invariant covers only registry pulls.
                -- The test CA bundle it trusts (SSL_CERT_FILE in 'proxyEnv') is bind-mounted from
                -- the certs dir.
                let proxRun =
                        (dockerRun prox net (LocallyBuilt (toText image)))
                            { drPorts = ["127.0.0.1:" <> show proxyPort <> ":4873"]
                            , drMounts = [(certsDir, "/certs:ro")]
                            , drEnv = proxyEnv proxyPort queueUrl <> ecExtraEnv cfg
                            }
                withDockerContainer labelArgs proxRun $ \_ -> do
                    let verdPort = gdpVerdPort gdp
                        base = "http://127.0.0.1:" <> show proxyPort
                        e2e =
                            E2E
                                { e2eRegistry = base <> "/npm/"
                                , e2eBaseUrl = base
                                , e2eVerdaccio = "http://127.0.0.1:" <> show verdPort
                                , e2eStubContainer = stub
                                , e2eProxyContainer = prox
                                , e2eCollectorContainer = collectorName
                                , e2eManager = manager
                                }
                    ready <- waitFor manager (base <> "/readyz") 200
                    unless ready (fail "proxy did not become ready on /readyz within the timeout")
                    action e2e

{- | The proxy's environment, given the published host port and the ministack mirror queue
URL. @ECLUSE_SERVER__PUBLIC_URL@ is the host-loopback address npm reaches the proxy on.
-}
proxyEnv :: Int -> Text -> [(Text, Text)]
proxyEnv hostPort queueUrl =
    [ ("ECLUSE_SERVER__PORT", "4873")
    , -- ECLUSE_SERVER__PUBLIC_URL is the proxy's own client-facing URL (for dist.tarball
      -- rewriting), not a registry-egress target, so it stays http on host loopback.
      ("ECLUSE_SERVER__PUBLIC_URL", "http://127.0.0.1:" <> show hostPort)
    , -- The registry endpoints are https-only by construction: an nginx terminator with
      -- the test cert serves the upstream and mirror stubs over TLS. SSL_CERT_FILE below
      -- extends the proxy image's trust store with the test CA, the documented internal-CA
      -- operator workflow.
      ("ECLUSE_MOUNTS__NPM__PRIVATE_UPSTREAM__VERDACCIO__URL", "https://mirror/")
    , ("ECLUSE_MOUNTS__NPM__PUBLIC_UPSTREAM__REGISTRY__URL", "https://upstream/")
    , ("ECLUSE_MOUNTS__NPM__MIRROR_TARGET__VERDACCIO__URL", "https://mirror/")
    , ("ECLUSE_MOUNTS__NPM__MIRROR_TARGET__VERDACCIO__TOKEN", "e2e-publish-token")
    , ("SSL_CERT_FILE", "/certs/bundle.pem")
    , ("ECLUSE_QUEUE__URL", queueUrl)
    , -- The production endpoint override (AWS-SDK-standard), aimed at the ministack
      -- alias. The dummy keys sign the request the emulator does not validate.
      ("AWS_ENDPOINT_URL_SQS", "http://ministack:4566")
    , ("AWS_REGION", "us-east-1")
    , ("AWS_ACCESS_KEY_ID", "test")
    , ("AWS_SECRET_ACCESS_KEY", "test")
    , ("ECLUSE_OBSERVABILITY__LOG_FORMAT", "json")
    , -- Add DenyInstallTimeExecution so the deny scenario has a rule to fire. This policy
      -- also disables 'min-age' from the opinionated default policy, which would otherwise
      -- block the e2e test's freshly-created test packages.
      ("ECLUSE_RULES", "{\"min-age\":{\"type\":\"AllowIfOlderThan\",\"ageSeconds\":0},\"deny-install-scripts\":{\"type\":\"DenyInstallTimeExecution\"}}")
    ]

{- | A detached test container's @docker run@ specification: everything that varies between
the harness's containers, so every creation site shares one builder and one bracket.
-}
data DockerRun = DockerRun
    { drName :: String
    -- ^ The @--name@, and how the log\/pause helpers address the container later.
    , drNetwork :: String
    -- ^ The network to join (@--network@).
    , drAliases :: [String]
    -- ^ In-network aliases (@--network-alias@, repeatable).
    , drPorts :: [String]
    -- ^ @-p@ publish specs, e.g. @"127.0.0.1:0:4873"@.
    , drMounts :: [(FilePath, String)]
    -- ^ @-v@ bind mounts as @(hostPath, "containerPath[:ro]")@.
    , drEnv :: [(Text, Text)]
    -- ^ @-e@ environment.
    , drImage :: String
    -- ^ The image reference, already rendered to the string @docker@ receives.
    , drCmd :: [String]
    -- ^ Arguments after the image, overriding the default CMD. Usually empty.
    }

{- | Unwrap a validated pin into an 'ImageRef', failing the suite at harness startup rather
than at the pull if the literal is not digest-pinned.
-}
pinnedExternal :: Either Text PinnedImageRef -> IO ImageRef
pinnedExternal = fmap PinnedExternal . either (fail . toString) pure

{- | The base 'DockerRun' for a named container on a network. The image is an 'ImageRef', so
a pulled image is digest-pinned by construction and only 'LocallyBuilt' may be unpinned.
-}
dockerRun :: String -> String -> ImageRef -> DockerRun
dockerRun name net image =
    DockerRun
        { drName = name
        , drNetwork = net
        , drAliases = []
        , drPorts = []
        , drMounts = []
        , drEnv = []
        , drImage = toString (renderImageRef image)
        , drCmd = []
        }

{- | Render and run a 'DockerRun' detached (@docker run --rm -d@), stamped with the reaping
labels. It fails the test loudly on a non-zero exit.
-}
runDetached :: [String] -> DockerRun -> IO ()
runDetached labelArgs spec =
    dockerOk $
        ["run", "--rm", "-d", "--name", drName spec, "--network", drNetwork spec]
            <> concatMap (\a -> ["--network-alias", a]) (drAliases spec)
            <> concatMap (\p -> ["-p", p]) (drPorts spec)
            <> concatMap (\(h, c) -> ["-v", h <> ":" <> c]) (drMounts spec)
            <> concatMap (\(k, v) -> ["-e", toString (k <> "=" <> v)]) (drEnv spec)
            <> labelArgs
            <> (drImage spec : drCmd spec)

{- | Run a detached container for the duration of the action, force-removing it on every
exit path. It yields the container name the caller chose.
-}
withDockerContainer :: [String] -> DockerRun -> (String -> IO a) -> IO a
withDockerContainer labelArgs spec =
    bracket (runDetached labelArgs spec >> pure (drName spec)) removeContainer

{- | Create a labelled docker network for the action, removing it on every exit path after
any containers on it. @createArgs@ carries extra @network create@ flags such as @--subnet@.
-}
withDockerNetwork :: [String] -> String -> [String] -> (String -> IO a) -> IO a
withDockerNetwork labelArgs name createArgs =
    bracket (dockerOk (["network", "create"] <> createArgs <> labelArgs <> [name]) >> pure name) removeNetwork

{- | Bring up the OTLP collector for a scenario that asks for one, waited ready and torn
down around the action. Any other scenario is a no-op yielding 'Nothing'.
-}
withOptionalCollector :: E2EConfig -> [String] -> String -> String -> (Maybe String -> IO a) -> IO a
withOptionalCollector cfg labelArgs net coll body
    | not (ecCollector cfg) = body Nothing
    | otherwise = do
        image <- pinnedExternal collectorImage
        let collectorRun =
                (dockerRun coll net image)
                    { drAliases = [toString collectorAlias]
                    , drEnv = [("OTELCOL_CONFIG", collectorConfig)]
                    , drCmd = ["--config", "env:OTELCOL_CONFIG"]
                    }
        withDockerContainer labelArgs collectorRun $ \_ -> do
            ready <- awaitContainerLog coll (T.isInfixOf "Everything is ready") 240
            unless ready (fail "OTLP collector did not become ready within the timeout")
            body (Just coll)

-- Force-remove a container by name. It never throws (a missing container is fine), so a
-- bracket release cannot mask the action's own result or exception.
removeContainer :: String -> IO ()
removeContainer c = void (readProcess (proc "docker" ["rm", "-f", c]))

-- Remove a network by name. It never throws, for the same reason as 'removeContainer'.
removeNetwork :: String -> IO ()
removeNetwork net = void (readProcess (proc "docker" ["network", "rm", net]))

-- The collector's network alias on the TEST-NET. The proxy exports to it by this name.
collectorAlias :: Text
collectorAlias = "otelcol"

{- | The in-cluster OTLP endpoint the proxy exports to, reached by the collector's network
alias. A scenario names it through 'otlpCollectorEnv' or derives it from @DD_AGENT_HOST@.
-}
collectorOtlpEndpoint :: Text
collectorOtlpEndpoint = "http://" <> collectorAlias <> ":4318"

{- Standard @OTEL_*@ configuration the SDK reads, not a test-only path. A span and a metric
reach the collector within a scenario's patience window, not on minute-scale defaults. -}
telemetryExportTuning :: [(Text, Text)]
telemetryExportTuning =
    [ ("OTEL_TRACES_EXPORTER", "otlp")
    , ("OTEL_METRICS_EXPORTER", "otlp")
    , ("OTEL_METRIC_EXPORT_INTERVAL", "1000")
    , ("OTEL_BSP_SCHEDULE_DELAY", "1000")
    ]

{- | Proxy environment for the vanilla-OpenTelemetry dialect: telemetry on, endpoint in
@OTEL_EXPORTER_OTLP_ENDPOINT@. With @ecCollector = False@ it exercises graceful degradation.
-}
otlpCollectorEnv :: [(Text, Text)]
otlpCollectorEnv =
    [ ("ECLUSE_OBSERVABILITY__TELEMETRY", "on")
    , ("OTEL_EXPORTER_OTLP_ENDPOINT", collectorOtlpEndpoint)
    ]
        <> telemetryExportTuning

{- | The Datadog unified-service-tag identity the Datadog scenario configures and asserts
on. Named constants, so the proxy environment and the assertions cannot drift apart.
-}
ddTagService, ddTagEnv, ddTagVersion :: Text
ddTagService = "ecluse-e2e-dd"
ddTagEnv = "e2e-staging"
ddTagVersion = "9.9.9-e2e"

{- | Proxy environment for the Datadog dialect: @DD_SERVICE@\/@DD_ENV@\/@DD_VERSION@ plus
@DD_AGENT_HOST@ pointing the resolver at the collector. Pair with @ecCollector = True@.
-}
datadogCollectorEnv :: [(Text, Text)]
datadogCollectorEnv =
    [ ("ECLUSE_OBSERVABILITY__TELEMETRY", "on")
    , ("DD_SERVICE", ddTagService)
    , ("DD_ENV", ddTagEnv)
    , ("DD_VERSION", ddTagVersion)
    , ("DD_AGENT_HOST", collectorAlias)
    ]
        <> telemetryExportTuning

{- The collector configuration as a single-line flow-style YAML document. It arrives through
the @env:@ provider, so the distroless image needs no shell, file, or bind mount. -}
collectorConfig :: Text
collectorConfig =
    "{receivers: {otlp: {protocols: {http: {endpoint: \"0.0.0.0:4318\"}}}}, "
        <> "exporters: {debug: {verbosity: detailed}}, "
        <> "service: {pipelines: {"
        <> "traces: {receivers: [otlp], exporters: [debug]}, "
        <> "metrics: {receivers: [otlp], exporters: [debug]}}}}"

{- | What one @ecluse dredger --once@ run reported: the status a scheduler reads, and the JSONL
log lines it wrote. The run is not detached, so it ends when the cycle does.
-}
data DredgerRun = DredgerRun
    { dredgerExit :: ExitCode
    , dredgerOutput :: Text
    }

{- | Run the product image as @ecluse dredger --once@ against the shared data plane, with the extra
environment the case layers over the Dredger's own. It deletes from the same Verdaccio store the
proxy mirrors into, so a case seeds through the proxy and asserts against the store.
-}
runDredgerOnce :: GlobalDataPlane -> [Text] -> [(Text, Text)] -> IO DredgerRun
runDredgerOnce gdp flags extraEnv = do
    image <- maybe (fail (imageVar <> " unset")) pure =<< lookupEnv imageVar
    sfx <- uniqueSuffix
    labelArgs <- dockerLabelArgs "e2e"
    let run =
            (dockerRun ("ecluse-e2e-dredger-" <> sfx) (gdpNet gdp) (LocallyBuilt (toText image)))
                { drMounts = [(gdpWorkDir gdp </> "certs", "/certs:ro")]
                , drEnv = dredgerEnv <> extraEnv
                , drCmd = "dredger" : map toString flags
                }
    (code, out, err) <- readProcess (proc "docker" (foregroundArgs labelArgs run))
    pure DredgerRun{dredgerExit = code, dredgerOutput = decodeUtf8 (LBS.toStrict (out <> err))}

-- The same render as a detached run, without @-d@, so the caller waits for the cycle to end.
foregroundArgs :: [String] -> DockerRun -> [String]
foregroundArgs labelArgs spec =
    ["run", "--rm", "--name", drName spec, "--network", drNetwork spec]
        <> concatMap (\(h, c) -> ["-v", h <> ":" <> c]) (drMounts spec)
        <> concatMap (\(k, v) -> ["-e", toString (k <> "=" <> v)]) (drEnv spec)
        <> labelArgs
        <> (drImage spec : drCmd spec)

{- | The Dredger's own environment. Its mirror target is the store the proxy mirrors into, and it
carries the operator consent that store's tag admits. Its private upstream is a registry of its
own, because the deleting role refuses a mirror target that is also any mount\'s private upstream.
-}
dredgerEnv :: [(Text, Text)]
dredgerEnv =
    [ ("ECLUSE_SERVER__PORT", "4873")
    , ("ECLUSE_SERVER__PUBLIC_URL", "http://127.0.0.1:4873")
    , ("ECLUSE_MOUNTS__NPM__ENABLED", "true")
    , ("ECLUSE_MOUNTS__NPM__PRIVATE_UPSTREAM__REGISTRY__URL", "https://private-upstream/")
    , ("ECLUSE_MOUNTS__NPM__PUBLIC_UPSTREAM__REGISTRY__URL", "https://upstream/")
    , ("ECLUSE_MOUNTS__NPM__MIRROR_TARGET__VERDACCIO__URL", "https://mirror/")
    , ("ECLUSE_MOUNTS__NPM__MIRROR_TARGET__VERDACCIO__TOKEN", "e2e-publish-token")
    , ("ECLUSE_MOUNTS__NPM__MIRROR_TARGET__VERDACCIO__PERMIT_DELETION", "true")
    , ("ECLUSE_OBSERVABILITY__LOG_FORMAT", "json")
    , ("ECLUSE_DREDGER__CHUNK_PAUSE", "1")
    , ("SSL_CERT_FILE", "/certs/bundle.pem")
    ]

-- | Run a docker command, failing the test loudly if it exits non-zero.
dockerOk :: [String] -> IO ()
dockerOk args = do
    (code, _, err) <- readProcess (proc "docker" args)
    unless (code == ExitSuccess) $
        fail ("docker command " <> show args <> " failed: " <> toString (decodeUtf8 (LBS.toStrict err) :: Text))

{- | Generate a test CA and a server certificate into @dir@ (SANs: @upstream@, @mirror@,
@private-upstream@, @localhost@, @127.0.0.1@), plus a @bundle.pem@ of system and test CAs for
@SSL_CERT_FILE@.
-}
generateCerts :: FilePath -> IO ()
generateCerts dir = do
    createDirectoryIfMissing True dir
    let caCrt = dir </> "ca.crt"
        caKey = dir </> "ca.key"
        srvCrt = dir </> "server.crt"
        srvKey = dir </> "server.key"
        srvCsr = dir </> "server.csr"
        ext = dir </> "san.ext"
    writeFileText ext "subjectAltName=DNS:upstream,DNS:mirror,DNS:private-upstream,DNS:localhost,IP:127.0.0.1\n"
    opensslOk ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", caKey, "-out", caCrt, "-days", "2", "-subj", "/CN=Ecluse E2E Test CA"]
    opensslOk ["genrsa", "-out", srvKey, "2048"]
    opensslOk ["req", "-new", "-key", srvKey, "-out", srvCsr, "-subj", "/CN=ecluse-e2e"]
    opensslOk ["x509", "-req", "-in", srvCsr, "-CA", caCrt, "-CAkey", caKey, "-CAcreateserial", "-out", srvCrt, "-days", "2", "-extfile", ext]
    -- The system CAs plus the test CA, exactly the operator's "system store + my CA"
    -- extension. The system CAs keep an unmodified deployment trusting public TLS.
    systemCas <- lookupEnv "NIX_SSL_CERT_FILE" >>= maybe (pure "") readBytesOrEmpty
    testCa <- readFileBS caCrt
    writeFileBS (dir </> "bundle.pem") (systemCas <> "\n" <> testCa)

-- Read a file's bytes, or empty on any error. The system CA bundle is best-effort: the
-- proxy reaches only the test stubs over TLS in the e2e, so the test CA alone suffices.
readBytesOrEmpty :: FilePath -> IO ByteString
readBytesOrEmpty path = handleAny (\_ -> pure "") (readFileBS path)

-- | Run an openssl command, failing the test loudly if it exits non-zero.
opensslOk :: [String] -> IO ()
opensslOk args = do
    (code, _, err) <- readProcess (proc "openssl" args)
    unless (code == ExitSuccess) $
        fail ("openssl command " <> show args <> " failed: " <> toString (decodeUtf8 (LBS.toStrict err) :: Text))

-- | The host loopback port docker published a container's given @\<port\>\/tcp@ to.
publishedPort :: String -> String -> IO Int
publishedPort cname containerPort = do
    (_, out) <- readProcessStdout (proc "docker" ["port", cname, containerPort])
    let firstLine = fromMaybe "" (listToMaybe (lines (decodeUtf8 (LBS.toStrict out))))
        portText = T.takeWhileEnd (/= ':') (T.strip firstLine)
    maybe
        (fail ("could not parse published port from " <> show firstLine))
        pure
        (readMaybe (toString portText))

{- | Create the mirror queue in the ministack SQS emulator and return its queue URL.
@CreateQueue@ is idempotent, so retrying while the emulator warms up is safe. The URL names the
emulator's own host, which nothing dials because the proxy routes by @AWS_ENDPOINT_URL_SQS@.
-}
createMinistackQueue :: Manager -> Int -> Text -> IO Text
createMinistackQueue manager hostPort queueName =
    pollUntil 60 500000 isJust attempt
        >>= maybe (fail "ministack SQS CreateQueue never succeeded within the timeout") pure
  where
    endpoint =
        "http://127.0.0.1:"
            <> show hostPort
            <> "/?Action=CreateQueue&QueueName="
            <> queueName
            <> "&Version=2012-11-05"
    attempt :: IO (Maybe Text)
    attempt =
        handleAny (\_ -> pure Nothing) $ do
            base <- parseRequest (toString endpoint)
            resp <- httpLbs base{method = "POST"} manager
            let body = decodeUtf8 (LBS.toStrict (responseBody resp)) :: Text
            pure $ case (statusCode (responseStatus resp), between "<QueueUrl>" "</QueueUrl>" body) of
                (200, Just url) | not (T.null url) -> Just url
                _ -> Nothing

-- | The text between the first @opening@ and the following @closing@ marker, or 'Nothing'.
between :: Text -> Text -> Text -> Maybe Text
between opening closing t =
    let afterOpen = snd (T.breakOn opening t)
     in if T.null afterOpen
            then Nothing
            else
                let (inner, rest) = T.breakOn closing (T.drop (T.length opening) afterOpen)
                 in if T.null rest then Nothing else Just inner

-- | Poll a URL until it returns the wanted status, up to ~30s.
waitFor :: Manager -> Text -> Int -> IO Bool
waitFor manager url want = pollUntil 100 300000 id probe
  where
    probe :: IO Bool
    probe =
        handleAny (\_ -> pure False) $ do
            req <- parseRequest (toString url)
            (== want) . statusCode . responseStatus <$> (httpLbs req manager :: IO (Response LByteString))

exitOk :: (ExitCode, a, b) -> Bool
exitOk (code, _, _) = code == ExitSuccess

{- | A free host loopback port: bind to @127.0.0.1:0@, read the port the OS assigned,
release it. The brief window before docker rebinds it is a tolerable race for a
loopback test. Picked up front so ECLUSE_SERVER__PUBLIC_URL can name it before boot.
-}
freeHostPort :: IO Int
freeHostPort =
    bracket (socket AF_INET Stream defaultProtocol) close $ \sock -> do
        bind sock (SockAddrInet 0 (tupleToHostAddress (127, 0, 0, 1)))
        getSocketName sock >>= \case
            SockAddrInet port _ -> pure (fromIntegral port)
            other -> fail ("unexpected socket address: " <> show other)

-- | A unique, monotonic-ish suffix for network/container/temp names.
uniqueSuffix :: IO String
uniqueSuffix = do
    t <- getPOSIXTime
    pure (show (round (t * 1000) :: Integer))

{- | The nginx stub config. One nginx terminates TLS for every registry stub by @server_name@, so
the proxy dials https-only registry endpoints. Only the proxy validates the cert, so the harness's
own probes stay plain HTTP. @client_max_body_size 0@ admits a published tarball, and
@X-Forwarded-Proto https@ keeps Verdaccio generating https URLs.
-}
nginxStubConfig :: Text
nginxStubConfig =
    T.unlines
        [ "server {"
        , "    listen 443 ssl;"
        , "    server_name upstream;"
        , "    ssl_certificate /certs/server.crt;"
        , "    ssl_certificate_key /certs/server.key;"
        , "    root /usr/share/nginx/html;"
        , "    location ~ ^/(?<pkg>[^/]+)$ {"
        , "        default_type application/json;"
        , "        alias /usr/share/nginx/html/$pkg/packument.json;"
        , "    }"
        , "    location / {"
        , "        try_files $uri =404;"
        , "    }"
        , "}"
        , "server {"
        , "    listen 443 ssl;"
        , "    server_name private-upstream;"
        , "    ssl_certificate /certs/server.crt;"
        , "    ssl_certificate_key /certs/server.key;"
        , "    location / {"
        , "        return 404;"
        , "    }"
        , "}"
        , "server {"
        , "    listen 443 ssl;"
        , "    server_name mirror;"
        , "    ssl_certificate /certs/server.crt;"
        , "    ssl_certificate_key /certs/server.key;"
        , "    client_max_body_size 0;"
        , "    location / {"
        , "        proxy_pass http://verdaccio:4873;"
        , "        proxy_set_header Host $host;"
        , "        proxy_set_header X-Forwarded-Proto https;"
        , "        proxy_set_header X-Forwarded-For $remote_addr;"
        , "    }"
        , "}"
        ]

{- | The Verdaccio config: anonymous read + publish, no uplinks (a sealed local
mirror), listening on all interfaces so a peer container can reach it.
-}
verdaccioConfig :: Text
verdaccioConfig =
    T.unlines
        [ "listen: 0.0.0.0:4873"
        , "storage: /verdaccio/storage/data"
        , "auth:"
        , "  htpasswd:"
        , "    file: /verdaccio/storage/htpasswd"
        , "    max_users: -1"
        , "uplinks: {}"
        , "packages:"
        , "  '@*/*':"
        , "    access: $all"
        , "    publish: $all"
        , "    unpublish: $all"
        , "  '**':"
        , "    access: $all"
        , "    publish: $all"
        , "    unpublish: $all"
        , "log: { type: stdout, format: pretty, level: warn }"
        ]

{- | Pause the public-upstream stub for the duration of an action, then resume it on every exit
path. With the stub frozen, only the private mirror can answer an install.
-}
withUpstreamPaused :: E2E -> IO a -> IO a
withUpstreamPaused e2e =
    bracket_
        (dockerOk ["pause", e2eStubContainer e2e])
        (dockerOk ["unpause", e2eStubContainer e2e])

{- | Poll a container's logs until the predicate holds, up to @attempts@ times at ~250ms.
'False' means it never held inside the budget.
-}
awaitContainerLog :: String -> (Text -> Bool) -> Int -> IO Bool
awaitContainerLog cname matches attempts =
    pollUntil attempts 250000 id (matches <$> containerLogs cname)

{- | A container's combined stdout+stderr so far (@docker logs@). Empty on any docker
error, such as the container not existing yet, mid image-pull.
-}
containerLogs :: String -> IO Text
containerLogs cname =
    handleAny (\_ -> pure "") $ do
        (_, out, err) <- readProcess (proc "docker" ["logs", cname])
        pure (decodeUtf8 (LBS.toStrict out) <> decodeUtf8 (LBS.toStrict err))
