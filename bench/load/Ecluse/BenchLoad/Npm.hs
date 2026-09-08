-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Local npm load scenarios for metadata, artifacts, caches, and the mirror worker.
Private reads stay live. Public requests can share one in-flight fetch even at zero cache TTL.
The harness uses loopback upstreams and the production composition defaults.
-}
module Ecluse.BenchLoad.Npm (
    npmFixture,
) where

import Control.Concurrent (threadDelay)
import Data.Aeson (Value, encode, (.=))
import Data.Aeson.Key qualified as Key
import Data.ByteString.Lazy qualified as LBS
import Data.List qualified as List
import Data.Map.Strict qualified as Map
import Data.Text qualified as T
import Data.Time (NominalDiffTime, UTCTime (UTCTime), addUTCTime, fromGregorian, nominalDay)
import Data.Time.Format.ISO8601 (iso8601Show)
import GHC.Clock (getMonotonicTime)
import GHC.Conc (getNumCapabilities)
import Katip (LogEnv)
import Network.HTTP.Client (defaultManagerSettings, newManager)
import Network.HTTP.Client qualified as HTTP
import Network.HTTP.Types (hContentType, status200, status404)
import Network.HTTP.Types.Header (hETag)
import Network.Wai (Application, Request, pathInfo, responseLBS)
import Network.Wai.Handler.Warp (testWithApplication)

import Ecluse (mountBindingFor)
import Ecluse.BenchLoad.Error (benchFail)
import Ecluse.BenchLoad.Harness (Driver (DriveHttpHeaders, DriveHttpUrls, DriveInProcess), LoadKnobs (..), Scenario (..), UpstreamFixture (..))
import Ecluse.Composition.Sizing (connectionPoolSettings, openFileSoftLimit, resolvePrivateConnections, resolvePublicConnections, resolveServeAdmission)

import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.Package (Hash, HashAlg (SHA1, SRI), PackageName, mkPackageName, unscopedName)
import Ecluse.Core.Queue (
    MirrorJob (
        MirrorJob,
        jobArtifactFilename,
        jobArtifactUrl,
        jobPackage,
        jobTraceContext,
        jobVersion
    ),
    MirrorQueue (receive),
    enqueue,
 )
import Ecluse.Core.Queue.Memory (defaultMemoryQueueConfig, newBoundedInMemoryQueue)
import Ecluse.Core.Registry (ParseError (ParseError), RegistryResponse (RegistryResponse))
import Ecluse.Core.Registry.Publish (MirrorPublish (..))
import Ecluse.Core.Rules (prepare)
import Ecluse.Core.Security.Egress.DevHttp (loopbackRegistryUrl)
import Ecluse.Core.Server.Admission (newServeAdmission)
import Ecluse.Core.Server.Cache (CacheConfig (..), StoreBudget (..), newMetadataCache)
import Ecluse.Core.Server.Context (PackumentDeps (..))
import Ecluse.Core.Server.Upstream (MirrorServePlan (MirrorOnAdmit))
import Ecluse.Core.Version (mkVersion)
import Ecluse.Core.Worker (
    WorkerRuntime (
        WorkerRuntime,
        wrHeartbeat,
        wrInjectTraceContext,
        wrManager,
        wrMetrics,
        wrPolicies,
        wrQueue,
        wrTracing
    ),
    newWorkerHeartbeat,
    processBatch,
    runWorkerM,
 )
import Ecluse.Runtime.Env (newEnvWithAdmission)
import Ecluse.Runtime.Server (application, mkServerConfig)
import Ecluse.Runtime.Telemetry (telemetryDisabled)
import Ecluse.Test.Corpus (CorpusPackage (cpPackage, cpPath, cpWeight), corpusPackages, cpName, permissiveAgeRules)
import Ecluse.Test.Log (newTestLogEnv)
import Ecluse.Test.Package (hexSha1OfLazy, sriSha512OfLazy, unsafeFilename, unsafeHash, validSha1, validSha512Sri)
import Ecluse.Test.Port (noopWorkerMetricsPort, passthroughWorkerTracingPort)
import Ecluse.Test.Registry.Npm (VersionSpec (..), packumentValue, versionSpec, versionValue)
import Ecluse.Test.Rules (inertRuleDeps)
import Ecluse.Test.Server.Cache (defaultCacheConfig)
import Ecluse.Test.Server.Mount (npmServeDeps)
import Ecluse.Test.Wai (localhost, rebaseAuthority, selfBaseUrl)
import Ecluse.Test.Worker (admitAllPolicies)

-- | The npm load-test fixture: the packument traffic scenarios plus the worker loop.
npmFixture :: UpstreamFixture
npmFixture =
    UpstreamFixture
        { fixtureEcosystem = Npm
        , fixtureScenarios =
            [ mergeScenario
            , cacheHitScenario
            , revalidateScenario
            , cacheFitsScenario
            , cacheEvictsScenario
            , tarballScenario
            , tarballOnboardingScenario
            , tarballCeilingScenario
            , workerScenario
            ]
        }

-- | The headline packument @GET@ path: both upstreams fetched and merged with the public metadata cache off (TTL 0).
mergeScenario :: Scenario
mergeScenario =
    Scenario
        { scenarioName = "merge-cold"
        , scenarioConcurrencyScale = 1
        , scenarioDescription =
            "Public download path with the private + public packument merge in the loop, over a large-emphasis mix drawn from the curated real-world corpus (the heavy many-version packuments are the primary drivers): GET /{pkg} fans to both upstreams -> merge -> rule-filter -> URL-rewrite -> ETag -> re-serialise, with the public metadata cache disabled (TTL 0). The public leg is single-flight, so concurrent misses coalesce onto one in-flight fetch+decode and followers share the leader's parsed packument: the public fetch+decode is amortised under load, not paid per request. Every request still pays the live private fetch, the merge, the rule sweep, and the re-serialise."
        , scenarioBoot = \knobs k -> withNpmProxy knobs 0 defaultCacheEntries serveMix (k . DriveHttpUrls)
        }

-- | The cheap high-throughput path: the same packument @GET@ with the public origin served from a warm metadata cache, so only the live private leg and the merge run.
cacheHitScenario :: Scenario
cacheHitScenario =
    Scenario
        { scenarioName = "cached-public-hit"
        , scenarioConcurrencyScale = 1
        , scenarioDescription =
            "The cheap cache-served path over the same large-emphasis corpus mix: GET /{pkg} with the anonymous public origin served from the warm metadata cache (no public fetch or decode), the live private leg merged in. The passthrough model caches the public origin, not the per-client private one, so this is the faithful no-public-fetch shape."
        , scenarioBoot = \knobs k -> withNpmProxy knobs longCacheTtl defaultCacheEntries serveMix (k . DriveHttpUrls)
        }

-- | The conditional-revalidation path: every request echoes a primed @ETag@ as @If-None-Match@ and the proxy answers @304@.
revalidateScenario :: Scenario
revalidateScenario =
    Scenario
        { scenarioName = "revalidate-not-modified"
        , scenarioConcurrencyScale = 1
        , scenarioDescription =
            "Conditional revalidation of the heaviest corpus packument: a priming GET captures the served ETag, then every driven request echoes it as If-None-Match and is answered 304 off the derived validator -- the private leg still fetched and the plan still computed per request, but no assembly, encode, or output hash. The realistic shape for CI fleets restoring npm's cache: metadata traffic that revalidates instead of re-downloading."
        , scenarioBoot = \knobs k ->
            let pkgs = take 1 (workingSet knobs)
             in withNpmProxy knobs longCacheTtl defaultCacheEntries (uniformMix pkgs) $ \case
                    url : _ -> do
                        etag <- primeETag url
                        k (DriveHttpHeaders [("If-None-Match", etag)] [url])
                    [] -> benchFail "revalidate-not-modified: no URL to drive"
        }

primeETag :: Text -> IO Text
primeETag url = do
    manager <- newManager defaultManagerSettings
    request <- HTTP.parseRequest (toString url)
    response <- HTTP.httpLbs request manager
    case List.lookup hETag (HTTP.responseHeaders response) of
        Just tag -> pure (decodeUtf8 tag)
        Nothing -> benchFail "revalidate-not-modified: the priming GET returned no ETag"

-- | The cache-eviction baseline: a uniform working set of large packuments against a cache bound that holds the whole set, so every entry stays resident after warm-up.
cacheFitsScenario :: Scenario
cacheFitsScenario =
    Scenario
        { scenarioName = "cache-fits-large"
        , scenarioConcurrencyScale = 1
        , scenarioDescription =
            "Cache-eviction baseline (fits): a uniform working set of large packuments served with TTL > 0 and a cache bound that holds the whole set, so after warm-up every entry stays resident and the public leg is cache-served with no re-derivation. Residency reflects the whole working set held at once; alloc/request is the cheap warm-served floor. Read against cache-evicts-large to isolate the eviction cost."
        , scenarioBoot = \knobs k ->
            let pkgs = workingSet knobs
             in withNpmProxy knobs longCacheTtl (length pkgs) (uniformMix pkgs) (k . DriveHttpUrls)
        }

-- | The cache-eviction stress: the same uniform working set against a cache bound smaller than it, so the cache continually evicts entries and re-derives them on the next request.
cacheEvictsScenario :: Scenario
cacheEvictsScenario =
    Scenario
        { scenarioName = "cache-evicts-large"
        , scenarioConcurrencyScale = 1
        , scenarioDescription =
            "Cache-eviction stress (exceeds): the same uniform large working set with TTL > 0, but a cache bound smaller than the working set, so entries are continually evicted and re-derived. Isolates the eviction cost against cache-fits-large: throughput/latency under churn, the alloc/request of re-deriving (re-fetch + decode + project) each evicted large packument on a miss, and a peak residency bounded by the cache bound rather than the whole set. Bound = BENCH_LOAD_CACHE_MAX_ENTRIES, working set = BENCH_LOAD_WORKING_SET."
        , scenarioBoot = \knobs k ->
            let pkgs = workingSet knobs
             in withNpmProxy knobs longCacheTtl (lkCacheMaxEntries knobs) (uniformMix pkgs) (k . DriveHttpUrls)
        }

tarballScenario :: Scenario
tarballScenario =
    Scenario
        { scenarioName = "tarball-hot-path"
        , scenarioConcurrencyScale = 1
        , scenarioDescription =
            "Tarball proxy hot path: GET /npm/{pkg}/-/{unscoped-pkg}-9999.0.2.tgz (the scope-dropping npm convention) fans to the packument first to read the dist.tarball URL (instantly served from the metadata cache), then streams the tarball from the artifact upstream."
        , scenarioBoot = \knobs k -> withNpmProxy knobs longCacheTtl defaultCacheEntries tarballMix (k . DriveHttpUrls)
        }

-- | The onboarding fail-over: every tarball request misses the private pull-through and takes the public leg, the shape a new project drives before the mirror warms.
tarballOnboardingScenario :: Scenario
tarballOnboardingScenario =
    Scenario
        { scenarioName = "tarball-onboarding"
        , scenarioConcurrencyScale = 1
        , scenarioDescription =
            "The onboarding fail-over: GET /npm/{pkg}/-/{pkg}-1.0.0.tgz with the private pull-through missing everything (404 after the injected latency, as an unwarmed mirror would) and the public leg serving -- single-version gate, then the artifact streamed from the public origin's self-hosted location, then the mirror-job enqueue. Prices the regime a new project drives until the mirror warms; the steady state is tarball-hot-path. Per-request floor is two sequential upstream round trips (probe miss + artifact) plus the stream."
        , scenarioBoot = \knobs k ->
            let latency = lkUpstreamLatencyMicros knobs
                bytes = artifactBytes (lkPayloadBytes knobs)
             in withProxyOverStubs
                    knobs
                    longCacheTtl
                    defaultCacheEntries
                    (onboardingPrivateStub latency)
                    (onboardingPublicStub latency bytes)
                    onboardingMix
                    (k . DriveHttpUrls)
        }

-- | The streaming-ceiling probe: the private-hit relay at four times the shared concurrency against a 2 ms stub latency, so the proxy's own relay binds instead of the client's connections x RTT.
tarballCeilingScenario :: Scenario
tarballCeilingScenario =
    Scenario
        { scenarioName = "tarball-ceiling"
        , scenarioConcurrencyScale = 4
        , scenarioDescription =
            "Streaming-ceiling probe on the private-hit relay: 4x the shared concurrency, 2 ms stub latency (overriding the probed RTT for this scenario alone), same conventional private read as tarball-hot-path. Chases the proxy's own streaming knee -- relay pump, connection handling, syscall pressure -- instead of the client's connections x RTT ceiling. Throughput here x the worker-artifact payload size approximates the relay's byte rate."
        , scenarioBoot = \knobs k ->
            withNpmProxy knobs{lkUpstreamLatencyMicros = 2_000} longCacheTtl defaultCacheEntries tarballMix (k . DriveHttpUrls)
        }

-- A cache TTL longer than any scenario's warm-up plus measured window, so a warm entry
-- leaves by eviction rather than by expiry.
longCacheTtl :: NominalDiffTime
longCacheTtl = 3600

-- The fixture's full-store entry bound, the scenarios' default working-set knob.
defaultCacheEntries :: Int
defaultCacheEntries = sbMaxEntries (cacheFullBudget defaultCacheConfig)

-- The fixture's byte split with the scenario's TTL and entry knob applied to every
-- store: the knob is the axis under test, never the split.
benchCacheConfig :: NominalDiffTime -> Int -> CacheConfig
benchCacheConfig ttl maxEntries =
    defaultCacheConfig
        { cacheTtl = ttl
        , cacheFullBudget = capEntries (cacheFullBudget defaultCacheConfig)
        , cacheVersionBudget = capEntries (cacheVersionBudget defaultCacheConfig)
        , cacheAssembledBudget = capEntries (cacheAssembledBudget defaultCacheConfig)
        }
  where
    capEntries budget = budget{sbMaxEntries = maxEntries}

-- | Boot the two path-aware packument upstream stubs over the real-world corpus, then the composed proxy over them, and yield the caller's serve mix.
withNpmProxy :: LoadKnobs -> NominalDiffTime -> Int -> (Int -> [Text]) -> ([Text] -> IO a) -> IO a
withNpmProxy knobs ttl maxEntries mkMix body = do
    bodies <- loadServeBodies
    rewritten <- newIORef mempty
    let bytes = artifactBytes (lkPayloadBytes knobs)
        latency = lkUpstreamLatencyMicros knobs
    withProxyOverStubs
        knobs
        ttl
        maxEntries
        (privateOverlayStub latency bytes)
        (corpusPublicStub rewritten latency bodies)
        mkMix
        body

-- | Boot the composed proxy over the given private and public upstream stubs, the shared shell of every HTTP scenario.
withProxyOverStubs :: LoadKnobs -> NominalDiffTime -> Int -> Application -> Application -> (Int -> [Text]) -> ([Text] -> IO a) -> IO a
withProxyOverStubs knobs ttl maxEntries privateApp publicApp mkMix body = do
    capabilities <- getNumCapabilities
    fdLimit <- openFileSoftLimit
    let admissionCapacity = fst (resolveServeAdmission (lkServeMaxInFlight knobs) capabilities)
        privateConnections = fst (resolvePrivateConnections (lkPrivateConnectionsPerHost knobs) fdLimit)
        publicConnections = fst (resolvePublicConnections (lkPublicConnectionsPerHost knobs) fdLimit)
    testWithApplication (pure privateApp) $ \privatePort ->
        testWithApplication (pure publicApp) $ \publicPort -> do
            publicManager <- newManager (connectionPoolSettings publicConnections defaultManagerSettings)
            -- The private pool does not follow the admission capacity: a trusted tarball hit
            -- streams outside admission (see resolvePrivateConnections).
            privateManager <- newManager (connectionPoolSettings privateConnections defaultManagerSettings)
            admission <- newServeAdmission admissionCapacity
            cache <- newMetadataCache (benchCacheConfig ttl (max 1 maxEntries))
            logEnv <- newTestLogEnv
            heartbeat <- newWorkerHeartbeat
            -- The production memory backend at config/default.yaml's queueMemoryMaxDepth default,
            -- 50000. No worker drains it, so past the cap it sheds drop-newest, like production.
            queue <-
                newBoundedInMemoryQueue
                    (defaultMemoryQueueConfig 50_000)
                    (\n -> putTextLn ("bench serve stack: bounded in-memory mirror queue at cap; running dropped-job total: " <> show n))
            -- The serve path never touches the publish-side registry handle, so it is the refusing
            -- placeholder.
            env <- newEnvWithAdmission admission queue publicManager privateManager cache logEnv telemetryDisabled heartbeat
            deps <- npmDeps privatePort publicPort
            let cfg = mkServerConfig (maybeToList (mountBindingFor Npm deps Nothing))
            testWithApplication (pure (application cfg env)) $ \proxyPort ->
                body (mkMix proxyPort)

-- The proxy URL for one corpus package's packument GET.
packageUrl :: Int -> Text -> Text
packageUrl proxyPort name = localhost proxyPort <> "/npm/" <> name

-- Repeats each package's URL by its serve weight, so the oha drive follows the
-- large-emphasis proportion 'corpusPackages' encodes.
serveMix :: Int -> [Text]
serveMix proxyPort =
    concatMap (\cp -> replicate (cpWeight cp) (packageUrl proxyPort (cpName cp))) corpusPackages

-- Each package once, so oha cycles them evenly. That reuse thrashes a too-small cache:
-- the drive asks for an evicted package again and the proxy re-derives it.
uniformMix :: [CorpusPackage] -> Int -> [Text]
uniformMix pkgs proxyPort = map (packageUrl proxyPort . cpName) pkgs

-- The tarball serve mix: each corpus package's tarball URL repeated by its serve weight.
-- A tarball path is /npm/{pkg}/-/{unscoped-pkg}-{version}.tgz (npm convention).
tarballMix :: Int -> [Text]
tarballMix proxyPort =
    concatMap (\cp -> replicate (cpWeight cp) (localhost proxyPort <> "/npm/" <> cpName cp <> "/-/" <> unscopedName (cpPackage cp) <> "-9999.0.2.tgz")) corpusPackages

-- The cache-eviction working set: the leading 'lkWorkingSet' large corpus packages (in
-- 'corpusPackages' order, heaviest first), so a bound below its length forces eviction.
workingSet :: LoadKnobs -> [CorpusPackage]
workingSet knobs = take (max 1 (lkWorkingSet knobs)) corpusPackages

-- The stub ports are addressed by the @localhost@ DNS name, never a bare IP literal: the
-- public leg's tarball gate blocks internal ranges, which it only recognises as literals.
npmDeps :: Int -> Int -> IO PackumentDeps
npmDeps privatePort publicPort = do
    prepared <- prepare inertRuleDeps permissiveAgeRules
    pure
        ( npmServeDeps
            (Just (loopbackRegistryUrl (localhost privatePort)))
            (loopbackRegistryUrl (localhost publicPort))
            (MirrorOnAdmit (loopbackRegistryUrl "https://mirror.bench"))
            prepared
            (pure benchNow)
        )
            { pdMountBaseUrl = "https://bench.proxy"
            , pdEgressUrl = Right . loopbackRegistryUrl
            }

-- | The mirror worker's hot loop, driven in-process against a stub artifact upstream.
workerScenario :: Scenario
workerScenario =
    Scenario
        { scenarioName = "worker-mirroring"
        , scenarioConcurrencyScale = 1
        , scenarioDescription =
            "The mirror worker's fetch -> verify -> publish -> ack loop, driven in-process over a stub artifact upstream: each job fetches the artifact over loopback, recomputes and verifies its integrity digest, and publishes through a succeeding in-memory client. The mirror-presence probe answers absent, so every job measures the full pipeline, never the dedup short-circuit."
        , scenarioBoot = \knobs k -> do
            counter <- newIORef (0 :: Int)
            let bytes = artifactBytes (lkPayloadBytes knobs)
            testWithApplication (pure (stubUpstream octetContentType (lkUpstreamLatencyMicros knobs) bytes)) $ \artPort -> do
                manager <- newManager defaultManagerSettings
                -- A dropped job breaks the single-outstanding-job cadence and fails the run.
                queue <-
                    newBoundedInMemoryQueue
                        (defaultMemoryQueueConfig 16)
                        (\n -> benchFail ("worker scenario: the in-memory mirror queue dropped a job (running total " <> show n <> "); the enqueue-receive cadence broke"))
                heartbeat <- newWorkerHeartbeat
                logEnv <- newTestLogEnv
                let runtime =
                        WorkerRuntime
                            { wrQueue = queue
                            , wrManager = manager
                            , wrHeartbeat = heartbeat
                            , wrMetrics = noopWorkerMetricsPort
                            , wrTracing = passthroughWorkerTracingPort
                            , wrInjectTraceContext = id
                            , -- The verification digests are the re-admitted artifact's,
                              -- The verify gate compares against the injected resolver's digests,
                              -- so they must be the stub bytes' true digests for a job to publish.
                              wrPolicies = admitAllPolicies (succeedingPublishClient counter) (jobHashes bytes)
                            }
                    artUrl = localhost artPort <> "/" <> packageText <> "/-/" <> packageText <> "-1.0.0.tgz"
                    job = mirrorJob artUrl
                k (DriveInProcess (runWorkerLoop knobs logEnv runtime queue job counter))
        }

-- | Run the worker loop for the configured duration and return the per-job latencies in seconds.
runWorkerLoop :: LoadKnobs -> LogEnv -> WorkerRuntime -> MirrorQueue -> MirrorJob -> IORef Int -> IO [Double]
runWorkerLoop knobs logEnv runtime queue job counter = do
    deadline <- (+ fromIntegral (lkDurationSeconds knobs)) <$> getMonotonicTime
    latencies <- go deadline []
    published <- readIORef counter
    when (published /= length latencies) $
        benchFail
            ( "worker scenario: "
                <> show published
                <> " of "
                <> show (length latencies)
                <> " jobs published -- a harness wiring failure (fetch/verify/publish broke)"
            )
    pure latencies
  where
    go :: Double -> [Double] -> IO [Double]
    go deadline acc = do
        nowT <- getMonotonicTime
        if nowT >= deadline
            then pure (reverse acc)
            else do
                enqueue queue job >>= either (\f -> fail ("bench enqueue faulted: " <> show f)) pure
                messages <- receive queue >>= either (\f -> fail ("bench receive faulted: " <> show f)) pure
                t0 <- getMonotonicTime
                runWorkerM logEnv mempty runtime (processBatch messages)
                t1 <- getMonotonicTime
                go deadline ((t1 - t0) : acc)

-- A mirror job for the canned artifact at the given upstream URL. The digests its verify
-- gate checks live on the injected policies ('admitAllPolicies').
mirrorJob :: Text -> MirrorJob
mirrorJob url =
    MirrorJob
        { jobPackage = packageName
        , jobVersion = mkVersion Npm "1.0.0"
        , jobArtifactUrl = loopbackRegistryUrl url
        , jobArtifactFilename = unsafeFilename (packageText <> "-1.0.0.tgz")
        , jobTraceContext = Nothing
        }

-- Records each publish and reports success. The mirror-presence probe must answer absent,
-- or every job after the first short-circuits: an unparseable body is that absent posture.
succeedingPublishClient :: IORef Int -> MirrorPublish
succeedingPublishClient counter =
    MirrorPublish
        { mpPublishArtifact = \_ _ _ _ -> do
            atomicModifyIORef' counter (\n -> (n + 1, ()))
            pure (Right ())
        , mpProbeMetadata = const (pure (Right (RegistryResponse 200 "")))
        , mpParseVersionList = const (Left (ParseError "bench mirror: nothing mirrored yet"))
        }

-- The canned artifact bytes for the worker scenario: a payload-sized buffer (the verify
-- step hashes the whole body, so its size is the per-job work).
artifactBytes :: Int -> LByteString
artifactBytes size = LBS.replicate (fromIntegral (max 1 size)) 0x61

-- The artifact's real integrity digests (an SRI sha512 and a hex sha1), so the worker's
-- recompute-and-compare verify gate admits exactly these bytes.
jobHashes :: LByteString -> NonEmpty Hash
jobHashes bytes = unsafeHash SRI (sriSha512OfLazy bytes) :| [unsafeHash SHA1 (hexSha1OfLazy bytes)]

-- A stub upstream that injects the configured latency then serves a fixed body. The
-- worker scenario's artifact upstream uses it, and answers any path the same way.
stubUpstream :: ByteString -> Int -> LByteString -> Application
stubUpstream contentType latency body _request respond = do
    when (latency > 0) (threadDelay latency)
    respond (responseLBS status200 [(hContentType, contentType)] body)

jsonContentType, octetContentType :: ByteString
jsonContentType = "application/json"
octetContentType = "application/octet-stream"

-- Serves the real captured packument for the requested package, so each request decodes,
-- merges, gates, rewrites, and re-serialises a genuinely heterogeneous document.
corpusPublicStub :: IORef (Map Text LByteString) -> Int -> Map Text LByteString -> Application
corpusPublicStub rewritten latency bodies request respond = do
    when (latency > 0) (threadDelay latency)
    served <- selfHosted rewritten (selfBaseUrl request) bodies
    respond $ case requestedPackage request >>= (`Map.lookup` served) of
        Just packument -> responseLBS status200 [(hContentType, jsonContentType)] packument
        Nothing -> responseLBS status404 [(hContentType, jsonContentType)] "{}"

-- Point captured artifact locations at the stub's authority so the scenario measures admitted versions.
selfHosted :: IORef (Map Text LByteString) -> Text -> Map Text LByteString -> IO (Map Text LByteString)
selfHosted rewritten authority bodies =
    readIORef rewritten >>= \case
        cached | not (Map.null cached) -> pure cached
        _ -> do
            let served = Map.map (rebaseCapture authority) bodies
            writeIORef rewritten served
            pure served

-- Replace the captured registry authority with the stub's own, over the raw bytes.
rebaseCapture :: Text -> LByteString -> LByteString
rebaseCapture = rebaseAuthority capturedAuthority

-- The authority every committed corpus capture names as its tarball host.
capturedAuthority :: Text
capturedAuthority = "https://registry.npmjs.org"

-- Serves a small overlay of disjoint versions, so the merge yields a genuine cross-upstream
-- union, plus the canned artifact bytes for any tarball path under the package.
privateOverlayStub :: Int -> LByteString -> Application
privateOverlayStub latency bytes request respond = do
    when (latency > 0) (threadDelay latency)
    let mPkg = requestedPackage request
    case mPkg of
        -- Artifact request: /{pkg}/-/{file}
        Just pkg
            | "/-/" `T.isInfixOf` pkg ->
                respond (responseLBS status200 [(hContentType, octetContentType)] bytes)
        -- Packument request: /{pkg}
        Just pkg ->
            respond (responseLBS status200 [(hContentType, jsonContentType)] (encode (privateOverlay (selfBaseUrl request) pkg)))
        Nothing ->
            respond (responseLBS status404 [(hContentType, jsonContentType)] "{}")

-- Rejoins the path segments with @/@, so a scoped name sent as one percent-encoded segment
-- or as two raw ones recovers as @\@scope\/name@ either way.
requestedPackage :: Request -> Maybe Text
requestedPackage request = case pathInfo request of
    [] -> Nothing
    segments -> Just (T.intercalate "/" segments)

-- | The onboarding fixture: the private stub answers @404@ after the injected latency, because an unwarmed pull-through still costs a probe round trip.
onboardingPrivateStub :: Int -> Application
onboardingPrivateStub latency _request respond = do
    when (latency > 0) (threadDelay latency)
    respond (responseLBS status404 [(hContentType, jsonContentType)] "{}")

-- The self-hosted public stub of the onboarding fixture (see 'onboardingPrivateStub').
onboardingPublicStub :: Int -> LByteString -> Application
onboardingPublicStub latency bytes request respond = do
    when (latency > 0) (threadDelay latency)
    case requestedPackage request of
        Just pkg
            | "/-/" `T.isInfixOf` pkg ->
                respond (responseLBS status200 [(hContentType, octetContentType)] bytes)
        Just pkg ->
            respond (responseLBS status200 [(hContentType, jsonContentType)] (encode (onboardingPackument (selfBaseUrl request) pkg)))
        Nothing ->
            respond (responseLBS status404 [(hContentType, jsonContentType)] "{}")

-- One old version with a self-hosted conventional tarball and floor-meeting digests, just
-- enough for the single-version gate to admit and the public stream to fetch.
onboardingPackument :: Text -> Text -> Value
onboardingPackument base name =
    packumentValue
        name
        onboardingVersion
        [(onboardingVersion, versionObj)]
        ["created" .= publishedLongAgo, Key.fromText onboardingVersion .= publishedLongAgo]
        ["_id" .= name]
  where
    versionObj =
        versionValue
            ( (versionSpec name onboardingVersion (base <> "/" <> name <> "/-/" <> tarballStem name <> "-" <> onboardingVersion <> ".tgz"))
                { vsIntegrity = Just validSha512Sri
                , vsShasum = Just validSha1
                }
            )

onboardingVersion :: Text
onboardingVersion = "1.0.0"

-- The onboarding drive: each corpus package's tarball once, uniformly. A fresh project
-- pulls each dependency once, never by popularity weight.
onboardingMix :: Int -> [Text]
onboardingMix proxyPort =
    [localhost proxyPort <> "/npm/" <> cpName cp <> "/-/" <> unscopedName (cpPackage cp) <> "-" <> onboardingVersion <> ".tgz" | cp <- corpusPackages]

-- Read each corpus package's captured packument into a name-to-body map at boot. A
-- missing or empty capture fails loudly, a literal harness failure rather than a result.
loadServeBodies :: IO (Map Text LByteString)
loadServeBodies = Map.fromList <$> traverse load corpusPackages
  where
    load cp = do
        packument <- readFileLBS (cpPath cp)
        when (LBS.null packument) (benchFail ("bench-load: corpus capture is empty: " <> toText (cpPath cp)))
        pure (cpName cp, packument)

-- | A trusted-private overlay for the requested package: three versions disjoint from any real version and old enough to clear the quarantine, so the merge serves a genuine union.
privateOverlay :: Text -> Text -> Value
privateOverlay authority name =
    packumentValue
        name
        "9999.0.2"
        [(version, overlayVersionObject authority name version) | version <- overlayVersions]
        (("created" .= publishedLongAgo) : [Key.fromText version .= publishedLongAgo | version <- overlayVersions])
        ["_id" .= name]
  where
    overlayVersions :: [Text]
    overlayVersions = ["9999.0.0", "9999.0.1", "9999.0.2"]

overlayVersionObject :: Text -> Text -> Text -> Value
overlayVersionObject authority name version =
    versionValue
        ( (versionSpec name version (authority <> "/" <> name <> "/-/" <> unscoped <> "-" <> version <> ".tgz"))
            { vsIntegrity = Just validSha512Sri
            , vsShasum = Just validSha1
            }
        )
  where
    unscoped = tarballStem name

-- The npm tarball filename stem for a requested wire name: a scoped @scope/name drops
-- its scope. A stub recovers the stem from the path, with no PackageName at hand.
tarballStem :: Text -> Text
tarballStem name = case T.breakOn "/" name of
    (scope, base)
        | "@" `T.isPrefixOf` scope && not (T.null base) -> T.drop 1 base
    _ -> name

packageText :: Text
packageText = "bench-pkg"

packageName :: PackageName
packageName = mkPackageName Npm Nothing packageText

-- A fixed wall clock, so the age-based admission is deterministic across runs.
benchNow :: UTCTime
benchNow = UTCTime (fromGregorian 2026 6 1) 0

-- An ISO-8601 instant 400 days before 'benchNow', comfortably past any short quarantine,
-- so the gate admits every canned version.
publishedLongAgo :: Text
publishedLongAgo = toText (iso8601Show (addUTCTime (negate (400 * nominalDay)) benchNow))
