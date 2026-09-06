-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Unit cover for the core serve handlers ("Ecluse.Core.Server.Pipeline") driven
__directly__ over a 'ServeRuntime' of test doubles, with no application 'Env' and no
OpenTelemetry SDK.

This is the partition's proof that the request pipeline is genuinely core. It builds the
request runtime from a recording metrics port, a pass-through tracing port, an in-memory
queue, and a real cache and HTTP manager. It then runs the handlers through the core
'runHandler' against a scribe-less @katip@ environment. The handlers serve a merged
packument and a gated tarball, degrade to an unavailability when no upstream resolves,
and stub an unwired mount. The recording port confirms the serve decision each path
recorded through the interface. The integration suite's @Ecluse.Core.Server.PipelineIntegrationSpec@
covers the exhaustive serve-path behaviour (every status, the credential split, the
merge) through the real stack. These cases pin that the handlers run over the ports.
-}
module Ecluse.Core.Server.PipelineSpec (spec) where

import Data.Aeson (Value, encode, (.=))
import Data.ByteString.Lazy qualified as LBS
import Data.List (lookup)
import Data.Time (UTCTime (UTCTime), fromGregorian, nominalDay)
import Network.HTTP.Client (defaultManagerSettings, newManager)
import Network.HTTP.Types (hContentType, status200, status404, statusCode)

import Ecluse.Core.Credential (ClientCredential (credSecret), bareCredential, mkSecret, unSecret)
import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.Package (PackageName, mkPackageName)
import Ecluse.Core.Registry.Npm.Credential (npmCredential)
import Ecluse.Core.Registry.Npm.Route (
    npmPackumentContract,
    npmPackumentReplies,
    npmRouter,
    npmTarballContract,
    npmTarballReplies,
 )
import Ecluse.Core.Registry.Request (CredentialMapping, credentialMapping)
import Ecluse.Core.Rules (prepare)
import Ecluse.Core.Rules.Types (PrecededRule, Rule (AllowIfOlderThan))
import Ecluse.Core.Security.Egress.DevHttp (loopbackRegistryUrl)
import Ecluse.Core.Server.Admission (ServeAdmission, newServeAdmission, newServeAdmissionTuned, withServeAdmission)
import Ecluse.Core.Server.Cache (newMetadataCache)
import Ecluse.Core.Server.Context (
    Handler,
    MountBinding (..),
    PackumentDeps (..),
    RequestCtx (RequestCtx),
    ServeRuntime (ServeRuntime, srMetrics),
    runHandler,
 )
import Ecluse.Core.Server.Contract (ResponseContract, responseToWai)
import Ecluse.Core.Server.Pipeline (servePackument, serveTarball)
import Ecluse.Core.Server.Pipeline.Publish ()
import Ecluse.Core.Server.Pipeline.Shared (hRetryAfter)
import Ecluse.Core.Server.Upstream (MirrorServePlan (MirrorOnAdmit))
import Ecluse.Core.Telemetry.Metrics (Decision (Admit, Deny, Unavailable))
import Ecluse.Core.Telemetry.Record (MetricsPort)
import Ecluse.Core.Version (mkVersion)
import Ecluse.Test.Log (newTestLogEnv)
import Ecluse.Test.Package (sriSha512Of, unsafeFilename)
import Ecluse.Test.Port (passthroughTracingPort, recordingDivergenceMetricsPort, recordingMetricsPort)
import Ecluse.Test.Queue (newTestMemoryQueue)
import Ecluse.Test.Registry.Npm (VersionSpec (vsIntegrity), packumentValue, versionSpec, versionValue)
import Ecluse.Test.Rules (atDefaultPrecedence, inertRuleDeps)
import Ecluse.Test.Server.Cache (defaultCacheConfig)
import Ecluse.Test.Server.Mount (npmServeDeps, withPrivateBaseUrl)
import Network.HTTP.Types.Header (RequestHeaders, hHost)
import Network.Wai (Application, Request (rawPathInfo, requestHeaders), Response, defaultRequest, responseHeaders, responseLBS, responseStatus)
import Network.Wai.Handler.Warp (testWithApplication)
import Network.Wai.Internal (ResponseReceived (ResponseReceived))
import Test.Hspec
import UnliftIO.Exception (throwString)

spec :: Spec
spec = describe "Ecluse.Core.Server.Pipeline (core handlers over a ServeRuntime)" $ do
    it "serves a merged packument and records an admit through the metrics port" $
        testWithApplication (pure upstreamApp) $ \port -> do
            (metricsPort, decisions) <- recordingMetricsPort
            rt <- mkRuntime metricsPort
            deps <- depsFor port
            resp <- captureServe npmPackumentContract rt (mountWith deps) (servePackument npmPackumentReplies leftpad defaultRequest)
            statusCode (responseStatus resp) `shouldBe` 200
            decisions >>= (`shouldBe` [Admit])

    it "logs and meters a cross-upstream integrity divergence, still serving the trusted copy (warn)" $
        -- Both origins resolve leftpad 1.0.0 but contradict on the shared SHA-512 digest,
        -- so the merge records a divergence (threat #11). Under the default warn policy the
        -- pipeline serves the trusted copy (200) and the divergence counter fires once.
        testWithApplication (pure upstreamApp) $ \publicPort ->
            testWithApplication (pure divergentPrivateApp) $ \privatePort -> do
                (metricsPort, divergences) <- recordingDivergenceMetricsPort
                rt <- mkRuntime metricsPort
                baseDeps <- depsFor publicPort
                let deps = withPrivateBaseUrl (Just (loopbackRegistryUrl ("http://localhost:" <> show privatePort))) baseDeps
                resp <- captureServe npmPackumentContract rt (mountWith deps) (servePackument npmPackumentReplies leftpad defaultRequest)
                statusCode (responseStatus resp) `shouldBe` 200
                divergences >>= (`shouldBe` 1)

    it "records an unavailability and renders 503 when no upstream resolves" $ do
        (metricsPort, decisions) <- recordingMetricsPort
        rt <- mkRuntime metricsPort
        -- 'depsFor 1' points both origins at a closed port, which refuses each fetch.
        deps <- depsFor 1
        resp <- captureServe npmPackumentContract rt (mountWith deps) (servePackument npmPackumentReplies leftpad defaultRequest)
        statusCode (responseStatus resp) `shouldBe` 503
        decisions >>= (`shouldBe` [Unavailable])

    it "admits exactly the credential presentation the mount's ecosystem declares" $ do
        (metricsPort, _decisions) <- recordingMetricsPort
        rt <- mkRuntime metricsPort
        -- Both origins point at a closed port, so a 503 means the edge admitted the request and a
        -- 401 is the gate's own refusal. The mounts differ only in credential presentation.
        gated <- gatedDeps
        let serveUnder mapping headers =
                statusCode . responseStatus
                    <$> captureServe
                        npmPackumentContract
                        rt
                        (mountUnder mapping gated)
                        (servePackument npmPackumentReplies leftpad (requestWith headers))
        serveUnder npmCredential [("Authorization", "Bearer " <> edgeToken)] >>= (`shouldBe` 503)
        serveUnder npmCredential [("X-Api-Key", edgeToken)] >>= (`shouldBe` 401)
        serveUnder apiKeyCredential [("X-Api-Key", edgeToken)] >>= (`shouldBe` 503)
        serveUnder apiKeyCredential [("Authorization", "Bearer " <> edgeToken)] >>= (`shouldBe` 401)

    it "serves a gated tarball and records an admit, driving the metrics and tracing ports" $
        testWithApplication (pure upstreamApp) $ \port -> do
            (metricsPort, decisions) <- recordingMetricsPort
            rt <- mkRuntime metricsPort
            deps <- depsFor port
            resp <-
                captureServe
                    npmTarballContract
                    rt
                    (mountWith deps)
                    (serveTarball npmTarballReplies leftpad (mkVersion Npm "1.0.0") (unsafeFilename "leftpad-1.0.0.tgz") defaultRequest)
            statusCode (responseStatus resp) `shouldBe` 200
            decisions >>= (`shouldBe` [Admit])

    it "keeps a first-party packument off the public upstream, answering 404 on a private miss" $ do
        (metricsPort, decisions) <- recordingMetricsPort
        rt <- mkRuntime metricsPort
        hits <- newIORef (0 :: Int)
        testWithApplication (pure (countingUpstream hits upstreamApp)) $ \port -> do
            base <- depsFor port
            -- Each predicate reads the requested name, as the one the composition root derives
            -- does, rather than answering a constant whatever it is asked.
            let serveUnder firstParty =
                    captureServe
                        npmPackumentContract
                        rt
                        (mountWith base{pdFirstParty = firstParty})
                        (servePackument npmPackumentReplies leftpad defaultRequest)
            -- The first-party serve runs first, against a cold metadata cache, so a zero count
            -- means the public leg was never entered rather than answered from a cache entry.
            firstParty <- serveUnder (== leftpad)
            statusCode (responseStatus firstParty) `shouldBe` 404
            readIORef hits >>= (`shouldBe` 0)
            decisions >>= (`shouldBe` [Deny])
            -- The control: the same live upstream serves the same name once it is not first-party.
            thirdParty <- serveUnder (/= leftpad)
            statusCode (responseStatus thirdParty) `shouldBe` 200
            readIORef hits >>= (`shouldSatisfy` (> 0))
            decisions >>= (`shouldBe` [Deny, Admit])

    it "keeps a first-party artifact off the public upstream, answering 404 after a private miss" $ do
        (metricsPort, decisions) <- recordingMetricsPort
        rt <- mkRuntime metricsPort
        hits <- newIORef (0 :: Int)
        testWithApplication (pure (countingUpstream hits upstreamApp)) $ \port -> do
            base <- depsFor port
            let serveUnder firstParty =
                    captureServe
                        npmTarballContract
                        rt
                        (mountWith base{pdFirstParty = firstParty})
                        (serveTarball npmTarballReplies leftpad (mkVersion Npm "1.0.0") (unsafeFilename "leftpad-1.0.0.tgz") defaultRequest)
            firstParty <- serveUnder (== leftpad)
            statusCode (responseStatus firstParty) `shouldBe` 404
            readIORef hits >>= (`shouldBe` 0)
            decisions >>= (`shouldBe` [Deny])
            thirdParty <- serveUnder (/= leftpad)
            statusCode (responseStatus thirdParty) `shouldBe` 200
            readIORef hits >>= (`shouldSatisfy` (> 0))
            decisions >>= (`shouldBe` [Deny, Admit])

    it "sheds packument work when metadata admission refuses" $ do
        (metricsPort, _decisions) <- recordingMetricsPort
        -- No waiting room, so admission refuses the saturated attempt outright. These cases own the
        -- refusal rendering (503 plus Retry-After), and AdmissionSpec owns the wait semantics.
        admission <- newServeAdmissionTuned 1 0 0
        rt <- mkRuntimeWith admission metricsPort
        deps <- depsFor 1
        held <- withServeAdmission (srMetrics rt) admission (captureServe npmPackumentContract rt (mountWith deps) (servePackument npmPackumentReplies leftpad defaultRequest))
        response <- maybe (expectationFailure "failed to acquire the test's outer admission slot" >> throwString "unreachable") pure held
        statusCode (responseStatus response) `shouldBe` 503
        (snd <$> find ((== hRetryAfter) . fst) (responseHeaders response)) `shouldBe` Just "1"

    it "releases metadata admission after an admitted operation completes" $
        testWithApplication (pure upstreamApp) $ \port -> do
            (metricsPort, _decisions) <- recordingMetricsPort
            admission <- newServeAdmissionTuned 1 0 0
            rt <- mkRuntimeWith admission metricsPort
            deps <- depsFor port
            saturated <- withServeAdmission (srMetrics rt) admission (captureServe npmPackumentContract rt (mountWith deps) (servePackument npmPackumentReplies leftpad defaultRequest))
            (statusCode . responseStatus <$> saturated) `shouldBe` Just 503
            admitted <- captureServe npmPackumentContract rt (mountWith deps) (servePackument npmPackumentReplies leftpad defaultRequest)
            statusCode (responseStatus admitted) `shouldBe` 200

    it "sheds a tarball miss when its public metadata gate cannot acquire admission" $ do
        (metricsPort, _decisions) <- recordingMetricsPort
        admission <- newServeAdmissionTuned 1 0 0
        rt <- mkRuntimeWith admission metricsPort
        deps <- depsFor 1
        held <-
            withServeAdmission (srMetrics rt) admission $
                captureServe
                    npmTarballContract
                    rt
                    (mountWith deps)
                    (serveTarball npmTarballReplies leftpad (mkVersion Npm "1.0.0") (unsafeFilename "leftpad-1.0.0.tgz") defaultRequest)
        response <- maybe (expectationFailure "failed to acquire the test's outer admission slot" >> throwString "unreachable") pure held
        statusCode (responseStatus response) `shouldBe` 503
        (snd <$> find ((== hRetryAfter) . fst) (responseHeaders response)) `shouldBe` Just "1"

    it "does not hold metadata admission around a trusted private tarball stream" $
        testWithApplication (pure upstreamApp) $ \port -> do
            (metricsPort, _decisions) <- recordingMetricsPort
            admission <- newServeAdmission 1
            rt <- mkRuntimeWith admission metricsPort
            deps <- depsFor 1
            let privateDeps = withPrivateBaseUrl (Just (loopbackRegistryUrl ("http://localhost:" <> show port))) deps
            held <-
                withServeAdmission (srMetrics rt) admission $
                    captureServe
                        npmTarballContract
                        rt
                        (mountWith privateDeps)
                        (serveTarball npmTarballReplies leftpad (mkVersion Npm "1.0.0") (unsafeFilename "leftpad-1.0.0.tgz") defaultRequest)
            (statusCode . responseStatus <$> held) `shouldBe` Just 200

{- | Run a serve handler over a request runtime and mount, capturing the 'Response' it hands its
continuation. The @katip@ environment has no scribe and no active span, so warnings go nowhere
and no @dd@ object is attached.
-}
captureServe :: ResponseContract response -> ServeRuntime -> MountBinding -> ((response -> IO ResponseReceived) -> Handler ResponseReceived) -> IO Response
captureServe contract rt binding mkHandler = do
    logEnv <- newTestLogEnv
    captured <- newIORef Nothing
    let respond value = writeIORef captured (Just (responseToWai contract value)) >> pure ResponseReceived
    _ <- runHandler logEnv mempty (RequestCtx rt binding) (mkHandler respond)
    maybe (throwString "the handler produced no response") pure =<< readIORef captured

{- | A request runtime over the recording metrics port, sharing one no-TLS manager across both
legs.
-}
mkRuntime :: MetricsPort -> IO ServeRuntime
mkRuntime metricsPort = do
    -- Capacity high enough that this handle never gates. The admission cases wrap
    -- 'withServeAdmission' with their own tuned handle.
    admission <- newServeAdmission 1_000_000
    mkRuntimeWith admission metricsPort

mkRuntimeWith :: ServeAdmission -> MetricsPort -> IO ServeRuntime
mkRuntimeWith admission metricsPort = do
    manager <- newManager defaultManagerSettings
    cache <- newMetadataCache defaultCacheConfig
    queue <- newTestMemoryQueue
    pure (ServeRuntime admission manager manager cache queue metricsPort passthroughTracingPort)

leftpad :: PackageName
leftpad = mkPackageName Npm Nothing "leftpad"

-- | An npm mount over the given serve dependencies (or 'Nothing' for the unwired stub).
mountWith :: PackumentDeps -> MountBinding
mountWith = mountUnder npmCredential

-- | An npm mount carrying the given credential presentation.
mountUnder :: CredentialMapping -> PackumentDeps -> MountBinding
mountUnder mapping deps =
    MountBinding
        { bindingPrefix = "npm" :| []
        , bindingRouter = npmRouter
        , bindingCredential = mapping
        , bindingPackumentDeps = deps
        , bindingPublishDeps = Nothing
        }

{- | A presentation that carries a raw token on @X-Api-Key@, a form npm does not present. A mount
declaring it accepts what an npm mount refuses, and refuses what an npm mount accepts.
-}
apiKeyCredential :: CredentialMapping
apiKeyCredential = credentialMapping recoverApiKey "X-Api-Key" (encodeUtf8 . unSecret . credSecret)
  where
    recoverApiKey headers = bareCredential . mkSecret . decodeUtf8 <$> lookup "X-Api-Key" headers

-- | The token a gated mount requires at its edge, in the form a client presents it.
edgeToken :: (IsString s) => s
edgeToken = "edge-token"

{- | Serve dependencies whose edge requires 'edgeToken' and whose origins both point at a
closed port, so an admitted request degrades rather than reaching an upstream.
-}
gatedDeps :: IO PackumentDeps
gatedDeps = do
    base <- depsFor 1
    pure base{pdInboundToken = Just (mkSecret edgeToken)}

-- | A request presenting the given headers, otherwise the WAI default.
requestWith :: RequestHeaders -> Request
requestWith headers = defaultRequest{requestHeaders = headers}

{- | Serve dependencies pointing the public origin at the in-process upstream on @publicPort@ and
the private origin at a closed port. The stubs use the @localhost@ DNS name, because the
internal-range block recognises only a literal address and must not fire on the artifact leg.
-}
depsFor :: Int -> IO PackumentDeps
depsFor publicPort = do
    prepared <- prepare inertRuleDeps allowPolicy
    pure
        ( npmServeDeps
            (Just (loopbackRegistryUrl "http://localhost:1"))
            (loopbackRegistryUrl ("http://localhost:" <> show publicPort))
            (MirrorOnAdmit (loopbackRegistryUrl "http://mirror.test"))
            prepared
            (pure fixedNow)
        )
            { pdMountBaseUrl = "http://proxy.test"
            , pdEgressUrl = Right . loopbackRegistryUrl
            }

{- | A pure rule policy that admits the fixture version. The engine is deny-by-default, so an
empty policy denies everything, and this quarantine rule admits the 2019 fixture against a 2020
@now@.
-}
allowPolicy :: [PrecededRule]
allowPolicy = [atDefaultPrecedence (AllowIfOlderThan (7 * nominalDay))]

-- | A fixed wall clock against which the fixture version reads as well-aged.
fixedNow :: UTCTime
fixedNow = UTCTime (fromGregorian 2020 1 1) 0

{- | A minimal npm upstream serving @leftpad@ and its self-hosted tarball. It takes the host from
the request, so the tarball URL carries the ephemeral test port, and its @integrity@ is a real
SHA-512 over the bytes it serves.
-}
upstreamApp :: Application
upstreamApp req respond =
    case rawPathInfo req of
        "/leftpad" ->
            respond (responseLBS status200 [(hContentType, "application/json")] (encode (packumentFor host)))
        "/leftpad/-/leftpad-1.0.0.tgz" ->
            respond (responseLBS status200 [(hContentType, "application/octet-stream")] (LBS.fromStrict artifactBytes))
        _ -> respond (responseLBS status404 [] "")
  where
    host = maybe "localhost" snd (find ((== hHost) . fst) (requestHeaders req))

{- | An upstream that counts every request before delegating. A first-party serve that reached
the public leg would leave a count behind.
-}
countingUpstream :: IORef Int -> Application -> Application
countingUpstream hits app req respond = modifyIORef' hits (+ 1) >> app req respond

-- | The artifact bytes the upstream serves and the packument's @integrity@ commits to.
artifactBytes :: ByteString
artifactBytes = "leftpad artifact bytes"

{- | A one-version packument for @leftpad@, its tarball self-hosted on @host@, committing
to the given @integrity@ string (so a divergent copy differs only in that digest).
-}
packumentWithIntegrity :: ByteString -> Text -> Value
packumentWithIntegrity host integrity =
    packumentValue
        "leftpad"
        "1.0.0"
        [
            ( "1.0.0"
            , versionValue
                ( (versionSpec "leftpad" "1.0.0" ("http://" <> decodeUtf8 host <> "/leftpad/-/leftpad-1.0.0.tgz"))
                    { vsIntegrity = Just integrity
                    }
                )
            )
        ]
        ["1.0.0" .= ("2019-01-01T00:00:00.000Z" :: Text)]
        []

-- | The public copy's packument: its integrity is a real SHA-512 over the served bytes.
packumentFor :: ByteString -> Value
packumentFor host = packumentWithIntegrity host (sha512Integrity artifactBytes)

-- | The Subresource-Integrity @sha512-<base64>@ string over the given bytes.
sha512Integrity :: ByteString -> Text
sha512Integrity = sriSha512Of

{- | A private (trusted) upstream whose @leftpad@ 1.0.0 integrity contradicts the public copy on
the shared SHA-512 algorithm. It serves only the packument route, because the merge decides the
divergence on metadata and never fetches a tarball.
-}
divergentPrivateApp :: Application
divergentPrivateApp req respond =
    case rawPathInfo req of
        "/leftpad" ->
            respond (responseLBS status200 [(hContentType, "application/json")] (encode (packumentForDivergent host)))
        _ -> respond (responseLBS status404 [] "")
  where
    host = maybe "localhost" snd (find ((== hHost) . fst) (requestHeaders req))

{- | The private copy's packument: a well-formed SHA-512 digest over /different/ bytes, so
it contradicts 'packumentFor' on the shared algorithm while still meeting the floor.
-}
packumentForDivergent :: ByteString -> Value
packumentForDivergent host = packumentWithIntegrity host (sha512Integrity "leftpad artifact bytes (privately tampered)")
