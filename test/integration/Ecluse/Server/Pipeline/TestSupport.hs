-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT
{-# LANGUAGE RankNTypes #-}

{- | Local registry doubles and proxy fixtures for read-path policy tests.
Doubles record credentials, artifact methods, and validators so tests can verify upstream requests.
-}
module Ecluse.Server.Pipeline.TestSupport (
    -- * The fixed clock
    publishedDaysAgo,

    -- * Upstream doubles
    Upstream,
    recordingUpstream,
    upstreamRespondingWith,
    truncatedResponse,
    servingUpstream,
    servingUpstreamPer,
    failingUpstream,
    mutatingUpstream,
    twoServingUpstreams,
    artifactUpstream,
    artifactUpstreamAnswering,
    artifactUpstreamServing,
    conditionalArtifactUpstream,
    crossHostPublicUpstream,
    honouredPathUpstream,
    offConventionPrivateUpstream,
    privateArtifactHit,
    privateArtifactHitWithHeader,
    privateArtifactHitHashless,
    privateArtifactHitShasumOnly,
    privateArtifactMiss,
    privateArtifactMidStreamFailure,

    -- * What a double saw
    seenAuth,
    seenArtifactMethods,
    seenArtifactValidators,

    -- * Packument and version fixtures
    packument,
    packumentNamed,
    privatePackument,
    privatePackumentWith,
    admittingPublic,
    encodePackument,
    versionObject,
    plainVersion,
    shasumOnlyVersion,
    hashlessVersion,
    emptyDigestVersion,
    selfHostedVersion,
    selfHostedHashless,
    selfHostedShasumOnly,
    selfHostedEmptyDigest,
    sriFor,
    sri256For,
    privateTarballBytes,
    publicTarballBytes,

    -- * The proxy harness
    newTestEnvWithQueue,
    withProxyOver,
    withProxyEnvQueueDeps,
    withProxyEnvQueue,
    withProxyEnv,
    withProxy,
    withProxyEffectful,

    -- * Request drivers
    getPath,
    requestAt,
    getPathWith,
    postPath,
    getThing,
    getThingWith,
    headThing,
    headThingWith,
    getTarball,
    getTarballWith,
    headTarball,

    -- * Reading a served document
    topLevel,
    servedVersionKey,
    servedTarball,
    servedIntegrity,
    servedLatest,

    -- * The mirror queue
    drainJobs,
    jobShape,
    newFailingQueue,
) where

import Prelude hiding (get)

import Data.Aeson (Value (Object, String), (.=))
import Data.Aeson qualified as Aeson
import Data.Aeson.Key qualified as Key
import Data.Aeson.KeyMap qualified as KeyMap
import Data.ByteString qualified as BS
import Data.CaseInsensitive qualified as CI
import Data.List (lookup)
import Data.Text qualified as T
import Data.Time (UTCTime (UTCTime), fromGregorian, nominalDay)
import Katip (LogEnv)
import Network.HTTP.Client (Manager, defaultManagerSettings, newManager)
import Network.HTTP.Types (Header, Method, Status, hAuthorization, methodGet, methodHead, methodPost, status200, status304, status404, status500, statusCode, statusMessage)
import Network.HTTP.Types.Header (hETag, hHost)
import Network.Wai (Application, Request (rawPathInfo, requestHeaders, requestMethod), Response, responseLBS, responseRaw)
import Network.Wai.Handler.Warp (testWithApplication)
import Network.Wai.Test (SResponse, defaultRequest, request, runSession, setPath)

import Ecluse (mountBindingFor)
import Ecluse.Core.Credential (mkSecret)
import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.Fault (TransportCause (TransportUnreachable), transportFault)
import Ecluse.Core.Package (PackageName)
import Ecluse.Core.Queue (
    MirrorJob (jobArtifactFilename, jobArtifactUrl, jobPackage, jobVersion),
    MirrorQueue (enqueue, receive),
    QueueMessage (msgJob),
 )
import Ecluse.Core.Rules (PreparedRule, prepare)
import Ecluse.Core.Rules.Types (
    PrecededRule,
    Rule (AllowIfOlderThan, DenyInstallTimeExecution),
 )
import Ecluse.Core.Security.Egress (registryUrlText)
import Ecluse.Core.Security.Egress.DevHttp (loopbackRegistryUrl)
import Ecluse.Core.Server.Context (PackumentDeps (..))
import Ecluse.Core.Server.Path (unFilename)
import Ecluse.Core.Server.Upstream (MirrorServePlan (MirrorOnAdmit))
import Ecluse.Core.Version (Version)
import Ecluse.Runtime.Env (Env (envQueue))
import Ecluse.Runtime.Server (
    application,
    mkServerConfig,
 )
import Ecluse.Runtime.Telemetry (telemetryDisabled)
import Ecluse.Runtime.Test.Support (newTestEnvLogging, newTestEnvWith)
import Ecluse.Test.Log (newTestLogEnv)
import Ecluse.Test.Package (sriSha256Of, sriSha512Of)
import Ecluse.Test.Queue (newTestMemoryQueue)
import Ecluse.Test.Registry.Npm (VersionSpec (..), packumentValue, versionSpec, versionValue)
import Ecluse.Test.Registry.Npm qualified as NpmFixture (publishedDaysAgo)
import Ecluse.Test.Rules (atDefaultPrecedence, inertRuleDeps)
import Ecluse.Test.Server.Mount (npmServeDeps)
import Ecluse.Test.Wai (decodedBody, localhost, lookupAuth, lookupIfNoneMatch, rebaseAuthority, selfBaseUrl)

-- | A fixed "now" so the age-based admit/deny axis is deterministic under test.
now :: UTCTime
now = UTCTime (fromGregorian 2026 6 20) 0

-- | Keep version age relative to the fixture's fixed clock.
publishedDaysAgo :: Integer -> Text
publishedDaysAgo = NpmFixture.publishedDaysAgo now

-- | The policy under test: a 7-day publish-age quarantine plus an install-script deny.
policy :: [PrecededRule]
policy =
    [ atDefaultPrecedence (AllowIfOlderThan (7 * nominalDay))
    , atDefaultPrecedence DenyInstallTimeExecution
    ]

-- | Record credentials, artifact methods, and conditional validators received by a local upstream.
data Upstream = Upstream
    { upApp :: Application
    , upSeenAuth :: IORef [Maybe ByteString]
    , upSeenArtifactMethods :: IORef [ByteString]
    , upSeenArtifactValidators :: IORef [Maybe ByteString]
    }

-- | An upstream double answering each request with the given response.
recordingUpstream :: (Request -> Response) -> IO Upstream
recordingUpstream respondTo = recordingUpstreamIO (pure . respondTo)

-- | 'recordingUpstream' over an effectful responder, for a double whose answer depends on what it already served.
recordingUpstreamIO :: (Request -> IO Response) -> IO Upstream
recordingUpstreamIO respondTo = do
    seen <- newIORef []
    mkUpstream seen $ \req respond -> do
        modifyIORef' seen (lookupAuth (requestHeaders req) :)
        respondTo req >>= respond

-- | An upstream double answering every request with one fixed response.
upstreamRespondingWith :: Response -> IO Upstream
upstreamRespondingWith response = recordingUpstream (const response)

-- | Serve metadata with artifact locations rebased to the local upstream's authority.
servingUpstream :: LByteString -> IO Upstream
servingUpstream = servingUpstreamPer . const

-- | 'servingUpstream' over a body that depends on the request, for a double whose answer turns on what the client sent.
servingUpstreamPer :: (Request -> LByteString) -> IO Upstream
servingUpstreamPer bodyFor =
    recordingUpstream (\req -> bodyAt (\base -> rebaseAuthority fixtureAuthority base (bodyFor req)) req)

-- | An upstream double that always answers @500@: a failed or unavailable upstream, for the partial-upstream-availability and no-survivors paths.
failingUpstream :: IO Upstream
failingUpstream = upstreamRespondingWith (responseLBS status500 [] "upstream error")

-- | Advance through response bodies, retaining the final body for later requests.
mutatingUpstream :: NonEmpty LByteString -> IO Upstream
mutatingUpstream bodies = do
    remaining <- newIORef (toList bodies)
    recordingUpstreamIO $ \req -> do
        body <- atomicModifyIORef' remaining serveNext
        pure (bodyAt (\base -> rebaseAuthority fixtureAuthority base body) req)
  where
    -- Serve the head and advance, but hold on the last body once exhausted.
    serveNext :: [LByteString] -> ([LByteString], LByteString)
    serveNext (b : rest@(_ : _)) = (rest, b)
    serveNext [b] = ([b], b)
    serveNext [] = ([], "")

-- The auth headers an upstream double saw, in arrival order.
seenAuth :: Upstream -> IO [Maybe ByteString]
seenAuth up = reverse <$> readIORef (upSeenAuth up)

-- The HTTP methods an upstream double saw on artifact-slot requests, in arrival order. A test
-- asserts a HEAD reached upstream as a HEAD, never as a body-pumping GET.
seenArtifactMethods :: Upstream -> IO [ByteString]
seenArtifactMethods up = reverse <$> readIORef (upSeenArtifactMethods up)

-- The @If-None-Match@ validators an upstream double saw on artifact-slot requests, in arrival
-- order. 'Nothing' for a request that carried none.
seenArtifactValidators :: Upstream -> IO [Maybe ByteString]
seenArtifactValidators up = reverse <$> readIORef (upSeenArtifactValidators up)

-- | Preserve credential recording while adding artifact method and validator observations.
mkUpstream :: IORef [Maybe ByteString] -> Application -> IO Upstream
mkUpstream seen app = do
    methods <- newIORef []
    validators <- newIORef []
    let recording req respond = do
            when (isTarballPath (rawPathInfo req)) $ do
                modifyIORef' methods (requestMethod req :)
                modifyIORef' validators (lookupIfNoneMatch (requestHeaders req) :)
            app req respond
    pure
        Upstream
            { upApp = recording
            , upSeenAuth = seen
            , upSeenArtifactMethods = methods
            , upSeenArtifactValidators = validators
            }

-- | Whether a request path is a tarball slot (@\/…\/-\/….tgz@) rather than a packument, so one double can answer both.
isTarballPath :: ByteString -> Bool
isTarballPath path = "/-/" `BS.isInfixOf` path && ".tgz" `BS.isSuffixOf` path

-- | Answer a tarball-slot path with the first responder, and every other path with the second.
tarballOr :: (Request -> Response) -> (Request -> Response) -> Request -> Response
tarballOr onTarball onPackument req
    | isTarballPath (rawPathInfo req) = onTarball req
    | otherwise = onPackument req

-- | A responder answering @200@ with fixed bytes and extra headers, whatever the request.
okBytes :: [Header] -> LByteString -> Request -> Response
okBytes extraHeaders body _req = responseLBS status200 extraHeaders body

-- | A @200@ whose body is built from the base URL the request reached the double at.
bodyAt :: (Text -> LByteString) -> Request -> Response
bodyAt bodyFor req = responseLBS status200 [] (bodyFor (selfBaseUrl req))

-- | 'bodyAt' over a packument document rather than raw bytes.
packumentAt :: (Text -> Value) -> Request -> Response
packumentAt documentFor = bodyAt (encodePackument . documentFor)

-- The self-referential packument a path-aware double answers a non-tarball path with.
selfHostedPackument :: Text -> Request -> Response
selfHostedPackument version = packumentAt (`selfHostedAdmitting` version)

-- | An install-script-free version with integrity and an artifact on the given authority.
selfHostedVersion :: Text -> Text -> Value
selfHostedVersion baseUrl version =
    versionValue
        ( (versionFixture version (baseUrl <> "/thing/-/thing-" <> version <> ".tgz"))
            { vsIntegrity = Just (sriFor version)
            , vsShasum = Just validShasum
            }
        )

-- | An admitting public packument (single old-enough version @v@) whose @dist.tarball@ points at @baseUrl@: the self-hosting form the artifact path fetches.
selfHostedAdmitting :: Text -> Text -> Value
selfHostedAdmitting baseUrl v =
    packument [(v, selfHostedVersion baseUrl v)] v [(v, publishedDaysAgo 30)]

-- | Serve a version's metadata and artifact bytes from the same local authority.
artifactUpstream :: Text -> LByteString -> IO Upstream
artifactUpstream version tarballBody =
    recordingUpstream (tarballOr (okBytes [] tarballBody) (selfHostedPackument version))

-- | Like 'artifactUpstream' but answering the artifact slot with the given arbitrary response, for the public-relay verdict cases.
artifactUpstreamAnswering :: Text -> Response -> IO Upstream
artifactUpstreamAnswering version artifactResponse =
    recordingUpstream (tarballOr (const artifactResponse) (selfHostedPackument version))

-- | Like 'artifactUpstream' but serving the given packument body verbatim, for tests that shape the gating packument themselves.
artifactUpstreamServing :: (Text -> LByteString) -> LByteString -> IO Upstream
artifactUpstreamServing packumentFor tarballBody =
    recordingUpstream (tarballOr (okBytes [] tarballBody) (bodyAt packumentFor))

-- | Serve a private artifact at its conventional path without requiring a metadata read.
privateArtifactHit :: Text -> LByteString -> IO Upstream
privateArtifactHit version = privateArtifactHitWith version []

-- | Attach one header to a private artifact response for relay assertions.
privateArtifactHitWithHeader :: ByteString -> ByteString -> Text -> LByteString -> IO Upstream
privateArtifactHitWithHeader headerName headerText version =
    privateArtifactHitWith version [(CI.mk headerName, headerText)]

-- | Serve private bytes and headers alongside metadata that points back to the same upstream.
privateArtifactHitWith :: Text -> [Header] -> LByteString -> IO Upstream
privateArtifactHitWith version extraHeaders tarballBody =
    recordingUpstream (tarballOr (okBytes extraHeaders tarballBody) (selfHostedPackument version))

-- | Serve private bytes whose metadata declares no integrity digest.
privateArtifactHitHashless :: Text -> LByteString -> IO Upstream
privateArtifactHitHashless = privateArtifactHitBelowFloor selfHostedHashless

-- | Serve private bytes whose metadata declares only a SHA-1 shasum.
privateArtifactHitShasumOnly :: Text -> LByteString -> IO Upstream
privateArtifactHitShasumOnly = privateArtifactHitBelowFloor selfHostedShasumOnly

-- The shared private hit whose single version comes from a fixture the public integrity floor
-- would refuse. Its publish time is a day old, so only the private exemption can admit it.
privateArtifactHitBelowFloor :: (Text -> Text -> Value) -> Text -> LByteString -> IO Upstream
privateArtifactHitBelowFloor versionFor version tarballBody =
    recordingUpstream (tarballOr (okBytes [] tarballBody) (packumentAt young))
  where
    young base = packument [(version, versionFor base version)] version [(version, publishedDaysAgo 1)]

-- | Return 404 for the private artifact probe.
privateArtifactMiss :: IO Upstream
privateArtifactMiss =
    recordingUpstream (tarballOr (const (responseLBS status404 [] "not found")) (selfHostedPackument "1.0.0"))

-- | Truncate a committed private 200 response to test failure without public fallback.
privateArtifactMidStreamFailure :: IO Upstream
privateArtifactMidStreamFailure =
    recordingUpstream (tarballOr (const (truncatedResponse status200 (BS.replicate 1024 0x7a))) (selfHostedPackument "1.0.0"))

-- | A response that closes before its declared body length, preserving the given status.
truncatedResponse :: Status -> ByteString -> Response
truncatedResponse status body = responseRaw truncated (responseLBS status500 [] "raw unsupported")
  where
    truncated :: IO ByteString -> (ByteString -> IO ()) -> IO ()
    truncated _recv send = do
        send ("HTTP/1.1 " <> show (statusCode status) <> " " <> statusMessage status <> "\r\nContent-Length: 1048576\r\n\r\n")
        send body

-- | Declare a separate artifact host. Use a @*.localhost@ name that resolves to the local stub.
crossHostPublicUpstream :: Text -> Text -> LByteString -> IO Upstream
crossHostPublicUpstream crossHost version tarballBody =
    recordingUpstream (tarballOr (okBytes [] tarballBody) crossHostPackument)
  where
    -- The dist.tarball names @crossHost@ at this same port, so the policy sees a cross-host URL.
    crossHostPackument req =
        let port = snd (T.breakOnEnd ":" (decodeUtf8 (fromMaybe "" (lookup hHost (requestHeaders req)))))
            tarballBase = "http://" <> crossHost <> ":" <> port
         in responseLBS status200 [] (encodePackument (selfHostedAdmitting tarballBase version))

-- | Declare an off-convention artifact URL while serving any requested @.tgz@ path.
honouredPathUpstream :: Text -> Text -> LByteString -> IO Upstream
honouredPathUpstream version filename tarballBody = recordingUpstream answer
  where
    answer req
        | ".tgz" `BS.isSuffixOf` rawPathInfo req = responseLBS status200 [] tarballBody
        | otherwise = packumentAt altPackument req

    altPackument base =
        let vo =
                versionValue
                    ( (versionSpec "thing" version (base <> "/files/" <> filename))
                        { vsIntegrity = Just (sriFor version)
                        }
                    )
         in packument [(version, vo)] version [(version, publishedDaysAgo 30)]

-- | Serve bytes only at @/files/{filename}@, returning 404 for a conventional private probe.
offConventionPrivateUpstream :: Text -> LByteString -> IO Upstream
offConventionPrivateUpstream filename tarballBody = recordingUpstream answer
  where
    answer req
        | rawPathInfo req == encodeUtf8 ("/files/" <> filename) = responseLBS status200 [] tarballBody
        | otherwise = responseLBS status404 [] "not found"

-- | Answer conditional artifact requests with 304 and an ETag, otherwise return the bytes.
conditionalArtifactUpstream :: Text -> LByteString -> IO Upstream
conditionalArtifactUpstream version tarballBody =
    recordingUpstream (tarballOr conditionalTarball (selfHostedPackument version))
  where
    -- A relayed client validator turns the upstream artifact fetch into a 304. An
    -- unconditional fetch still serves the bytes.
    conditionalTarball req
        | isJust (lookupIfNoneMatch (requestHeaders req)) = responseLBS status304 [(hETag, "\"v1\"")] ""
        | otherwise = responseLBS status200 [] tarballBody

-- | Include an unknown top-level field to test lossless metadata assembly.
packument :: [(Text, Value)] -> Text -> [(Text, Text)] -> Value
packument versions latest times =
    packumentValue
        "thing"
        latest
        versions
        (("created" .= publishedDaysAgo 400) : [(Key.fromText version, String time) | (version, time) <- times])
        ["_id" .= ("thing" :: Text)] -- an unmodeled top-level key

-- | Vary the reported package identity while retaining the standard fixture shape.
packumentNamed :: Text -> [(Text, Value)] -> Text -> [(Text, Text)] -> Value
packumentNamed nm versions latest times =
    case packument versions latest times of
        Object o -> Object (KeyMap.insert "name" (String nm) o)
        v -> v

-- | Include an unknown version field and an optional install script.
versionObject :: Text -> Text -> Bool -> Value
versionObject version integrity hasInstall =
    versionValue
        ( (versionFixture version (fixtureAuthority <> "/thing/-/thing-" <> version <> ".tgz"))
            { vsIntegrity = Just integrity
            , vsShasum = Just validShasum
            , vsHasInstallScript = hasInstall
            }
        )

-- | Placeholder authority that serving fixtures replace with their own.
fixtureAuthority :: Text
fixtureAuthority = "https://upstream.example"

-- A @thing@ version fixture with the unmodelled field the relay assertions preserve.
versionFixture :: Text -> Text -> VersionSpec
versionFixture version tarballUrl =
    (versionSpec "thing" version tarballUrl)
        { vsExtraPairs = ["_unmodeled" .= ("kept" :: Text)]
        }

-- A plain (no-install-script) version object with a distinct integrity.
plainVersion :: Text -> Value
plainVersion version = versionObject version (sriFor version) False

-- | Derive reproducible SHA-512 and SHA-256 SRI values from a test label.
sriFor, sri256For :: Text -> Text
sriFor = sriSha512Of . encodeUtf8
sri256For = sriSha256Of . encodeUtf8

-- | A well-formed 40-hex SHA-1 shasum (sha1 of the empty string) for the dist fixtures.
validShasum :: Text
validShasum = "da39a3ee5e6b4b0d3255bfef95601890afd80709"

-- | A version with a SHA-1 shasum and no SRI digest.
shasumOnlyVersion :: Text -> Value
shasumOnlyVersion version =
    versionValue
        ( (versionFixture version (fixtureAuthority <> "/thing/-/thing-" <> version <> ".tgz"))
            { vsShasum = Just validShasum
            }
        )

-- | A version object carrying neither @integrity@ nor @shasum@. The integrity-presence policy refuses such a version from a public upstream.
hashlessVersion :: Text -> Value
hashlessVersion version =
    versionValue (versionFixture version (fixtureAuthority <> "/thing/-/thing-" <> version <> ".tgz"))

-- | Empty digest strings must classify as missing integrity rather than weak integrity.
emptyDigestVersion :: Text -> Value
emptyDigestVersion version =
    versionValue
        ( (versionFixture version (fixtureAuthority <> "/thing/-/thing-" <> version <> ".tgz"))
            { vsIntegrity = Just ""
            , vsShasum = Just ""
            }
        )

-- | A self-hosted version without integrity, for refusal before artifact fetch.
selfHostedHashless :: Text -> Text -> Value
selfHostedHashless baseUrl version =
    versionValue (versionFixture version (baseUrl <> "/thing/-/thing-" <> version <> ".tgz"))

-- | A self-hosted SHA-1-only version, for refusal below the public integrity floor.
selfHostedShasumOnly :: Text -> Text -> Value
selfHostedShasumOnly baseUrl version =
    versionValue
        ( (versionFixture version (baseUrl <> "/thing/-/thing-" <> version <> ".tgz"))
            { vsShasum = Just validShasum
            }
        )

-- | A self-hosted fixture whose empty digest fields must prevent a public artifact fetch.
selfHostedEmptyDigest :: Text -> Text -> Value
selfHostedEmptyDigest baseUrl version =
    versionValue
        ( (versionFixture version (baseUrl <> "/thing/-/thing-" <> version <> ".tgz"))
            { vsIntegrity = Just ""
            , vsShasum = Just ""
            }
        )

-- | A fresh 'Env' over handle doubles and a real (no-TLS) manager, carrying the given mirror queue.
newTestEnvWithQueue :: MirrorQueue -> Manager -> IO Env
newTestEnvWithQueue queue manager = newTestEnvWith queue (manager, manager) telemetryDisabled

-- | Use local upstreams, deterministic rules, and an optional edge token.
deps :: Int -> Int -> Maybe Text -> IO PackumentDeps
deps privatePort publicPort inbound = do
    prepared <- prepare inertRuleDeps policy
    pure
        ( npmServeDeps
            (Just (loopbackRegistryUrl (localhost privatePort)))
            (loopbackRegistryUrl (localhost publicPort))
            (MirrorOnAdmit (loopbackRegistryUrl "https://mirror.test"))
            prepared
            (pure now)
        )
            { pdInboundToken = mkSecret <$> inbound
            , pdEgressUrl = Right . loopbackRegistryUrl
            }

-- | Run the proxy over local upstreams with caller-supplied logging, queue, and dependency changes.
withProxyOver ::
    LogEnv ->
    MirrorQueue ->
    Upstream ->
    Upstream ->
    Maybe Text ->
    (PackumentDeps -> PackumentDeps) ->
    -- The continuation sees the proxy application, its 'Env' (to drain the queue),
    -- and the public upstream's ephemeral port (to assert an enqueued artifact URL).
    (forall a. (Application -> Env -> Int -> IO a) -> IO a)
withProxyOver logEnv queue privateUp publicUp inbound tweakDeps k =
    testWithApplication (pure (upApp privateUp)) $ \privatePort ->
        testWithApplication (pure (upApp publicUp)) $ \publicPort -> do
            manager <- newManager defaultManagerSettings
            env <- newTestEnvLogging logEnv queue (manager, manager) telemetryDisabled
            baseDeps <- deps privatePort publicPort inbound
            let cfg = mkServerConfig (maybeToList (mountBindingFor Npm (tweakDeps baseDeps) Nothing))
            k (application cfg env) env publicPort

-- | Apply dependency changes before the proxy handles requests.
withProxyEnvQueueDeps ::
    MirrorQueue ->
    Upstream ->
    Upstream ->
    Maybe Text ->
    (PackumentDeps -> PackumentDeps) ->
    (forall a. (Application -> Env -> Int -> IO a) -> IO a)
withProxyEnvQueueDeps queue privateUp publicUp inbound tweakDeps k = do
    logEnv <- newTestLogEnv
    withProxyOver logEnv queue privateUp publicUp inbound tweakDeps k

-- | Expose the supplied queue while driving a proxy over local upstreams.
withProxyEnvQueue ::
    MirrorQueue ->
    Upstream ->
    Upstream ->
    Maybe Text ->
    (forall a. (Application -> Env -> Int -> IO a) -> IO a)
withProxyEnvQueue queue privateUp publicUp inbound =
    withProxyEnvQueueDeps queue privateUp publicUp inbound id

-- | Expose the proxy environment so tests can inspect queued mirror jobs.
withProxyEnv ::
    Upstream ->
    Upstream ->
    Maybe Text ->
    (forall a. (Application -> Env -> IO a) -> IO a)
withProxyEnv privateUp publicUp inbound k = do
    queue <- newTestMemoryQueue
    withProxyEnvQueue queue privateUp publicUp inbound (\app env _port -> k app env)

-- | Run an assertion against a proxy over the two in-process upstream doubles, without its 'Env'.
withProxy ::
    Upstream ->
    Upstream ->
    Maybe Text ->
    (forall a. (Application -> IO a) -> IO a)
withProxy privateUp publicUp inbound k =
    withProxyEnv privateUp publicUp inbound (\app _env -> k app)

-- | Apply the supplied effectful rules to public versions through the proxy.
withProxyEffectful ::
    [PreparedRule] ->
    Upstream ->
    Upstream ->
    (forall a. (Application -> IO a) -> IO a)
withProxyEffectful effectful privateUp publicUp k = do
    queue <- newTestMemoryQueue
    withProxyEnvQueueDeps queue privateUp publicUp Nothing appendEffectful (\app _env _port -> k app)
  where
    appendEffectful d = d{pdRules = pdRules d <> effectful}

-- | A base request carrying the given extra headers (e.g. a conditional @If-None-Match@).
headersRequest :: [Header] -> Request
headersRequest extra = defaultRequest{requestHeaders = extra}

-- | A base request carrying the given bearer credential, if any.
bearerRequest :: Maybe Text -> Request
bearerRequest bearer =
    headersRequest (maybe [] (\t -> [(hAuthorization, "Bearer " <> encodeUtf8 t)]) bearer)

-- | The @thing@ tarball slot under the npm mount, at the given version.
tarballPathFor :: Text -> ByteString
tarballPathFor version = "/npm/thing/-/thing-" <> encodeUtf8 version <> ".tgz"

-- | Drive one request against the proxy: a method and path over the given base request.
requestAt :: Method -> ByteString -> Request -> Application -> IO SResponse
requestAt method path base = runSession (request (setPath base path){requestMethod = method})

-- | A @GET@ at the given path with no credential: the arbitrary-path generalisation of 'getThing'.
getPath :: ByteString -> Application -> IO SResponse
getPath path = requestAt methodGet path defaultRequest

-- | GET with explicit request headers and no implicit credential.
getPathWith :: [Header] -> ByteString -> Application -> IO SResponse
getPathWith extra path = requestAt methodGet path (headersRequest extra)

-- | POST with neither a body nor an implicit credential.
postPath :: ByteString -> Application -> IO SResponse
postPath path = requestAt methodPost path defaultRequest

-- | A @GET \/npm\/thing@ request carrying the given (optional) bearer credential.
getThing :: Maybe Text -> Application -> IO SResponse
getThing bearer = requestAt methodGet "/npm/thing" (bearerRequest bearer)

-- | A @GET \/npm\/thing@ with no credential and the given extra request headers (e.g. a conditional @If-None-Match@).
getThingWith :: [Header] -> Application -> IO SResponse
getThingWith extra = requestAt methodGet "/npm/thing" (headersRequest extra)

-- | HEAD with an optional bearer credential.
headThing :: Maybe Text -> Application -> IO SResponse
headThing bearer = requestAt methodHead "/npm/thing" (bearerRequest bearer)

-- | HEAD with explicit headers for conditional metadata requests.
headThingWith :: [Header] -> Application -> IO SResponse
headThingWith extra = requestAt methodHead "/npm/thing" (headersRequest extra)

-- | A @GET \/npm\/thing\/-\/thing-{version}.tgz@ artifact request carrying the given (optional) bearer credential: the tarball path for @thing@ at one version.
getTarball :: Text -> Maybe Text -> Application -> IO SResponse
getTarball version bearer = requestAt methodGet (tarballPathFor version) (bearerRequest bearer)

-- | A conditional GET for the named tarball version with the supplied request headers.
getTarballWith :: Text -> [Header] -> Application -> IO SResponse
getTarballWith version extra = requestAt methodGet (tarballPathFor version) (headersRequest extra)

-- | A @HEAD \/npm\/thing\/-\/thing-{version}.tgz@ carrying the given optional bearer credential. The serve path must answer without pumping the full artifact body.
headTarball :: Text -> Maybe Text -> Application -> IO SResponse
headTarball version bearer = requestAt methodHead (tarballPathFor version) (bearerRequest bearer)

-- | Return pending mirror jobs in FIFO order, reading until the queue reports an empty batch.
drainJobs :: Env -> IO [MirrorJob]
drainJobs env = go []
  where
    go acc =
        receive (envQueue env) >>= \case
            Right [] -> pure (reverse acc)
            Right messages -> go (reverse (map msgJob messages) <> acc)
            Left fault -> fail ("drainJobs: the in-memory queue faulted: " <> show fault)

-- The value at a top-level key in the served body (for relayed unmodeled keys).
topLevel :: Text -> SResponse -> Maybe Value
topLevel key resp = case decodedBody resp of
    Object o -> KeyMap.lookup (Key.fromText key) o
    _ -> Nothing

-- The value at a top-level @field@ within a served version object.
servedVersionKey :: Text -> Text -> SResponse -> Maybe Value
servedVersionKey version field resp = do
    Object o <- Just (decodedBody resp)
    Object vs <- KeyMap.lookup "versions" o
    Object vo <- KeyMap.lookup (Key.fromText version) vs
    KeyMap.lookup (Key.fromText field) vo

-- A string field of a served version object's @dist@ block.
servedDist :: Text -> Text -> SResponse -> Maybe Text
servedDist version field resp = do
    Object dist <- servedVersionKey version "dist" resp
    String value <- KeyMap.lookup (Key.fromText field) dist
    pure value

-- A version object's @dist.tarball@ in the served body.
servedTarball :: Text -> SResponse -> Maybe Text
servedTarball version = servedDist version "tarball"

-- A served version object's @dist.integrity@.
servedIntegrity :: Text -> SResponse -> Maybe Text
servedIntegrity version = servedDist version "integrity"

-- The served @dist-tags.latest@ target.
servedLatest :: SResponse -> Maybe Text
servedLatest resp = do
    Object o <- Just (decodedBody resp)
    Object tags <- KeyMap.lookup "dist-tags" o
    String latest <- KeyMap.lookup "latest" tags
    pure latest

-- A private packument. Its publish times are incidental: the pipeline skips the rules for a
-- private version, so it trusts one whatever its age.
privatePackument :: [(Text, Value)] -> Text -> Value
privatePackument versions latest =
    packument versions latest [(v, publishedDaysAgo 1) | (v, _) <- versions]

-- A private packument with explicit version objects (used for the divergence test).
privatePackumentWith :: [(Text, Value)] -> Text -> Value
privatePackumentWith = privatePackument

twoServingUpstreams :: IO (Upstream, Upstream)
twoServingUpstreams = do
    privateUp <- servingUpstream (encodePackument (privatePackument [("1.0.0", plainVersion "1.0.0")] "1.0.0"))
    publicUp <-
        servingUpstream
            (encodePackument (packument [("2.0.0", plainVersion "2.0.0")] "2.0.0" [("2.0.0", publishedDaysAgo 30)]))
    pure (privateUp, publicUp)

encodePackument :: Value -> LByteString
encodePackument = Aeson.encode

-- The opaque bytes a tarball double serves, distinct per origin so a test can pin
-- which upstream the served artifact came from.
privateTarballBytes :: LByteString
privateTarballBytes = "PRIVATE-TGZ-BYTES"

publicTarballBytes :: LByteString
publicTarballBytes = "PUBLIC-TGZ-BYTES"

-- A public packument whose single version clears the quarantine. On the packument path the serve
-- path only relays its dist.tarball under the mount base and never fetches it.
admittingPublic :: Text -> Value
admittingPublic v = packument [(v, plainVersion v)] v [(v, publishedDaysAgo 30)]

-- A flat projection of a mirror job, for an order-stable equality assertion over
-- the coordinates the queued worker consumes.
jobShape :: MirrorJob -> (PackageName, Version, Text, Text)
jobShape job = (jobPackage job, jobVersion job, registryUrlText (jobArtifactUrl job), unFilename (jobArtifactFilename job))

newFailingQueue :: IO MirrorQueue
newFailingQueue = do
    queue <- newTestMemoryQueue
    -- The typed producer channel: a backend fault is the 'Left' value the serve
    -- path's best-effort enqueue counts and swallows.
    pure queue{enqueue = \_ -> pure (Left (transportFault TransportUnreachable "enqueue failed (test double)"))}
