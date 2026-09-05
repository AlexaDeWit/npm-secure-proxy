-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT
{-# LANGUAGE RankNTypes #-}

{- | The canonical proxy fixture for the pipeline suites: upstream doubles, npm document
fixtures, the proxy harness, and the request drivers.

Every double routes through one recording constructor, so the credential and
artifact-slot recording is uniform and a double states only how it answers.
-}
module Ecluse.Server.Pipeline.TestSupport (
    -- * The fixed clock
    publishedDaysAgo,

    -- * Upstream doubles
    Upstream,
    recordingUpstream,
    servingUpstream,
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
    withProxyEnvQueueDepsHosts,
    withProxyEnvQueueDeps,
    withProxyEnvQueue,
    withProxyEnv,
    withProxy,
    withProxyEffectful,

    -- * Request drivers
    getPath,
    getPathWith,
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
import Network.HTTP.Types (Header, Method, hAuthorization, methodGet, methodHead, status200, status304, status404, status500)
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
import Ecluse.Test.Server.Mount (npmServeDeps, withEcosystemHosts)
import Ecluse.Test.Wai (decodedBody, localhost, lookupAuth, lookupIfNoneMatch, selfBaseUrl)

-- | A fixed "now" so the age-based admit/deny axis is deterministic under test.
now :: UTCTime
now = UTCTime (fromGregorian 2026 6 20) 0

{- | An ISO-8601 instant @ageDays@ before 'now' (the npm @time@ string), so only a
version's fixture time decides its survival under the quarantine.
-}
publishedDaysAgo :: Integer -> Text
publishedDaysAgo = NpmFixture.publishedDaysAgo now

-- | The policy under test: a 7-day publish-age quarantine plus an install-script deny.
policy :: [PrecededRule]
policy =
    [ atDefaultPrecedence (AllowIfOlderThan (7 * nominalDay))
    , atDefaultPrecedence DenyInstallTimeExecution
    ]

{- | An in-process upstream double that records what each request carried. Tests read the
@Authorization@ header, the artifact-slot method, and its @If-None-Match@ validator.
-}
data Upstream = Upstream
    { upApp :: Application
    , upSeenAuth :: IORef [Maybe ByteString]
    , upSeenArtifactMethods :: IORef [ByteString]
    , upSeenArtifactValidators :: IORef [Maybe ByteString]
    }

-- | An upstream double answering each request with the given response.
recordingUpstream :: (Request -> Response) -> IO Upstream
recordingUpstream respondTo = recordingUpstreamIO (pure . respondTo)

{- | 'recordingUpstream' over an effectful responder, for a double whose answer depends on
what it already served.
-}
recordingUpstreamIO :: (Request -> IO Response) -> IO Upstream
recordingUpstreamIO respondTo = do
    seen <- newIORef []
    mkUpstream seen $ \req respond -> do
        modifyIORef' seen (lookupAuth (requestHeaders req) :)
        respondTo req >>= respond

-- | An upstream double answering every request with one fixed response.
upstreamRespondingWith :: Response -> IO Upstream
upstreamRespondingWith response = recordingUpstream (const response)

-- | An upstream double serving a fixed packument body with @200@.
servingUpstream :: LByteString -> IO Upstream
servingUpstream body = upstreamRespondingWith (responseLBS status200 [] body)

{- | An upstream double that always answers @500@: a failed or unavailable upstream,
for the partial-upstream-availability and no-survivors paths.
-}
failingUpstream :: IO Upstream
failingUpstream = upstreamRespondingWith (responseLBS status500 [] "upstream error")

{- | An upstream double serving each given body in turn, holding on the last once exhausted.
A test changes what upstream returns between two requests inside the cache TTL.
-}
mutatingUpstream :: NonEmpty LByteString -> IO Upstream
mutatingUpstream bodies = do
    remaining <- newIORef (toList bodies)
    recordingUpstreamIO (const (responseLBS status200 [] <$> atomicModifyIORef' remaining serveNext))
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

{- | Assemble an 'Upstream' over a double that already records @Authorization@ into the given ref.
It layers the artifact-slot method and @If-None-Match@ recording on uniformly.
-}
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

{- | Whether a request path is a tarball slot (@\/…\/-\/….tgz@) rather than a packument, so one
double can answer both.
-}
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

{- | A version object whose @dist.tarball@ addresses the given base URL's tarball slot, with a
distinct integrity and no install script. The serve path fetches that exact URL.
-}
selfHostedVersion :: Text -> Text -> Value
selfHostedVersion baseUrl version =
    versionValue
        ( (versionFixture version (baseUrl <> "/thing/-/thing-" <> version <> ".tgz"))
            { vsIntegrity = Just (sriFor version)
            , vsShasum = Just validShasum
            }
        )

{- | An admitting public packument (single old-enough version @v@) whose
@dist.tarball@ points at @baseUrl@: the self-hosting form the artifact path fetches.
-}
selfHostedAdmitting :: Text -> Text -> Value
selfHostedAdmitting baseUrl v =
    packument [(v, selfHostedVersion baseUrl v)] v [(v, publishedDaysAgo 30)]

{- | A path-aware upstream double answering a tarball slot with the given artifact bytes, and any
other path with a packument whose @dist.tarball@ for @version@ points back at this double.
-}
artifactUpstream :: Text -> LByteString -> IO Upstream
artifactUpstream version tarballBody =
    recordingUpstream (tarballOr (okBytes [] tarballBody) (selfHostedPackument version))

{- | Like 'artifactUpstream' but answering the artifact slot with the given arbitrary response, for
the public-relay verdict cases.
-}
artifactUpstreamAnswering :: Text -> Response -> IO Upstream
artifactUpstreamAnswering version artifactResponse =
    recordingUpstream (tarballOr (const artifactResponse) (selfHostedPackument version))

{- | Like 'artifactUpstream' but serving the given packument body verbatim, for tests that shape the
gating packument themselves.
-}
artifactUpstreamServing :: (Text -> LByteString) -> LByteString -> IO Upstream
artifactUpstreamServing packumentFor tarballBody =
    recordingUpstream (tarballOr (okBytes [] tarballBody) (bodyAt packumentFor))

{- | A private upstream double that has the artifact: a tarball slot answers @200@ with the given
bytes. The private tarball leg reads that conventional URL directly, with no packument fetch.
-}
privateArtifactHit :: Text -> LByteString -> IO Upstream
privateArtifactHit version = privateArtifactHitWith version []

{- | A private hit that also tags the artifact with one upstream header, so a test can assert the
relay forwards the artifact's own content headers through.
-}
privateArtifactHitWithHeader :: ByteString -> ByteString -> Text -> LByteString -> IO Upstream
privateArtifactHitWithHeader headerName headerText version =
    privateArtifactHitWith version [(CI.mk headerName, headerText)]

{- | The shared private-hit double: a tarball slot answers @200@ with the given bytes and extra
headers, any other path a self-referential single-version packument.
-}
privateArtifactHitWith :: Text -> [Header] -> LByteString -> IO Upstream
privateArtifactHitWith version extraHeaders tarballBody =
    recordingUpstream (tarballOr (okBytes extraHeaders tarballBody) (selfHostedPackument version))

{- | A private hit whose packument carries neither @integrity@ nor @shasum@. The private tarball leg
applies no serve-time integrity floor, so a hashless private artifact streams through.
-}
privateArtifactHitHashless :: Text -> LByteString -> IO Upstream
privateArtifactHitHashless = privateArtifactHitBelowFloor selfHostedHashless

{- | A private hit whose packument carries a legacy @shasum@ but no SRI @integrity@, below the
default SHA-256 floor. The private leg applies no serve-time floor, so this artifact still serves.
-}
privateArtifactHitShasumOnly :: Text -> LByteString -> IO Upstream
privateArtifactHitShasumOnly = privateArtifactHitBelowFloor selfHostedShasumOnly

-- The shared private hit whose single version comes from a fixture the public integrity floor
-- would refuse. Its publish time is a day old, so only the private exemption can admit it.
privateArtifactHitBelowFloor :: (Text -> Text -> Value) -> Text -> LByteString -> IO Upstream
privateArtifactHitBelowFloor versionFor version tarballBody =
    recordingUpstream (tarballOr (okBytes [] tarballBody) (packumentAt young))
  where
    young base = packument [(version, versionFor base version)] version [(version, publishedDaysAgo 1)]

{- | A private upstream double that does not hold the artifact: a tarball slot is a @404@, so the
request falls through to the public origin.
-}
privateArtifactMiss :: IO Upstream
privateArtifactMiss =
    recordingUpstream (tarballOr (const (responseLBS status404 [] "not found")) (selfHostedPackument "1.0.0"))

{- | A private upstream double whose tarball slot answers @200@, declares far more body than it
sends, then closes. Once the @200@ is on the wire the serve path must fail, never fall through.
-}
privateArtifactMidStreamFailure :: IO Upstream
privateArtifactMidStreamFailure =
    recordingUpstream (tarballOr (const truncated) (selfHostedPackument "1.0.0"))
  where
    truncated = responseRaw truncatedArtifact (responseLBS status500 [] "raw unsupported")

    -- Warp closes the raw socket once this returns, so the proxy reads EOF short of the declared
    -- Content-Length and fails immediately: no exception thrown here, no timeout waited on.
    truncatedArtifact :: IO ByteString -> (ByteString -> IO ()) -> IO ()
    truncatedArtifact _recv send = do
        send "HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\n\r\n"
        send (BS.replicate 1024 0x7a)

{- | A path-aware public double whose packument names its @dist.tarball@ on a host other than the
one that served it. Pass a @*.localhost@ alias: RFC 6761 reserves it for loopback, so it resolves.
-}
crossHostPublicUpstream :: Text -> Text -> LByteString -> IO Upstream
crossHostPublicUpstream crossHost version tarballBody =
    recordingUpstream (tarballOr (okBytes [] tarballBody) crossHostPackument)
  where
    -- The dist.tarball names @crossHost@ at this same port, so the policy sees a cross-host URL.
    crossHostPackument req =
        let port = snd (T.breakOnEnd ":" (decodeUtf8 (fromMaybe "" (lookup hHost (requestHeaders req)))))
            tarballBase = "http://" <> crossHost <> ":" <> port
         in responseLBS status200 [] (encodePackument (selfHostedAdmitting tarballBase version))

{- | A double whose @dist.tarball@ sits at an off-convention @\/files\/{filename}@ path, serving the
bytes at any @.tgz@ path, so the serve path must honour that URL rather than rebuild it.
-}
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

{- | A private double whose tarball lives only at @\/files\/{filename}@ and @404@s every other path.
The private leg reads the conventional @\/-\/@ slot, so it misses and the request falls to public.
-}
offConventionPrivateUpstream :: Text -> LByteString -> IO Upstream
offConventionPrivateUpstream filename tarballBody = recordingUpstream answer
  where
    answer req
        | rawPathInfo req == encodeUtf8 ("/files/" <> filename) = responseLBS status200 [] tarballBody
        | otherwise = responseLBS status404 [] "not found"

{- | A path-aware double that honours a conditional artifact request: a bodiless @304@ with an
@ETag@ when the request carries @If-None-Match@, and @200@ with the bytes otherwise.
-}
conditionalArtifactUpstream :: Text -> LByteString -> IO Upstream
conditionalArtifactUpstream version tarballBody =
    recordingUpstream (tarballOr conditionalTarball (selfHostedPackument version))
  where
    -- A relayed client validator turns the upstream artifact fetch into a 304. An
    -- unconditional fetch still serves the bytes.
    conditionalTarball req
        | isJust (lookupIfNoneMatch (requestHeaders req)) = responseLBS status304 [(hETag, "\"v1\"")] ""
        | otherwise = responseLBS status200 [] tarballBody

{- | A minimal npm packument body for @thing@, carrying an unmodeled top-level key. A test asserts
the serve path relays that key unchanged.
-}
packument :: [(Text, Value)] -> Text -> [(Text, Text)] -> Value
packument versions latest times =
    packumentValue
        "thing"
        latest
        versions
        (("created" .= publishedDaysAgo 400) : [(Key.fromText version, String time) | (version, time) <- times])
        ["_id" .= ("thing" :: Text)] -- an unmodeled top-level key

{- | A packument like 'packument' but self-reporting a different top-level @name@. The pipeline
validates out a packument named anything but @thing@ and drops its contribution.
-}
packumentNamed :: Text -> [(Text, Value)] -> Text -> [(Text, Text)] -> Value
packumentNamed nm versions latest times =
    case packument versions latest times of
        Object o -> Object (KeyMap.insert "name" (String nm) o)
        v -> v

{- | A version object with a @dist@ tarball URL and @integrity@, plus an unmodeled per-version key.
The @scripts@ field flags an install script when asked.
-}
versionObject :: Text -> Text -> Bool -> Value
versionObject version integrity hasInstall =
    versionValue
        ( (versionFixture version ("https://upstream.example/thing/-/thing-" <> version <> ".tgz"))
            { vsIntegrity = Just integrity
            , vsShasum = Just validShasum
            , vsHasInstallScript = hasInstall
            }
        )

-- A @thing@ version fixture with the unmodelled field the relay assertions preserve.
versionFixture :: Text -> Text -> VersionSpec
versionFixture version tarballUrl =
    (versionSpec "thing" version tarballUrl)
        { vsExtraPairs = ["_unmodeled" .= ("kept" :: Text)]
        }

-- A plain (no-install-script) version object with a distinct integrity.
plainVersion :: Text -> Value
plainVersion version = versionObject version (sriFor version) False

{- | A well-formed sha512 (resp. sha256) SRI derived from a label. These tests cover admission and
the merge, never digest realism, so a deterministic 'mkHash'-constructible digest stands in.
-}
sriFor, sri256For :: Text -> Text
sriFor = sriSha512Of . encodeUtf8
sri256For = sriSha256Of . encodeUtf8

-- | A well-formed 40-hex SHA-1 shasum (sha1 of the empty string) for the dist fixtures.
validShasum :: Text
validShasum = "da39a3ee5e6b4b0d3255bfef95601890afd80709"

{- | A version object carrying only a legacy SHA-1 @shasum@ and no @integrity@. The integrity floor
refuses such a version from a public upstream, and exempts a private one.
-}
shasumOnlyVersion :: Text -> Value
shasumOnlyVersion version =
    versionValue
        ( (versionFixture version ("https://upstream.example/thing/-/thing-" <> version <> ".tgz"))
            { vsShasum = Just validShasum
            }
        )

{- | A version object carrying neither @integrity@ nor @shasum@. The integrity-presence policy
refuses such a version from a public upstream.
-}
hashlessVersion :: Text -> Value
hashlessVersion version =
    versionValue (versionFixture version ("https://upstream.example/thing/-/thing-" <> version <> ".tgz"))

{- | A version whose @dist@ carries empty-string @integrity@ and @shasum@. The projection normalises
an empty digest to absent, so admission refuses it as 'NoIntegrity', not 'BelowFloor'.
-}
emptyDigestVersion :: Text -> Value
emptyDigestVersion version =
    versionValue
        ( (versionFixture version ("https://upstream.example/thing/-/thing-" <> version <> ".tgz"))
            { vsIntegrity = Just ""
            , vsShasum = Just ""
            }
        )

{- | A hashless version whose @dist.tarball@ points at @baseUrl@, the self-hosting form the artifact
path fetches. The artifact gate must refuse it before anything fetches that URL.
-}
selfHostedHashless :: Text -> Text -> Value
selfHostedHashless baseUrl version =
    versionValue (versionFixture version (baseUrl <> "/thing/-/thing-" <> version <> ".tgz"))

{- | A self-hosting version object carrying __only a legacy SHA-1 shasum__, so its strongest digest
sits below the default floor. The @BelowIntegrityFloor@ refusal fires before any @dist.tarball@ fetch.
-}
selfHostedShasumOnly :: Text -> Text -> Value
selfHostedShasumOnly baseUrl version =
    versionValue
        ( (versionFixture version (baseUrl <> "/thing/-/thing-" <> version <> ".tgz"))
            { vsShasum = Just validShasum
            }
        )

{- | A self-hosting version object whose @dist@ carries __empty-string__ @integrity@ and @shasum@,
so it projects to no digest. The 'MissingIntegrity' refusal fires before any @dist.tarball@ fetch.
-}
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

{- | The packument-serve dependencies over two in-process upstream ports and the given inbound edge
token. The doubles bind loopback as @localhost@: the internal-range block matches an IP literal.
-}
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

{- | The one proxy assembler: it hosts both doubles on ephemeral ports, builds an 'Env' over the
given queue and log environment, and binds the npm mount from the tweaked deps.
-}
withProxyOver ::
    LogEnv ->
    MirrorQueue ->
    Upstream ->
    Upstream ->
    Maybe Text ->
    (PackumentDeps -> [Text]) ->
    (PackumentDeps -> PackumentDeps) ->
    -- The continuation sees the proxy application, its 'Env' (to drain the queue),
    -- and the public upstream's ephemeral port (to assert an enqueued artifact URL).
    (forall a. (Application -> Env -> Int -> IO a) -> IO a)
withProxyOver logEnv queue privateUp publicUp inbound hostsOf tweakDeps k =
    testWithApplication (pure (upApp privateUp)) $ \privatePort ->
        testWithApplication (pure (upApp publicUp)) $ \publicPort -> do
            manager <- newManager defaultManagerSettings
            env <- newTestEnvLogging logEnv queue (manager, manager) telemetryDisabled
            baseDeps <- deps privatePort publicPort inbound
            let tweaked = tweakDeps baseDeps
                cfg = mkServerConfig (maybeToList (mountBindingFor Npm (withEcosystemHosts (hostsOf tweaked) tweaked) Nothing))
            k (application cfg env) env publicPort

{- | 'withProxyOver' over the default test log environment, with the tarball-host gate also
declaring ecosystem artifact hosts computed from the tweaked deps.
-}
withProxyEnvQueueDepsHosts ::
    MirrorQueue ->
    Upstream ->
    Upstream ->
    Maybe Text ->
    (PackumentDeps -> [Text]) ->
    (PackumentDeps -> PackumentDeps) ->
    (forall a. (Application -> Env -> Int -> IO a) -> IO a)
withProxyEnvQueueDepsHosts queue privateUp publicUp inbound hostsOf tweakDeps k = do
    logEnv <- newTestLogEnv
    withProxyOver logEnv queue privateUp publicUp inbound hostsOf tweakDeps k

{- | Like 'withProxyEnvQueue', but the mount's 'PackumentDeps' passes through the given transform
first, so a test can break one origin's base URL without a new harness.
-}
withProxyEnvQueueDeps ::
    MirrorQueue ->
    Upstream ->
    Upstream ->
    Maybe Text ->
    (PackumentDeps -> PackumentDeps) ->
    (forall a. (Application -> Env -> Int -> IO a) -> IO a)
withProxyEnvQueueDeps queue privateUp publicUp inbound =
    withProxyEnvQueueDepsHosts queue privateUp publicUp inbound (const [])

{- | Run an assertion against a proxy over the two in-process upstream doubles and the given mirror
queue. Warp hosts the doubles on ephemeral ports. The test drives the proxy through a WAI session.
-}
withProxyEnvQueue ::
    MirrorQueue ->
    Upstream ->
    Upstream ->
    Maybe Text ->
    (forall a. (Application -> Env -> Int -> IO a) -> IO a)
withProxyEnvQueue queue privateUp publicUp inbound =
    withProxyEnvQueueDeps queue privateUp publicUp inbound id

{- | Run an assertion against a proxy over the two upstream doubles and the proxy's own 'Env'. That
'Env' carries an in-memory queue, so a test can drain the enqueued mirror jobs.
-}
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

{- | Run an assertion against a proxy whose npm mount carries the given effectful rules, so a
request flows through the unified engine. The effectful rules see the public version.
-}
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

{- | A @GET@ at the given path carrying the given request headers, for a path whose answer turns
on what the client says it accepts.
-}
getPathWith :: [Header] -> ByteString -> Application -> IO SResponse
getPathWith extra path = requestAt methodGet path (headersRequest extra)

-- | A @GET \/npm\/thing@ request carrying the given (optional) bearer credential.
getThing :: Maybe Text -> Application -> IO SResponse
getThing bearer = requestAt methodGet "/npm/thing" (bearerRequest bearer)

{- | A @GET \/npm\/thing@ with no credential and the given extra request headers
(e.g. a conditional @If-None-Match@).
-}
getThingWith :: [Header] -> Application -> IO SResponse
getThingWith extra = requestAt methodGet "/npm/thing" (headersRequest extra)

{- | A @HEAD \/npm\/thing@ carrying the given optional bearer credential. The serve path must answer
with the GET's status and headers but no body.
-}
headThing :: Maybe Text -> Application -> IO SResponse
headThing bearer = requestAt methodHead "/npm/thing" (bearerRequest bearer)

{- | A @HEAD \/npm\/thing@ with no credential and the given extra request headers (e.g. a
conditional @If-None-Match@), to drive the own-ETag conditional on the HEAD path.
-}
headThingWith :: [Header] -> Application -> IO SResponse
headThingWith extra = requestAt methodHead "/npm/thing" (headersRequest extra)

{- | A @GET \/npm\/thing\/-\/thing-{version}.tgz@ artifact request carrying the given
(optional) bearer credential: the tarball path for @thing@ at one version.
-}
getTarball :: Text -> Maybe Text -> Application -> IO SResponse
getTarball version bearer = requestAt methodGet (tarballPathFor version) (bearerRequest bearer)

{- | A @GET \/npm\/thing\/-\/thing-{version}.tgz@ with no credential and the given extra request
headers (e.g. a conditional @If-None-Match@), to drive the pass-through conditional-GET relay.
-}
getTarballWith :: Text -> [Header] -> Application -> IO SResponse
getTarballWith version extra = requestAt methodGet (tarballPathFor version) (headersRequest extra)

{- | A @HEAD \/npm\/thing\/-\/thing-{version}.tgz@ carrying the given optional bearer credential. The
serve path must answer without pumping the full artifact body.
-}
headTarball :: Text -> Maybe Text -> Application -> IO SResponse
headTarball version bearer = requestAt methodHead (tarballPathFor version) (bearerRequest bearer)

{- | Drain every mirror job currently enqueued on the proxy's queue, in FIFO order. The backend
delivers batches up to its cap per receive, so this polls until an empty batch.
-}
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
