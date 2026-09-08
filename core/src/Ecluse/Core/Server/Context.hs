-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT
{-# LANGUAGE ExistentialQuantification #-}

{- | Per-request mount wiring, runtime capabilities, and the serve handler monad.
Dispatch pairs one 'MountBinding' with 'ServeRuntime' and establishes the ambient
@katip@ context. The composition root supplies the runtime capabilities.
-}
module Ecluse.Core.Server.Context (
    -- * Request runtime
    ServeRuntime (..),

    -- * Packument-serve dependencies
    PackumentDeps (..),
    pdPrivateBaseUrl,
    pdPublicBaseUrl,
    pdMirror,
    pdTarballHostGate,
    tarballHostHonoured,

    -- * Publish-serve dependencies
    PublishDeps (..),

    -- * The serve action, and the router an adapter supplies
    RouteAction (..),
    ResponseAction (..),
    MountRouter,

    -- * Mount binding
    MountBinding (..),

    -- * Per-request context
    RequestCtx (..),

    -- * The handler monad
    Handler,
    runHandler,
) where

import Data.IP (IPRange)
import Data.Time (UTCTime)
import Katip (Katip, KatipContext, LogEnv, SimpleLogPayload)
import Katip.Monadic (KatipContextT, runKatipContextT)
import Network.HTTP.Client (Manager)
import Network.HTTP.Types (Method)
import Network.HTTP.Types.Header (RequestHeaders)
import Network.Wai (ResponseReceived)
import Network.Wai qualified as Wai
import UnliftIO (MonadUnliftIO)

import Ecluse.Core.Credential (Secret)
import Ecluse.Core.Cve (DbEtag)
import Ecluse.Core.Package (PackageName)
import Ecluse.Core.Package.Integrity (MinIntegrity, MinTrustedIntegrity)
import Ecluse.Core.Package.Merge (DivergencePolicy)
import Ecluse.Core.Queue (MirrorQueue)
import Ecluse.Core.Registry.Adapter.Capability (AdapterArtifact, AdapterMetadata, AdapterPublish, ProjectName)
import Ecluse.Core.Registry.Request (CredentialMapping)
import Ecluse.Core.Rules (PreparedRule)
import Ecluse.Core.Security (HostPort, Limits, Origin, TarballHostGate, tarballHostAllowed, thgAllowlist, thgEcosystemHosts)
import Ecluse.Core.Security.Egress (RegistryUrl)
import Ecluse.Core.Server.Admission (ServeAdmission)
import Ecluse.Core.Server.Admission.Bytes (ByteAdmission)
import Ecluse.Core.Server.Cache (MetadataCache)
import Ecluse.Core.Server.Contract (ResponseContract)
import Ecluse.Core.Server.Response (HelpMessage)
import Ecluse.Core.Server.Upstream (
    MirrorServePlan,
    MountUpstreams,
    upstreamMirror,
    upstreamPrivateBaseUrl,
    upstreamPublicBaseUrl,
    upstreamTarballHostGate,
 )
import Ecluse.Core.Telemetry.Record (MetricsPort)
import Ecluse.Core.Telemetry.Span (TracingPort)

-- | Serve capabilities assembled at boot. Both HTTP managers must validate TLS certificates.
data ServeRuntime = ServeRuntime
    { srAdmission :: ServeAdmission
    -- ^ Bounds metadata materialisation, excluding private tarball hits and artifact streaming.
    , srPublicManager :: Manager
    {- ^ The validating-TLS data-plane manager for the __untrusted__ public-upstream
    metadata fetch and every artifact stream.
    -}
    , srPrivateManager :: Manager
    {- ^ The manager for the __trusted__ private upstream. It is the same validating TLS
    manager: the private origin differs in credential handling, not in the manager.
    -}
    , srMetadataCache :: MetadataCache
    {- ^ The short-TTL, size-bounded metadata cache shared by the serve paths
    (see "Ecluse.Core.Server.Cache").
    -}
    , srQueue :: MirrorQueue
    {- ^ The mirror-queue handle: the durable, best-effort hand-off from the serve
    path to the mirror worker.
    -}
    , srMetrics :: MetricsPort
    -- ^ The metric-recording port the serve path emits the @ecluse.*@ catalogue through.
    , srTracing :: TracingPort
    -- ^ The tracing port the serve path opens its hand-added domain spans through.
    }

-- | Mount inputs shared by packument and tarball handlers, resolved at boot.
data PackumentDeps = PackumentDeps
    { pdUpstreams :: MountUpstreams
    -- ^ Upstreams bound to their derived host gate, so their authorities cannot diverge.
    , pdFirstParty :: PackageName -> Bool
    {- ^ Whether a name belongs to a namespace this deployment owns, derived once at the composition root and deny
    by default. Its one authority is the private upstream: the public leg is never entered, and a private miss is @404@.
    -}
    , pdMountBaseUrl :: Text
    {- ^ The mount's externally-visible base URL, under which served @dist.tarball@
    URLs are rewritten so artifacts are fetched back through the gate.
    -}
    , pdRules :: [PreparedRule]
    -- ^ Rules prepared at boot and evaluated against every public version.
    , pdAdditionalBlockedRanges :: [IPRange]
    -- ^ Extra blocked IP ranges for untrusted artifact locations. Empty by default.
    , pdLimits :: Limits
    -- ^ Fetch and decode limits. A breach discards the whole upstream contribution.
    , pdInboundToken :: Maybe Secret
    {- ^ The optional inbound token a client must present (@ECLUSE_SERVER__AUTH_TOKEN@).
    'Nothing' leaves the edge open, and the network layer guards it.
    -}
    , pdNow :: IO UTCTime
    {- ^ The wall-clock "now" for the rules' 'Ecluse.Core.Rules.Types.EvalContext'.
    Injected so the time-sensitive age gate is deterministic under test.
    -}
    , pdAdvisoryEtag :: IO (Maybe DbEtag)
    -- ^ Non-pinning read of the active advisory etag. 'Nothing' means no database is loaded.
    , pdHelp :: Maybe HelpMessage
    -- ^ The operator help message appended to every denial body, if configured.
    , pdMinIntegrity :: MinIntegrity
    -- ^ Public integrity floor, at least SHA-256. Private reads use 'pdMinTrustedIntegrity'.
    , pdMinTrustedIntegrity :: MinTrustedIntegrity
    -- ^ The minimum integrity hash required for a trusted upstream dependency.
    , pdDivergencePolicy :: DivergencePolicy
    -- ^ Whether divergence also withholds a version from listings. Warning and metric always fire.
    , pdMetadata :: AdapterMetadata
    {- ^ The mount ecosystem's metadata capability, carried whole
    ('Ecluse.Core.Registry.Adapter.Capability.AdapterMetadata'), never copied field by field.
    -}
    , pdArtifact :: AdapterArtifact
    {- ^ The mount ecosystem's artifact request formation, carried whole
    ('Ecluse.Core.Registry.Adapter.Capability.AdapterArtifact'), never copied field by field.
    -}
    , pdEgressUrl :: Text -> Either Text RegistryUrl
    -- ^ Validate an artifact URL before enqueueing it. A 'Left' prevents the mirror job.
    }

-- | The private URL bound to the host gate. 'Nothing' skips the private fetch.
pdPrivateBaseUrl :: PackumentDeps -> Maybe RegistryUrl
pdPrivateBaseUrl = upstreamPrivateBaseUrl . pdUpstreams

-- | The public upstream base URL. Reads are anonymous, with no client credential.
pdPublicBaseUrl :: PackumentDeps -> RegistryUrl
pdPublicBaseUrl = upstreamPublicBaseUrl . pdUpstreams

-- | The mirror destination for admitted public artifacts, or no write for a serve-only mount.
pdMirror :: PackumentDeps -> MirrorServePlan
pdMirror = upstreamMirror . pdUpstreams

-- | The host gate derived from the mount's upstreams at boot.
pdTarballHostGate :: PackumentDeps -> TarballHostGate
pdTarballHostGate = upstreamTarballHostGate . pdUpstreams

{- | Apply 'tarballHostAllowed' with this mount's inputs for both serving and mirror re-evaluation.
A missing authority refuses. Trusted origins bypass only the internal-range block.
-}
tarballHostHonoured :: Origin -> PackumentDeps -> Maybe HostPort -> Maybe HostPort -> Bool
tarballHostHonoured origin deps =
    tarballHostAllowed
        (thgEcosystemHosts (pdTarballHostGate deps))
        origin
        (thgAllowlist (pdTarballHostGate deps))
        (pdAdditionalBlockedRanges deps)

-- | First-party publish inputs. Their presence enables the mount's publish route.
data PublishDeps = PublishDeps
    { pubTargetUrl :: RegistryUrl
    {- ^ The publication target endpoint (@mounts.npm.publicationTarget@) a client
    @npm publish@ is relayed to, as the https-only witness. The package path is appended to it.
    -}
    , pubAllowed :: PackageName -> Bool
    {- ^ Whether this package may publish here, refused before any upstream write: the same
    first-party predicate the serve path reads as 'pdFirstParty'.
    -}
    , pubStaticToken :: Maybe Secret
    -- ^ Replaces the authenticated edge token on publishes. Requires 'pubInboundToken' at boot.
    , pubInboundToken :: Maybe Secret
    {- ^ The optional inbound edge token a client must present (@ECLUSE_SERVER__AUTH_TOKEN@),
    the same gate the read paths apply. 'Nothing' leaves the edge open.
    -}
    , pubLimits :: Limits
    -- ^ The response-bound budget enforced on the publication target's response.
    , pubBodyBudget :: ByteAdmission
    -- ^ Shared body-byte budget reserved before reading. Exhaustion sheds a @503@.
    , pubMaxRequestBytes :: Int
    -- ^ Per-request body cap in bytes, also the aggregate reservation for a chunked body.
    , pubHelp :: Maybe HelpMessage
    -- ^ The operator help message appended to a publish denial, if configured.
    , pubProjectName :: ProjectName
    -- ^ The ecosystem's own name parser, which the anti-shadowing guard reads a declared name through.
    , pubAdapter :: AdapterPublish
    {- ^ The mount ecosystem's publish capability, carried whole
    ('Ecluse.Core.Registry.Adapter.Capability.AdapterPublish'), never copied field by field.
    -}
    }

-- | A matched request's action, constrained to its route's response contract.
data ResponseAction response
    = -- | A pure value admitted by the route's response contract.
      AnswerLocally response
    | {- | A refusal the route decided, rendered where the mount's help message is known, so a
      route table carries no configuration of its own.
      -}
      AnswerRefusal (Maybe HelpMessage -> response)
    | -- | A data-plane handler and its pre-commit fallback, both constrained to the route's response type.
      RunPipeline response (Wai.Request -> (response -> IO ResponseReceived) -> Handler ResponseReceived)

{- | A matched route's response contract paired with an action that produces only that contract's
response type. Dispatch renders the action without knowing an ecosystem's response sum.
-}
data RouteAction = forall response. RouteAction (ResponseContract response) (ResponseAction response)

{- | An ecosystem's whole routing decision over a mount-relative request, from its adapter. The
method and the headers are part of the mapping, and segments arrive stripped and decoded.
-}
type MountRouter = Method -> RequestHeaders -> [Text] -> RouteAction

-- | Ecosystem wiring under a non-empty prefix, so adding an ecosystem never displaces a root mount.
data MountBinding = MountBinding
    { bindingPrefix :: NonEmpty Text
    -- ^ The leading path segments this mount is served under. Never empty.
    , bindingRouter :: MountRouter
    -- ^ This mount's routing decision, derived from the adapter's own route table.
    , bindingCredential :: CredentialMapping
    {- ^ How a client of this mount presents its credential, and how the proxy carries one
    upstream. The adapter declares it, so the serve path holds no credential scheme of its own.
    -}
    , bindingPackumentDeps :: PackumentDeps
    {- ^ The packument-serve dependencies. A bound mount always serves packuments and artifacts,
    because a mount exists only for a registered adapter. Only /publish/ is opt-in.
    -}
    , bindingPublishDeps :: Maybe PublishDeps
    -- ^ Optional first-party publish dependencies. 'Nothing' makes @PUT \/{pkg}@ answer @405@.
    }

{- | The context one request is served through: the request runtime paired with the 'MountBinding'
the request matched. Dispatch builds it once per request, and 'Handler' reads it through its reader.
-}
data RequestCtx = RequestCtx
    { ctxRuntime :: ServeRuntime
    {- ^ The request runtime: the data-plane managers, the caches and queue, and the
    recording ports.
    -}
    , ctxMount :: MountBinding
    -- ^ The mount the request matched, carrying its complete ecosystem wiring.
    }

-- | Request context over @katip@'s reader-based logging context, shared across concurrent fetches.
newtype Handler a = Handler
    { unHandler :: ReaderT RequestCtx (KatipContextT IO) a
    }
    deriving newtype
        ( Functor
        , Applicative
        , Monad
        , MonadIO
        , MonadReader RequestCtx
        , MonadUnliftIO
        , Katip
        , KatipContext
        )

-- | Run a handler with the application's log stream and initial trace-correlation payload.
runHandler :: LogEnv -> SimpleLogPayload -> RequestCtx -> Handler a -> IO a
runHandler logEnv initialContext ctx action =
    runKatipContextT logEnv initialContext mempty (runReaderT (unHandler action) ctx)
