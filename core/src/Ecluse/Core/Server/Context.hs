-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT
{-# LANGUAGE ExistentialQuantification #-}

{- | The per-request context the serve path reads through, and the handler monad
over it.

Mount dispatch matches a request to one 'MountBinding', a mount's __complete__
ecosystem wiring. It then runs the route's handler in 'Handler', a reader over a
'RequestCtx' pairing that binding with the request runtime 'ServeRuntime'. A handler
reads its per-mount dependencies and the shared runtime from that one context, rather
than taking them as explicit arguments threaded down the pipeline. Those dependencies
are the classifier, the packument-serve dependencies, and the path prefix.

'ServeRuntime' is the __runtime interface__ the serve path is closed over. The fields
are the two data-plane HTTP managers, the metadata cache, the mirror queue, and the
abstract metric- and tracing-recording ports. It holds precisely what the pipeline needs to
serve a request and nothing more. The application's composition root constructs it,
wiring the concrete OpenTelemetry-backed ports, and a test constructs it over
doubles. Logging is __not__ a field: a handler logs through the ambient @katip@
context. The dispatch boundary establishes that context when it runs the handler, with
the structured-log scribes and the trace-correlation @dd@ object.

'RequestCtx' is a concrete record with plain accessors ('ctxRuntime', 'ctxMount'). The
handler monad layers over @katip@'s logging context, so a structured log call composes
uniformly across the serve path.
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

{- | The effectful backends the serve path is closed over, assembled by the composition root
and read by every handler through the 'RequestCtx'. The metric and tracing ports keep it
free of any named telemetry backend.

Both HTTP managers validate TLS, because registry egress is https-only by construction and
certificate validation authenticates the host.
-}
data ServeRuntime = ServeRuntime
    { srAdmission :: ServeAdmission
    {- ^ The process-wide brief-wait bound around metadata materialisation
    ("Ecluse.Core.Server.Admission"). Packument work and a tarball miss's public metadata gate
    acquire a slot. A private tarball hit and the artifact streaming pump stay outside it.
    -}
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

{- | The per-mount inputs the serve handlers need beyond the request runtime 'ServeRuntime',
resolved at the composition root and carried on the mount's 'MountBinding'.

Both the packument and the tarball paths read these deps, so the name is broader than the
one route it mentions.
-}
data PackumentDeps = PackumentDeps
    { pdUpstreams :: MountUpstreams
    {- ^ The mount's configured upstreams (private, public, and the mirror serve plan) with the
    tarball-host gate derived from them ("Ecluse.Core.Server.Upstream"). One opaque cluster, so
    a caller cannot build a gate that disagrees with the URLs it gates for. Read it through
    'pdPrivateBaseUrl', 'pdPublicBaseUrl', 'pdMirror', and 'pdTarballHostGate'.
    -}
    , pdFirstParty :: PackageName -> Bool
    {- ^ Whether a name belongs to a namespace this deployment owns, derived once at the composition root and deny
    by default. Its one authority is the private upstream: the public leg is never entered, and a private miss is @404@.
    -}
    , pdMountBaseUrl :: Text
    {- ^ The mount's externally-visible base URL, under which served @dist.tarball@
    URLs are rewritten so artifacts are fetched back through the gate.
    -}
    , pdRules :: [PreparedRule]
    {- ^ The mount's resolved rule set as the engine's prepared runtime rules
    ("Ecluse.Core.Rules.PreparedRule"), evaluated against every public version. The composition
    root 'prepare's them once at boot.
    -}
    , pdAdditionalBlockedRanges :: [IPRange]
    {- ^ The operator-configured ranges (@ECLUSE_EGRESS__ADDITIONAL_BLOCKED_RANGES@) that
    extend the fixed literal internal-range block when gating an honoured artifact
    location ('Ecluse.Core.Security.tarballHostAllowed'). They are the cheap pure
    defence in depth that complements the host allowlist. Empty by default.
    -}
    , pdLimits :: Limits
    {- ^ The response-bound budget enforced on every upstream metadata fetch and decode: the
    body-size, version-count, artifact-count, and JSON-nesting ceilings of
    'Ecluse.Core.Security.Limits' (@ECLUSE_LIMITS__MAX_RESPONSE_BYTES@,
    @ECLUSE_LIMITS__MAX_VERSION_COUNT@, @ECLUSE_LIMITS__MAX_ARTIFACT_COUNT@,
    @ECLUSE_LIMITS__MAX_NESTING_DEPTH@). A breach degrades the contribution to nothing, so a
    pathological upstream document is refused, never partially served (security.md invariant 4).
    -}
    , pdInboundToken :: Maybe Secret
    {- ^ The optional inbound token a client must present (@ECLUSE_SERVER__AUTH_TOKEN@).
    'Nothing' leaves the edge open, and the network layer guards it.
    -}
    , pdNow :: IO UTCTime
    {- ^ The wall-clock "now" for the rules' 'Ecluse.Core.Rules.Types.EvalContext'.
    Injected so the time-sensitive age gate is deterministic under test.
    -}
    , pdAdvisoryEtag :: IO (Maybe DbEtag)
    {- ^ A non-pinning read of the active advisory database's 'DbEtag' for the per-request
    'Ecluse.Core.Rules.Types.EvalContext'. It is the same value
    'Ecluse.Core.Rules.rdCurrentAdvisoryEtag' provides. 'Nothing' when no database is loaded.
    -}
    , pdHelp :: Maybe HelpMessage
    -- ^ The operator help message appended to every denial body, if configured.
    , pdMinIntegrity :: MinIntegrity
    {- ^ The floor a __public__ (untrusted) version's strongest digest must meet to be admitted
    (@ECLUSE_INTEGRITY__MIN_PUBLIC@, default SHA-256). It is hard-floored at SHA-256 and never
    lowerable (see "Ecluse.Core.Package.Integrity"). The trusted private path consults
    'pdMinTrustedIntegrity' instead.
    -}
    , pdMinTrustedIntegrity :: MinTrustedIntegrity
    -- ^ The minimum integrity hash required for a trusted upstream dependency.
    , pdDivergencePolicy :: DivergencePolicy
    {- ^ What to do with a served version a cross-upstream integrity divergence was
    detected on (@ECLUSE_INTEGRITY__DIVERGENCE_POLICY@, default 'Ecluse.Core.Package.Merge.Warn').
    The signal (the @WARNING@ log and the @ecluse.registry.merge.divergence@ counter)
    fires regardless. This only decides whether the contested version is additionally
    withheld from the served listing ('Ecluse.Core.Package.Merge.FailClosed').
    -}
    , pdMetadata :: AdapterMetadata
    {- ^ The mount ecosystem's metadata capability, carried whole
    ('Ecluse.Core.Registry.Adapter.Capability.AdapterMetadata'), never copied field by field.
    -}
    , pdArtifact :: AdapterArtifact
    {- ^ The mount ecosystem's artifact request formation, carried whole
    ('Ecluse.Core.Registry.Adapter.Capability.AdapterArtifact'), never copied field by field.
    -}
    , pdEgressUrl :: Text -> Either Text RegistryUrl
    {- ^ Form the validated egress witness for an artifact URL about to leave the process on a
    'Ecluse.Core.Queue.MirrorJob'. The composition root wires the https-only
    'Ecluse.Core.Security.Egress.mkRegistryUrl', and the loopback test harness substitutes its
    flag-gated dev former. A 'Left' fails the best-effort enqueue closed rather than letting an
    unwitnessed URL travel to the worker.
    -}
    }

{- | The private upstream base URL. Under @passthrough@, reads forward the client's
credential. 'Nothing' when the mount has no private upstream, so the private leg is never
fetched and a tarball request is a clean private miss straight to the public leg.

A plain function over 'pdUpstreams', not a record field, so a caller cannot replace a URL
while the tarball-host gate beside it keeps the old authorities. The same holds for
'pdPublicBaseUrl' and 'pdMirror'.
-}
pdPrivateBaseUrl :: PackumentDeps -> Maybe RegistryUrl
pdPrivateBaseUrl = upstreamPrivateBaseUrl . pdUpstreams

-- | The public upstream base URL. Reads are anonymous, with no client credential.
pdPublicBaseUrl :: PackumentDeps -> RegistryUrl
pdPublicBaseUrl = upstreamPublicBaseUrl . pdUpstreams

{- | Whether an admitted public artifact is enqueued for the demand-driven mirror, and
the declared destination when it is ('Ecluse.Core.Server.Upstream.MirrorOnAdmit'). A
serve-only mount carries 'Ecluse.Core.Server.Upstream.NoMirrorWrite' and never enqueues.
-}
pdMirror :: PackumentDeps -> MirrorServePlan
pdMirror = upstreamMirror . pdUpstreams

{- | The mount-constant inputs to the per-request tarball-host gate
('Ecluse.Core.Security.TarballHostGate'): the canonicalised @host:port@ allowlist and the
private and public upstream authorities, derived once when the cluster was bound. The hot
artifact path parses only the dynamic @dist.tarball@ authority per request.
-}
pdTarballHostGate :: PackumentDeps -> TarballHostGate
pdTarballHostGate = upstreamTarballHostGate . pdUpstreams

{- | Whether an artifact's @dist.tarball@ authority may be fetched, given the origin's trust
and the authority that served the packument it came from. The tarball's @host:port@ pair
must be on the upstream allowlist and equal to the packument origin's pair, with the
ecosystem's own declared artifact hosts as the one same-host equivalence.

The literal internal-range block is origin-aware. An 'Ecluse.Core.Security.UntrustedOrigin'
is gated against the fixed range set plus the operator-configured @additionalBlockedRanges@.
An 'Ecluse.Core.Security.TrustedOrigin' is exempt from that block alone, because a private
registry may legitimately live on an internal address (security.md invariant 3): the
allowlist and same-authority clauses still gate it identically.

This is the one composition of the host gate over a mount's inputs. The composition root
closes it into the mirror worker's re-evaluation bundle, so the ingest-time host check can
never drift from the serve-time one.

'Nothing' for either authority means no dialable host, and the gate refuses.
-}
tarballHostHonoured :: Origin -> PackumentDeps -> Maybe HostPort -> Maybe HostPort -> Bool
tarballHostHonoured origin deps =
    tarballHostAllowed
        (thgEcosystemHosts (pdTarballHostGate deps))
        origin
        (thgAllowlist (pdTarballHostGate deps))
        (pdAdditionalBlockedRanges deps)

{- | The per-mount inputs the first-party publish handler needs, from the publication target
endpoint to the first-party namespaces.

The presence of these deps is the publish path's opt-in. A mount carries a 'PublishDeps' only
when a publication target is configured, so @bindingPublishDeps@ being 'Nothing' is exactly
the "no publication target means @PUT \/{pkg}@ is @405 Method Not Allowed@" rule.

The credential posture is passthrough: the publisher's own forwarded token reaches the
publication target, and 'pubStaticToken' is only a fallback for a client that sends none.
Écluse mints no token of its own here, so this record carries no
'Ecluse.Core.Credential.CredentialProvider' (see @docs\/architecture\/registry-model.md@).
-}
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
    {- ^ The static fallback credential (the @token@ under that target's tag), forwarded __only
    when the client sends none of its own__. 'Nothing' on the common passthrough path.
    -}
    , pubInboundToken :: Maybe Secret
    {- ^ The optional inbound edge token a client must present (@ECLUSE_SERVER__AUTH_TOKEN@),
    the same gate the read paths apply. 'Nothing' leaves the edge open.
    -}
    , pubLimits :: Limits
    -- ^ The response-bound budget enforced on the publication target's response.
    , pubBodyBudget :: ByteAdmission
    {- ^ The process-wide byte admission a buffered publish body reserves against __before__ the
    body is read. Every mount shares it, sized from the memory plan's publish tenant.
    Exhaustion sheds a @503@.
    -}
    , pubMaxRequestBytes :: Int
    {- ^ The per-request publish-body cap, in bytes. A declared Content-Length over it fails
    closed before any byte is read, and a counted read bounds a chunked body against it. A
    chunked body also reserves this much against the aggregate body-byte budget.
    -}
    , pubHelp :: Maybe HelpMessage
    -- ^ The operator help message appended to a publish denial, if configured.
    , pubProjectName :: ProjectName
    -- ^ The ecosystem's own name parser, which the anti-shadowing guard reads a declared name through.
    , pubAdapter :: AdapterPublish
    {- ^ The mount ecosystem's publish capability, carried whole
    ('Ecluse.Core.Registry.Adapter.Capability.AdapterPublish'), never copied field by field.
    -}
    }

{- | How one matched request is served: by the proxy itself, or through the data plane.

The dispatcher discharges a 'RunPipeline' handler under the request perimeter, the guard that
answers an escaped fault with the route's declared neutral @500@. This type lives beside
'MountBinding' and 'Handler' because the three form one mutually-recursive knot.
-}
data ResponseAction response
    = -- | A pure value admitted by the route's response contract.
      AnswerLocally response
    | {- | A data-plane handler and its pre-commit perimeter fallback. The handler receives
      only the responder for this @response@ type, so it cannot send an unrestricted WAI
      'Response'. The fallback is a value of the same type, so the same contract
      documents it.
      -}
      RunPipeline response (Wai.Request -> (response -> IO ResponseReceived) -> Handler ResponseReceived)

{- | A matched route's response contract paired with an action that produces only that contract's
response type. Dispatch renders the action without knowing an ecosystem's response sum.
-}
data RouteAction = forall response. RouteAction (ResponseContract response) (ResponseAction response)

{- | An ecosystem's whole routing decision: what to do with a mount-relative request.

The adapter supplies one ('Ecluse.Core.Registry.Adapter.Types.serveRouter'). A path it does not
recognise yields the deny-by-default @404@. The 'Method' is part of the mapping, and a @HEAD@
resolves to the head-mode handler of its @GET@. Segments arrive mount-stripped and
percent-decoded.
-}
type MountRouter = Method -> [Text] -> RouteAction

{- | A path prefix bound to a registry, carrying that registry's complete ecosystem wiring.
Dispatch matches a request's leading segments to 'bindingPrefix' and routes the remainder
through the rest of the binding.

The prefix is 'NonEmpty' (@"npm" :| []@), so a root mount is unrepresentable. A root mount would
force a URL change on every consumer the day a second ecosystem is added.
-}
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
    {- ^ The first-party publish dependencies, when a publication target is
    configured. 'Nothing' is the opt-out: a @PUT \/{pkg}@ is then @405@, with no
    implicit write path.
    -}
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

{- | The request hot path's monad: a reader over the per-request 'RequestCtx' layered on
@katip@'s logging context.

The @katip@ base is a reader, never a 'StateT', so logging context behaves correctly across the
serve path's concurrent fetches (see @docs\/architecture\/technology-stack.md@).
-}
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

{- | Run a 'Handler' against the request's 'RequestCtx'. This discharges the serve path's
'Handler' code to 'IO'.

The caller supplies the 'LogEnv' and the initial context payload, so the application owns the
log stream and the @dd@ object every line carries for trace-to-log correlation.
-}
runHandler :: LogEnv -> SimpleLogPayload -> RequestCtx -> Handler a -> IO a
runHandler logEnv initialContext ctx action =
    runKatipContextT logEnv initialContext mempty (runReaderT (unHandler action) ctx)
