-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The serve paths behind the package routes: the packument merge behind
@GET \/{pkg}@.

This is the data-plane handler module for packuments. It composes the slices that decide
/what/ to serve into one action in the 'Ecluse.Core.Server.Context.Handler' reader:

* the origin resolution ("Ecluse.Core.Server.Pipeline.Origin")
* the per-version rules ("Ecluse.Core.Rules")
* the structural filter ("Ecluse.Core.Registry.Npm.Filter")
* the cross-upstream merge ("Ecluse.Core.Package.Merge")
* the metadata cache ("Ecluse.Core.Server.Cache")
* the own-ETag conditional ("Ecluse.Core.Server.Conditional")
* the serve-outcome status ("Ecluse.Core.Server.Response")

It reads its mount's serve dependencies and the request runtime
'Ecluse.Core.Server.Context.ServeRuntime' from the request's
'Ecluse.Core.Server.Context.RequestCtx'.

== Credential authority

This handler applies the @passthrough@ credential posture (see
@docs\/architecture\/registry-model.md@, "Credential flow and authority"). The invariant is
the __public strip__: the client's credential is __stripped before any public-upstream
fetch__, which is always anonymous. Sending an internal token to the public registry would
be a credential disclosure, so the public-upstream fetch carries no token at all.
The handler also __forwards the client's own credential verbatim to the private
upstream__, which is the authority for who may read what. It
fetches the two origins concurrently, each with its own credential posture, and nothing
shares a token across the trust split.

The private upstream is the __per-client authority__, so its metadata is
__not cached across clients__ here. Every request fetches and parses the private origin
with that client's own credential, so the upstream re-authorises each client itself. Only
the anonymous public origin is cached: one shared document, with no per-client authority
to preserve. A private-origin cache keyed by base URL alone would let one client's entry
serve another client's private document within the TTL, bypassing the upstream's
authorisation. That is a cross-client disclosure.

== Merge, not fallback

A packument is the /set of available versions/, spread across upstreams. The handler
therefore __merges__ them rather than short-circuiting on a private hit (see
@docs\/architecture\/registry-model.md@, "Packument merge across upstreams"). Private
versions are trusted and enter unfiltered. The rules and the structural filter gate public
versions first, where the 'FilterPlan''s survivors restrict the typed view. The merge then
combines the two: a private version wins a collision, and an integrity divergence is
flagged. If one upstream is unavailable while the other succeeds, the handler serves the
best-effort union of what resolved. Only when /nothing/ resolves does the request error.

A first-party name is the exception. Its namespace belongs to this deployment, so the public
origin is never fetched, nothing of its can be merged in, and a private miss answers @404@
('Ecluse.Core.Server.Context.pdFirstParty').

== Decision surface vs served surface

The merge and filter reason over the /typed/ 'PackageInfo'. The document served is the
__raw upstream document__, held opaquely here as a
'Ecluse.Core.Registry.CachedDocument.CachedDoc' and rebuilt from the winning sources.
Every unmodeled wire key therefore survives (see
@docs\/architecture\/registry-model.md@, "Decision surface vs served surface").

The 'MergePlan' names, for each surviving version, the source that won it. The mount's
injected assembly capability ('Ecluse.Core.Registry.Npm.Filter.assembleMergedDocument' for
npm) builds the served body in one pass, reading the raw documents in the adapter's own
representation. It takes each survivor's object from its winning source and rewrites the
tarball URL under the mount base as it places it. It carries the reconciled @dist-tags@
and @time@ from the plan, and relays every other top-level key from the
precedence-winning document. The typed model is never re-serialised.

The merge /owns/ two fields as a decision: @dist-tags.latest@ and the @time@ instants.
Both are re-rendered from that decision, the times as normalised ISO-8601, so they may
differ byte-for-byte from any single upstream while denoting the same value.
Integrity-bearing fields (@dist.integrity@, and @dist.tarball@ up to the rewrite's own
prefix) are relayed raw and untouched. The served bytes get our __own ETag__, since a
merged or filtered body matches no single upstream's.
-}
module Ecluse.Core.Server.Pipeline.Packument (
    PackumentReplies (..),
    servePackument,
    headPackument,

    -- * The derived validator (exported for its unit spec)
    packumentETag,
) where

import Crypto.Hash (Context, SHA256, hashFinalize, hashInit, hashUpdates)
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as LBS
import Data.Map.Strict qualified as Map
import Data.Set qualified as Set
import Data.Text qualified as T
import Katip (Severity (DebugS, InfoS), logFM, ls)
import Network.HTTP.Types (ResponseHeaders, hContentLength)
import Network.Wai (Request, ResponseReceived, requestHeaders)
import UnliftIO (concurrently)
import UnliftIO.Exception (catchAny, throwIO)

import Ecluse.Core.Credential (ClientCredential)
import Ecluse.Core.Package (
    PackageInfo (infoVersions),
    PackageName,
    renderPackageName,
 )
import Ecluse.Core.Package.Filter (filterPlanFromDecisions, fpDecisions, fpSurvivors, restrictToSurvivors)
import Ecluse.Core.Package.Integrity (
    MinTrustedIntegrity,
 )
import Ecluse.Core.Package.Merge (
    DivergencePolicy,
    MergePlan (mpSurvivors),
    Provenance (GatedSource, TrustedSource),
    SourceId,
    applyDivergencePolicy,
    mergePackuments,
 )
import Ecluse.Core.Registry.Adapter.Capability (AdapterMetadata (metadataAssemble, metadataSerialise))
import Ecluse.Core.Registry.CachedDocument (CachedDoc)
import Ecluse.Core.Registry.Metadata (
    ContentDigest,
    Manifest (manifestDigest, manifestInfo, manifestRaw),
    digestBytes,
 )
import Ecluse.Core.Rules (evalRules)
import Ecluse.Core.Rules.Types (Decision, EvalContext (ctxAdvisoryEtag), mkEvalContext)
import Ecluse.Core.Server.Cache (resolveAssembled)
import Ecluse.Core.Server.Conditional (Conditional (Modified, NotModified), ETag, etagHeader, evaluateETag, mkStrongETag, renderETag)
import Ecluse.Core.Server.Context (
    Handler,
    MountBinding (bindingPackumentDeps),
    PackumentDeps (..),
    ServeRuntime (..),
    ctxMount,
    ctxRuntime,
 )
import Ecluse.Core.Server.Fault (RenderEscape (RenderEscape))
import Ecluse.Core.Server.Pipeline.Diagnostics (warnDivergences)
import Ecluse.Core.Server.Pipeline.Internal (
    VersionVerdict (..),
    admitByIntegrity,
    evalTier,
    logDenials,
    packumentServeDecision,
    recordDenials,
    recordEffectfulFailures,
 )
import Ecluse.Core.Server.Pipeline.Origin (
    Contribution (..),
    OriginResult (..),
    fetchPrivateOrigin,
    fetchPublicOrigin,
    fingerprintPiece,
    originManifest,
    originMissed,
 )
import Ecluse.Core.Server.Pipeline.Shared
import Ecluse.Core.Server.Response (
    PackumentStatus (PackumentBadGateway, PackumentForbidden, PackumentOk, PackumentServerError, PackumentUnavailable),
    Refusal,
    RejectReason (Unavailable, UpstreamInvalid),
    Rejection (Rejection, rejectionMessage),
    ServeDecision (Admit, Reject),
    Transience (WillResolve),
    mkRefusal,
    packumentStatus,
    serveDecisionOf,
 )
import Ecluse.Core.Telemetry.Metrics qualified as Metric
import Ecluse.Core.Telemetry.Record (MetricsPort (..), timedSeconds)
import Ecluse.Core.Telemetry.Span (TracingPort, spanPackumentGate)

{- | The route-owned ways the ecosystem-neutral packument pipeline may answer.

The pipeline receives no WAI responder, so every branch selects one of these alternatives.
-}
data PackumentReplies response = PackumentReplies
    { packumentOk :: ResponseHeaders -> LByteString -> response
    , packumentNotModified :: ResponseHeaders -> response
    , packumentUnauthorised :: ResponseHeaders -> Refusal -> response
    , packumentForbidden :: ResponseHeaders -> Refusal -> response
    , packumentNotFound :: ResponseHeaders -> Refusal -> response
    , packumentInternal :: ResponseHeaders -> Refusal -> response
    , packumentBadGateway :: ResponseHeaders -> Refusal -> response
    , packumentUnavailable :: ResponseHeaders -> Refusal -> response
    }

{- | Serve a @GET \/{pkg}@ packument: fetch both upstreams concurrently, gate the public
versions, merge, and answer the conditional request.

The client's credential reaches the private origin only. An origin that self-reports a
different package name is dropped as untrusted, and a request left with no valid origin
answers @502@ rather than a genuine absence. A mount with no packument-serve dependencies
wired answers @501@.
-}
servePackument ::
    PackumentReplies response ->
    PackageName ->
    Request ->
    (response -> IO ResponseReceived) ->
    Handler ResponseReceived
servePackument = packumentWith PackumentFull

{- | Serve a @HEAD \/{pkg}@ packument. The gating matches 'servePackument' exactly, and the
reply carries the same status and headers, including the would-be body's @Content-Length@ and
the derived @ETag@. The route's 'Ecluse.Core.Server.Contract.bodilessContract' suppresses the
body. A packument body is assembled locally, so this @HEAD@ pumps no artifact body and carries
none of the egress amplification the tarball @HEAD@ closes.
-}
headPackument ::
    PackumentReplies response ->
    PackageName ->
    Request ->
    (response -> IO ResponseReceived) ->
    Handler ResponseReceived
headPackument = packumentWith PackumentHead

{- The packument serve mode. It changes exactly one thing: a @HEAD@ stamps the would-be
body's @Content-Length@ on the @200@ path, so a client sees the framing a @GET@ would. The
gating is identical between the two. -}
data PackumentServe
    = -- A @GET@: serve the merged packument body.
      PackumentFull
    | -- A @HEAD@: serve the identical status and headers (the would-be body's
      -- @Content-Length@ and the own @ETag@) with no body.
      PackumentHead

-- Dispatch shared by 'servePackument' and 'headPackument': read the mount's
-- dependencies and serve in the given mode.
packumentWith ::
    PackumentServe ->
    PackumentReplies response ->
    PackageName ->
    Request ->
    (response -> IO ResponseReceived) ->
    Handler ResponseReceived
packumentWith mode replies name request respond = do
    mount <- asks ctxMount
    serveWithDeps mode replies (bindingPackumentDeps mount) (forwardedCredential mount request) name request respond

-- Serve a packument once the mount's dependencies are known. The edge token is compared
-- before any upstream is touched, so an unauthenticated client cannot drive egress.
serveWithDeps ::
    PackumentServe ->
    PackumentReplies response ->
    PackumentDeps ->
    Maybe ClientCredential ->
    PackageName ->
    Request ->
    (response -> IO ResponseReceived) ->
    Handler ResponseReceived
serveWithDeps mode replies deps clientToken name request respond
    | not (edgeTokenMatches (pdInboundToken deps) clientToken) =
        liftIO (respond (packumentUnauthorised replies [] (mkRefusal Nothing unauthorisedMessage)))
    | otherwise = do
        rt <- asks ctxRuntime
        withAdmissionOrShed
            (srMetrics rt)
            (srAdmission rt)
            (liftIO (respond (packumentUnavailable replies [shedRetryAfter] (mkRefusal Nothing shedMessage))))
            (serveAdmittedPackument mode replies deps clientToken name request respond rt)
            pure

{- Serve a packument past the admission gate: fetch both origins concurrently, then gate,
merge, and either answer the conditional serve or take the no-survivors terminal. Its
serve context arrives as parameters, not a large @where@ closure, to keep the flow flat. -}
serveAdmittedPackument ::
    PackumentServe ->
    PackumentReplies response ->
    PackumentDeps ->
    Maybe ClientCredential ->
    PackageName ->
    Request ->
    (response -> IO ResponseReceived) ->
    ServeRuntime ->
    Handler ResponseReceived
serveAdmittedPackument mode replies deps clientToken name request respond rt = do
    logFM InfoS (ls ("serving packument request for " <> renderPackageName name))
    let metrics = srMetrics rt
    evalCtx <- liftIO (mkEvalContext (pdNow deps) (pdAdvisoryEtag deps))
    (privResult, pubResult) <- resolveOrigins deps rt clientToken name
    (public, publicExclusions, publicVerdicts) <- liftIO (gatePublic (srTracing rt) metrics deps name evalCtx (originManifest pubResult))
    let (private, privateExclusions) = admitTrusted (pdMinTrustedIntegrity deps) (originManifest privResult)
        sources = catMaybes [private, public]
        -- The terminal for a request that leaves nothing serveable: the merge found no
        -- survivors, or the divergence policy withheld the last of them (fail-closed).
        noServeableVersions = do
            let decisions = collectDecisions privResult pubResult (privateExclusions <> publicExclusions)
            liftIO (mpServeDecision metrics (packumentServeDecision decisions))
            liftIO (recordDenials metrics decisions)
            logDenials name (ctxAdvisoryEtag evalCtx) publicVerdicts
            liftIO (respond (noSurvivors replies deps decisions))
        -- Serve a plan that survived the divergence policy: record the admit, then answer
        -- the conditional request.
        serveResolved served = do
            liftIO (mpServeDecision metrics Metric.Admit)
            answerPackumentConditional mode replies deps name request respond rt sources served
    if pdFirstParty deps name && originMissed privResult
        then do
            liftIO (mpServeDecision metrics Metric.Deny)
            liftIO (respond (firstPartyAbsent replies deps name))
        else case packumentPlan sources of
            Nothing -> noServeableVersions
            Just plan -> do
                -- Every policy logs and meters a cross-upstream integrity divergence (threat #11). Only
                -- 'FailClosed' then withholds the contested versions.
                warnDivergences metrics name plan
                maybe noServeableVersions serveResolved (survivingPlan (pdDivergencePolicy deps) plan)

{- Resolve the origins this request may read: a first-party name reads the private origin alone
and never the public leg. Every other name reads both concurrently. -}
resolveOrigins :: PackumentDeps -> ServeRuntime -> Maybe ClientCredential -> PackageName -> Handler (OriginResult, OriginResult)
resolveOrigins deps rt clientToken name
    | pdFirstParty deps name = do
        privResult <- fetchPrivateOrigin deps rt clientToken name
        pure (privResult, OriginAbsent)
    | otherwise =
        concurrently
            (fetchPrivateOrigin deps rt clientToken name)
            (fetchPublicOrigin deps rt name)

{- The @404@ for a first-party name the private upstream did not resolve. The namespace belongs to
this deployment, so no public document may stand in for it. -}
firstPartyAbsent :: PackumentReplies response -> PackumentDeps -> PackageName -> response
firstPartyAbsent replies deps name =
    packumentNotFound replies [] (mkRefusal (pdHelp deps) message)
  where
    message :: Text
    message =
        "'"
            <> renderPackageName name
            <> "' did not resolve from the private upstream, and its namespace is first-party to this deployment, so it is never fetched from the public registry"

{- Answer the conditional packument request before any assembly. A 304 costs the fetches
and the plan, never the document rebuild, the encode, or an output hash. -}
answerPackumentConditional ::
    PackumentServe ->
    PackumentReplies response ->
    PackumentDeps ->
    PackageName ->
    Request ->
    (response -> IO ResponseReceived) ->
    ServeRuntime ->
    [Contribution] ->
    MergePlan ->
    Handler ResponseReceived
answerPackumentConditional mode replies deps name request respond rt sources plan = do
    let etag = packumentETag (pdMountBaseUrl deps) name (map fingerprintPiece sources)
    case evaluateETag (requestHeaders request) etag of
        NotModified matched -> do
            logFM DebugS (ls ("packument unchanged for " <> renderPackageName name <> " (304, unassembled)"))
            liftIO (respond (packumentNotModified replies [etagHeader matched]))
        Modified fresh -> do
            logFM DebugS (ls ("serving packument for " <> renderPackageName name))
            bytes <- liftIO (servedBytes rt deps sources plan fresh)
            liftIO (respond (packumentResponse replies mode fresh bytes))

{- Apply the trusted integrity floor ('pdMinTrustedIntegrity', default SHA-256) to a
private contribution, so a SHA-1-only or hashless private version is never listed. Trusted
versions stay unfiltered by the rules, because the trust split is the caller's. -}
admitTrusted :: MinTrustedIntegrity -> Maybe Manifest -> (Maybe Contribution, [ServeDecision])
admitTrusted minTrusted = \case
    Nothing -> (Nothing, [])
    Just manifest ->
        let (admissible, integrityRefusals) =
                admitByIntegrity minTrusted trustedIntegrityBelowFloor trustedIntegrityMissing (manifestInfo manifest)
         in if Map.null (infoVersions admissible)
                then (Nothing, integrityRefusals)
                else (Just (Contribution TrustedSource admissible (manifestRaw manifest) (manifestDigest manifest)), integrityRefusals)

{- Gate a public contribution: drop the versions below the integrity floor
('pdMinIntegrity'), then decide the rest through the rules engine, the first decisive rule
in boot order winning.

The gated 'Contribution' carries the typed view restricted to the survivors, because
'mergePackuments' treats a 'GatedSource' as already filtered. Feeding it the unfiltered
view would let a denied version reach the merge plan. The raw document stays whole, since
assembly takes only the plan's survivors from it. -}
gatePublic :: TracingPort -> MetricsPort -> PackumentDeps -> PackageName -> EvalContext -> Maybe Manifest -> IO (Maybe Contribution, [ServeDecision], [VersionVerdict])
gatePublic tracing metrics deps name ctx = \case
    Nothing -> pure (Nothing, [], [])
    Just manifest -> spanPackumentGate tracing name $ do
        let (admissible, integrityRefusals) = admitByIntegrity (pdMinIntegrity deps) integrityBelowFloor integrityMissing (manifestInfo manifest)
        (decisions, seconds) <- timedSeconds (decideVersions deps ctx admissible)
        mpRuleEvalDuration metrics (evalTier (pdRules deps)) seconds
        recordEffectfulFailures metrics (Map.elems decisions)
        let plan = filterPlanFromDecisions decisions admissible
        pure $
            if Set.null (fpSurvivors plan)
                then
                    let verdicts = projectDecisions admissible (fpDecisions plan)
                     in (Nothing, map vvDecision verdicts <> integrityRefusals, verdicts)
                else
                    ( Just (Contribution GatedSource (restrictToSurvivors (fpSurvivors plan) admissible) (manifestRaw manifest) (manifestDigest manifest))
                    , integrityRefusals
                    , []
                    )

{- Decide every version against the rules engine, keyed by the raw version string
'filterPlanFromDecisions' consumes. It is IO only because a rule may be effectful, and a
pure rule set launches none. -}
decideVersions :: PackumentDeps -> EvalContext -> PackageInfo -> IO (Map Text Decision)
decideVersions deps ctx info =
    traverse (evalRules ctx (pdRules deps)) (infoVersions info)

{- Project each excluded version's 'Decision' to a 'VersionVerdict' so a denial's audit
line can name the version. The plan carries 'fpDecisions' in @versions@-key order, which
is what lets them zip back onto the same-ordered keys. -}
projectDecisions :: PackageInfo -> [Decision] -> [VersionVerdict]
projectDecisions info =
    zipWith versionVerdict (Map.toList (infoVersions info))
  where
    versionVerdict (ver, details) d = VersionVerdict ver (serveDecisionOf details d)

-- The fully-assembled served body: the served document ('CachedDoc') to serialise and
-- answer against the conditional request.
newtype ServedBody = ServedBody {servedDoc :: CachedDoc}

{- Merge the resolved sources into the serve plan, 'Nothing' when no version survives. It
is split from the rendering so the conditional evaluation sits between them, and only a
'Modified' outcome pays for 'renderServedBody'. -}
packumentPlan :: [Contribution] -> Maybe MergePlan
packumentPlan sources = do
    plan <- mergePackuments [(srcProvenance s, srcInfo s) | s <- sources]
    guard (not (Map.null (mpSurvivors plan)))
    pure plan

{- The plan to serve under the operator's divergence policy. 'Nothing' when the policy
withheld the last surviving version, which takes the no-survivors terminal. -}
survivingPlan :: DivergencePolicy -> MergePlan -> Maybe MergePlan
survivingPlan policy plan =
    let served = applyDivergencePolicy policy plan
     in if Map.null (mpSurvivors served) then Nothing else Just served

{- | The derived packument validator: a SHA-256 over the serve's inputs, not over the
assembled bytes. It can never call a changed document unchanged, and it may change when
the re-assembled bytes would not have: a spurious @200@, never a wrong @304@. Deriving it
from inputs is what lets a @304@ skip assembly and encoding.

Fields reach the hash with unambiguous framing (a fixed-width digest, @NUL@-terminated
variable-length pieces, a terminator byte per source block), so no concatenation of
adjacent fields can collide with another split of the same bytes. Bump the leading salt
when the assembly's behaviour changes, so pre-change client caches revalidate as modified.
-}
packumentETag :: Text -> PackageName -> [(Provenance, ContentDigest, [Text])] -> ETag
packumentETag mountBaseUrl name sources =
    mkStrongETag (hashFinalize (hashUpdates (hashInit :: Context SHA256) pieces))
  where
    pieces :: [ByteString]
    pieces =
        [ "ecluse:packument-etag:v1\0"
        , encodeUtf8 mountBaseUrl <> "\0"
        , encodeUtf8 (renderPackageName name) <> "\0"
        ]
            <> concatMap sourcePieces sources

    sourcePieces :: (Provenance, ContentDigest, [Text]) -> [ByteString]
    sourcePieces (provenance, digest, survivors) =
        provenanceTag provenance
            : digestBytes digest
            : map (\v -> encodeUtf8 v <> "\0") survivors
                <> ["\1"]

    provenanceTag :: Provenance -> ByteString
    provenanceTag = \case
        TrustedSource -> "t\0"
        GatedSource -> "g\0"

-- The validator is a content address over every serve input, so the assembled bytes are
-- memoised under it and concurrent identical renders coalesce. A different private view
-- is a different key, so stored bytes can never cross a client boundary.
--
-- The render is total by contract, so a synchronous escape is an invariant break. The
-- confined 'RenderEscape' marker wraps the miss leg only, since a hit never runs it.
servedBytes :: ServeRuntime -> PackumentDeps -> [Contribution] -> MergePlan -> ETag -> IO ByteString
servedBytes rt deps sources plan etag =
    resolveAssembled (srMetrics rt) (srMetadataCache rt) (renderETag etag) $
        markRenderEscape $
            pure $!
                LBS.toStrict (metadataSerialise (pdMetadata deps) (servedDoc (renderServedBody deps sources plan)))
  where
    markRenderEscape :: IO ByteString -> IO ByteString
    markRenderEscape render = render `catchAny` (throwIO . RenderEscape)

{- Assemble the served packument by replaying the 'MergePlan' onto the sources' raw
documents through the mount adapter's own 'metadataAssemble'. The merge decides over the typed
'PackageInfo', but the body is built from the raw documents so unmodeled keys survive. -}
renderServedBody :: PackumentDeps -> [Contribution] -> MergePlan -> ServedBody
renderServedBody deps sources plan =
    ServedBody (metadataAssemble (pdMetadata deps) (pdMountBaseUrl deps) bySource plan (baseDocument sources))
  where
    bySource :: Map SourceId CachedDoc
    bySource = Map.fromList (zip [0 ..] (map srcValue sources))

{- The source whose unmodeled top-level keys are relayed into the served body: the
precedence winner, trusted before public, matching the identity the merge takes from its
first input. 'Nothing' only for an empty source list, which never reaches here. -}
baseDocument :: [Contribution] -> Maybe CachedDoc
baseDocument sources =
    srcValue <$> (find ((== TrustedSource) . srcProvenance) sources <|> listToMaybe sources)

{- The per-version serve decisions weighed for the no-survivors status. A private upstream
that did not resolve is transient, so a private outage with no public survivors renders
@503@ rather than @403@. An origin that answered for a different package is
'UpstreamInvalid', so its @502@ stays distinct from a genuine absence. A public upstream
that merely did not resolve is not by itself an outage. -}
collectDecisions :: OriginResult -> OriginResult -> [ServeDecision] -> [ServeDecision]
collectDecisions privResult pubResult publicExclusions =
    privateDecision privResult <> publicMismatch pubResult <> publicExclusions
  where
    privateDecision :: OriginResult -> [ServeDecision]
    privateDecision = \case
        OriginResolved _ -> []
        OriginUnresolved -> [neededUpstreamUnavailable]
        OriginNameMismatch -> [upstreamInvalidDecision]
        -- An unconfigured private leg (a serve-only pure gate) is not an outage:
        -- nothing was needed, so nothing is unavailable.
        OriginAbsent -> []

    publicMismatch :: OriginResult -> [ServeDecision]
    publicMismatch = \case
        OriginNameMismatch -> [upstreamInvalidDecision]
        OriginResolved _ -> []
        OriginUnresolved -> []
        OriginAbsent -> []

    neededUpstreamUnavailable :: ServeDecision
    neededUpstreamUnavailable = Reject (Rejection (Unavailable (WillResolve Nothing)) "a needed upstream was unavailable")

    upstreamInvalidDecision :: ServeDecision
    upstreamInvalidDecision = Reject (Rejection UpstreamInvalid "an upstream returned a packument for a different package")

{- The served packument @200@ over the memoised assembled bytes, carrying the 'ETag' the
caller already evaluated the conditional against. A 'PackumentHead' additionally stamps
the body's exact @Content-Length@, free off those bytes, and the route contract then
withholds them. -}
packumentResponse :: PackumentReplies response -> PackumentServe -> ETag -> ByteString -> response
packumentResponse replies mode etag bytes = case mode of
    PackumentFull ->
        packumentOk replies [etagHeader etag] (LBS.fromStrict bytes)
    PackumentHead ->
        packumentOk
            replies
            [etagHeader etag, (hContentLength, show (BS.length bytes))]
            (LBS.fromStrict bytes)

{- Render the no-survivors outcome: the status 'packumentStatus' chose over the
exclusions, with a denial body collecting the reasons. Never a @404@, because the package
existed and its versions were withheld. -}
noSurvivors :: PackumentReplies response -> PackumentDeps -> [ServeDecision] -> response
noSurvivors replies deps decisions = case status of
    PackumentOk -> packumentInternal replies [] body
    PackumentForbidden -> packumentForbidden replies [] body
    PackumentUnavailable retry -> packumentUnavailable replies (retryAfterHeaders retry) body
    PackumentBadGateway -> packumentBadGateway replies [] body
    PackumentServerError -> packumentInternal replies [] body
  where
    status :: PackumentStatus
    status = packumentStatus decisions

    -- The collected denial reasons. An empty set (no versions at all) renders a
    -- deny-by-default message rather than an empty body.
    message :: Text
    message = case mapMaybe rejectionText decisions of
        [] -> "no versions are available for this package"
        reasons -> T.intercalate "; " reasons

    body = mkRefusal (pdHelp deps) message

    rejectionText :: ServeDecision -> Maybe Text
    rejectionText = \case
        Admit -> Nothing
        Reject rej -> Just (rejectionMessage rej)
