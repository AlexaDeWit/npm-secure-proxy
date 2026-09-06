-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The serve paths behind the package routes: the artifact relay behind @GET \/{pkg}\/-\/{file}.tgz@.

This is the data-plane handler module for artifacts. It composes the slices that decide
/what/ to serve into one action in the 'Ecluse.Core.Server.Context.Handler' reader. It
reads its mount's serve dependencies and the request runtime
'Ecluse.Core.Server.Context.ServeRuntime' from the request's
'Ecluse.Core.Server.Context.RequestCtx'.

== Artifact path

The tarball handler ('serveTarball') is the demand-driven artifact relay. Its two legs
locate the tarball differently, by the trust of their origin.

The __private__ leg is a __conventional stable read__. It fetches the tarball at
@{pdPrivateBaseUrl}\/{pkg}\/-\/{file}@ ('artifactRequestByFile'), addressed by the
client's requested filename, __without a private-packument fetch__. That is the stable,
cacheable shape an @npm ci@ install issues. A worst-case lockfile fan-out therefore pays
one artifact round-trip per tarball, not a packument fetch and decode per tarball it would
only discard. The request __forwards the client's credential__ over the __trusted__
manager, attached under the mount's ecosystem presentation. The shared redirect pin
finalises it ('Ecluse.Core.Registry.Request.finaliseRequest', @redirectCount = 0@). This
credential-bearing read __never follows a redirect__: a private CDN @302@ is returned to
the serve path, not chased with the credential. The constructed URL is on the private base
host, so the 'Ecluse.Core.Security.TrustedOrigin' tarball-host gate is satisfied
__same-host__. The trusted origin is also exempt from the internal-range block, so a
private registry on an internal address still serves. A @2xx@ streams the artifact through
with __bounded memory__ (the @withResponse@\/@responseStream@ relay, never a buffering
fetch) and __answers the request__. A non-@2xx@ status or a connection failure is a
__clean miss__ that falls through to the public leg.

The private leg applies __no serve-time integrity floor__. An established version pinned
in a consumer's lockfile and served from an operator-__trusted__ private registry is
fast-tracked. Its bytes are still verified __client-side by @npm@__, against the
@dist.integrity@ it resolved over the packument route, and by the __mirror worker__ on
ingestion. Fast-tracking gives up only the proactive "refuse weak-integrity" stance, not
tamper-evidence. This leg does not reach a private upstream that serves its tarball __off
the conventional @\/-\/@ path__. That means a separate files host, or a signed CDN URL the
convention cannot rebuild. That case is a private miss, and it falls through to the public
origin.

The __public__ leg honours the __authoritative upstream location__, not a reconstructed
conventional path. That location is the @Artifact.artUrl@ the projection preserved from
the gated version's @dist.tarball@, selected by the requested filename. The proxy can
therefore front a public registry that serves its artifacts from a separate host or an
off-convention path. That covers a CDN or files host, and a signed URL. The location is
gated, not trusted. It is fetched only when the tarball-host policy
('Ecluse.Core.Security.tarballHostAllowed')
admits its @host:port@ authority. The default refuses a cross-authority @dist.tarball@, a
different host or a different port alike. The untrusted egress is https-only with
certificate validation.

The public leg is anonymous. It gates __that one version__ against the rules, the same
machinery the packument path gates the whole set with, and selects the artifact. On an
admit it __streams the public bytes from @artUrl@ and enqueues a
'Ecluse.Core.Queue.MirrorJob'__. The job names that authoritative URL, so the worker can
back-fill the mirror target. On a reject, including a host the tarball-host policy
refuses, it selects the serve error model (@403@\/@503@\/@500@\/@404@) through the
route's injected reply factories. The enqueue is __serve-then-enqueue, best-effort and
non-blocking__. The artifact reaches the client first, and an enqueue failure is swallowed
rather than failing or delaying the response. The public relay is additionally __judged__
at relay time ('RelayVerdict', status and headers only, the body always verbatim). An
anomalous relay is logged and counted: a non-success passed through, or a success that is
visibly not an artifact. Only a clean artifact relay enqueues the mirror job.

Mirroring is __demand-driven__: a job is enqueued only here, on a tarball-path admit,
never when a packument is filtered. The two legs are not peers over time. The back-fill
retires each artifact from the public leg. At steady state the private conventional read
serves the vast majority of tarball traffic. The public leg is then the transient
onboarding and fail-over ramp (see @docs\/architecture\/registry-model.md@ → "Traffic
shape over time"). The serve path does __not__ verify @dist.integrity@. The client checks
the artifact's own hash, and the worker re-verifies before publishing.

An artifact is a __pass-through__ body, served byte-identical to upstream's. Its
conditional-GET handling therefore __relays__ rather than computing an own ETag (see
@docs\/architecture\/web-layer.md@ → "Middleware and helper libraries", and contrast the
merged-packument own-ETag path). The client's @If-None-Match@\/@If-Modified-Since@ are
forwarded onto the upstream artifact request on __both__ legs ('forwardValidators'). An
upstream @304 Not Modified@ is relayed straight back to the client as a bodiless @304@,
through 'Ecluse.Core.Server.Conditional.isNotModified' in the relay's accept predicate, so
the proxy does not re-download the tarball: the cheap freshness check on the hot artifact
path.
-}
module Ecluse.Core.Server.Pipeline.Tarball (
    TarballReplies (..),

    -- * The tarball handler
    serveTarball,
    headTarball,

    -- * The public artifact gate (exposed for direct testing)
    PublicArtifactGate (..),
    publicArtifactGate,
    artifactOutcomeStatus,
) where

import Network.HTTP.Client qualified as HTTP
import Network.HTTP.Types (RequestHeaders, ResponseHeaders, Status, status401, status403, status500)
import Network.Wai (Request, ResponseReceived, StreamingBody, requestHeaders)

import Ecluse.Core.Credential (ClientCredential)
import Ecluse.Core.Cve (DbEtag)
import Ecluse.Core.Fault (TransportFault, tfDetail)
import Ecluse.Core.Package (
    Artifact (artFilename, artUrl),
    PackageDetails (pkgArtifacts),
    PackageName,
 )
import Ecluse.Core.Package.Admission (
    ArtifactAdmission (
        AdmissionAdmit,
        AdmissionBelowFloor,
        AdmissionDenied,
        AdmissionFileAbsent,
        AdmissionIntegrityMissing,
        AdmissionUndecidable
    ),
    admissionTransience,
    admitArtifact,
 )
import Ecluse.Core.Queue (
    MirrorJob (MirrorJob, jobArtifactFilename, jobArtifactUrl, jobPackage, jobTraceContext, jobVersion),
    enqueue,
 )
import Ecluse.Core.Registry.Metadata (
    VersionEvaluation (VersionMetadataUnavailable, VersionMissing, VersionPresent),
    fetchVersionDetails,
    versionTransience,
 )
import Ecluse.Core.Rules (renderDecision)
import Ecluse.Core.Rules.Types (EvalContext, mkEvalContext)
import Ecluse.Core.Security (
    Origin (TrustedOrigin, UntrustedOrigin),
    artifactAuthorityHonoured,
    hostPortAddress,
    thgEcosystemHosts,
    thgPrivateHostPort,
    thgPublicHostPort,
 )
import UnliftIO (tryAny, withRunInIO)

import Ecluse.Core.Registry.Adapter.Capability (AdapterArtifact (artifactByFile, artifactByUrl, artifactHosts))
import Ecluse.Core.Server.Conditional (forwardValidators)
import Ecluse.Core.Server.Context (
    Handler,
    MountBinding (bindingPackumentDeps),
    PackumentDeps (..),
    ServeRuntime (..),
    ctxMount,
    ctxRuntime,
    pdMirror,
    pdPrivateBaseUrl,
    pdPublicBaseUrl,
    pdTarballHostGate,
    tarballHostHonoured,
 )
import Ecluse.Core.Server.Path (Filename, unFilename)
import Ecluse.Core.Server.Pipeline.Internal (
    VersionVerdict (..),
    evalTier,
    logDenials,
    recordDenials,
    serveDecisionClass,
 )
import Ecluse.Core.Server.Pipeline.Origin (mountOrigin, withPrivateMetadataClient, withPublicMetadataClient)
import Ecluse.Core.Server.Pipeline.Shared
import Ecluse.Core.Server.Pipeline.Tarball.Relay (
    ArtifactServe (ServeFull, ServeHead),
    RelayVerdict (RelayedArtifact, RelayedNonSuccess, RelayedOddShape),
    acceptArtifact,
    observeRelayAnomaly,
    relayJudged,
    relayUnjudged,
    relayUpstreamWhen,
    withMethod,
    withValidators,
 )
import Ecluse.Core.Server.Response (
    ArtifactStatus (NotFound, Unavailable'),
    Refusal,
    Rejection (rejectionMessage),
    ServeDecision (Admit, Reject),
    Transience (WontResolve),
    artifactHttpStatus,
    artifactStatus,
    mkRefusal,
    rejectUnavailable,
    serveDecisionOf,
 )
import Ecluse.Core.Server.Stream (RelayResponder (RelayResponder))
import Ecluse.Core.Server.Upstream (MirrorServePlan (MirrorOnAdmit, NoMirrorWrite))
import Ecluse.Core.Telemetry.Metrics qualified as Metric
import Ecluse.Core.Telemetry.Record (MetricsPort (..), timedSeconds)
import Ecluse.Core.Telemetry.Span (spanMirrorEnqueue, spanRuleEval)
import Ecluse.Core.Version (Version, renderVersion)

{- | The route-owned ways the tarball pipeline may answer. The route's explicit
pass-through contract fixes the response type, and the pipeline never receives WAI's
unrestricted responder.
-}
data TarballReplies response = TarballReplies
    { tarballError :: Status -> ResponseHeaders -> Refusal -> response
    -- ^ An ecosystem-shaped local error.
    , tarballStream :: Status -> ResponseHeaders -> StreamingBody -> response
    -- ^ A transparent streamed upstream response.
    , tarballEmpty :: Status -> ResponseHeaders -> response
    -- ^ A transparent bodiless upstream response (@304@ or @HEAD@).
    }

{- | Serve a @GET \/{pkg}\/-\/{file}.tgz@ artifact request end to end, over the request's
'RequestCtx'. The private leg forwards the client credential, while the public leg fetches
anonymously, so the credential never reaches the public upstream.
-}
serveTarball ::
    TarballReplies response ->
    PackageName ->
    Version ->
    Filename ->
    Request ->
    (response -> IO ResponseReceived) ->
    Handler ResponseReceived
serveTarball = tarballWith ServeFull

{- | Serve a @HEAD \/{pkg}\/-\/{file}.tgz@ artifact request end to end, over the request's
'RequestCtx'. It runs the identical pipeline as 'serveTarball' but probes the upstream
bodiless, because pumping a whole artifact body only to discard it would waste upstream
egress and hand a cheap HEAD a DoS-amplification lever.
-}
headTarball ::
    TarballReplies response ->
    PackageName ->
    Version ->
    Filename ->
    Request ->
    (response -> IO ResponseReceived) ->
    Handler ResponseReceived
headTarball = tarballWith ServeHead

-- The dispatch shared by 'serveTarball' and 'headTarball': read the mount's
-- dependencies and serve in the given mode.
tarballWith ::
    ArtifactServe ->
    TarballReplies response ->
    PackageName ->
    Version ->
    Filename ->
    Request ->
    (response -> IO ResponseReceived) ->
    Handler ResponseReceived
tarballWith mode replies name version filename request respond = do
    mount <- asks ctxMount
    serveTarballWithDeps mode replies (bindingPackumentDeps mount) (forwardedCredential mount request) name version filename request respond

-- Serve a tarball once the mount's dependencies are known: edge auth, then the private leg and,
-- on a miss, the gated public leg. The mount's ecosystem presentation supplied the credential.
serveTarballWithDeps ::
    ArtifactServe ->
    TarballReplies response ->
    PackumentDeps ->
    Maybe ClientCredential ->
    PackageName ->
    Version ->
    Filename ->
    Request ->
    (response -> IO ResponseReceived) ->
    Handler ResponseReceived
serveTarballWithDeps mode replies deps clientToken name version file request respond
    | not (edgeTokenMatches (pdInboundToken deps) clientToken) =
        liftIO (respond (tarballError replies status401 [] (mkRefusal Nothing unauthorisedMessage)))
    | otherwise = do
        rt <- asks ctxRuntime
        -- The client's conditional validators, relayed onto both legs' upstream requests so
        -- upstream can answer a 304 for a pass-through body (the conditional-GET contract).
        let validators = forwardValidators (requestHeaders request)
        privateHit <- streamPrivateArtifact mode replies rt deps clientToken validators name version file respond
        case privateHit of
            Just received -> do
                -- A private hit is an admit from the trusted upstream, and no rule
                -- gate runs. The public path records its own decision on a miss.
                liftIO (mpServeDecision (srMetrics rt) Metric.Admit)
                pure received
            -- A first-party name has one authority, so a private miss ends here rather than
            -- falling through to the public leg.
            Nothing
                | pdFirstParty deps name -> do
                    liftIO (mpServeDecision (srMetrics rt) Metric.Deny)
                    liftIO (respond (artifactError replies deps firstPartyAbsent))
                | otherwise -> servePublicArtifact mode replies rt deps validators name version file respond

-- A 2xx or an upstream 304 answers the request, and anything else is the clean miss the caller
-- falls through on. A private CDN 302 comes back rather than being chased with the credential.
streamPrivateArtifact ::
    ArtifactServe ->
    TarballReplies response ->
    ServeRuntime ->
    PackumentDeps ->
    Maybe ClientCredential ->
    RequestHeaders ->
    PackageName ->
    Version ->
    Filename ->
    (response -> IO ResponseReceived) ->
    Handler (Maybe ResponseReceived)
streamPrivateArtifact mode replies rt deps token validators name version file respond =
    privateArtifactRequest rt deps token name version file >>= \case
        Just req ->
            liftIO $
                fmap snd
                    <$> relayUpstreamWhen mode (srPrivateManager rt) (withValidators validators (withMethod mode req)) acceptArtifact relayUnjudged (relayResponder replies respond)
        Nothing -> pure Nothing

{- Which arm runs is the ecosystem's own fact. A registry that serves its own artifact bytes
declares no artifact host, so a blind probe of the conventional path costs no metadata read on a
private hit. One that declares artifact hosts cannot spell that path, because its index names
each file's location, so the file resolves through the index and is fetched where it said. -}
privateArtifactRequest ::
    ServeRuntime ->
    PackumentDeps ->
    Maybe ClientCredential ->
    PackageName ->
    Version ->
    Filename ->
    Handler (Maybe HTTP.Request)
privateArtifactRequest rt deps token name version file = case pdPrivateBaseUrl deps of
    Nothing -> pure Nothing
    Just privateBase
        | not (tarballHostHonoured TrustedOrigin deps privateHostPort privateHostPort) -> pure Nothing
        | null (artifactHosts (pdArtifact deps)) -> pure (byConventionalPath privateBase)
        | otherwise -> byIndexedLocation privateBase
  where
    -- The precomputed private authority. A conventionally-built URL is on the private base, so
    -- the gate stays applied and trivially satisfied without re-parsing the URL.
    privateHostPort = thgPrivateHostPort (pdTarballHostGate deps)

    byConventionalPath privateBase =
        rightToMaybe (artifactByFile (pdArtifact deps) (mountOrigin deps (srPrivateManager rt) privateBase token) name (unFilename file))

    -- The location is gated from the same definition the download gate reads, and the credential
    -- rides only when it is the private upstream itself.
    byIndexedLocation privateBase = do
        resolved <- tryAny (withPrivateMetadataClient rt deps privateBase token (\client -> fetchVersionDetails client name version))
        pure $ do
            VersionPresent details <- rightToMaybe resolved
            artifact <- find ((== unFilename file) . artFilename) (pkgArtifacts details)
            let target = hostPortAddress (artUrl artifact)
            guard (artifactAuthorityHonoured (thgEcosystemHosts (pdTarballHostGate deps)) privateHostPort target)
            let carried = if target == privateHostPort then token else Nothing
            rightToMaybe (artifactByUrl (pdArtifact deps) carried (artUrl artifact))

{- Serve the artifact from the public upstream after a private miss: gate the single
requested version against the rules. An admit streams the bytes anonymously and enqueues a
mirror job, a reject renders the serve error model. -}
servePublicArtifact ::
    ArtifactServe ->
    TarballReplies response ->
    ServeRuntime ->
    PackumentDeps ->
    RequestHeaders ->
    PackageName ->
    Version ->
    Filename ->
    (response -> IO ResponseReceived) ->
    Handler ResponseReceived
servePublicArtifact mode replies rt deps validators name version file respond = do
    let metrics = srMetrics rt
    -- The advisory database active for this request, resolved once and used both for the
    -- version's evaluation and for a denial's audit line.
    advisoryEtag <- liftIO (pdAdvisoryEtag deps)
    withAdmissionOrShed
        metrics
        (srAdmission rt)
        (liftIO (respond (tarballError replies shedStatus [shedRetryAfter] (mkRefusal Nothing shedMessage))))
        (gatePublicVersion rt deps name version file advisoryEtag)
        $ \case
            Admitted artifact -> do
                liftIO (mpServeDecision metrics Metric.Admit)
                withRunInIO $ \runInIO ->
                    streamPublicArtifact mode replies rt deps validators name version file artifact (runInIO . observeRelayAnomaly metrics name version) respond
            Refused decision -> do
                liftIO (mpServeDecision metrics (serveDecisionClass decision))
                logDenials name advisoryEtag [VersionVerdict (renderVersion version) decision]
                liftIO (recordDenials metrics [decision])
                liftIO (respond (artifactError replies deps decision))

{- | The outcome of gating a single requested artifact on the public path. The admit carries the
artifact, so the stream step honours its 'artUrl' rather than reconstructing the location.
-}
data PublicArtifactGate
    = -- | The gate admitted the version. Carries the artifact selected by filename.
      Admitted Artifact
    | -- | The gate refused the version: a policy denial, an upstream outage, or absence.
      Refused ServeDecision

{- Gate the requested version and select its artifact. The single-version read resolves the full
packument through the shared metadata cache, so a packument @GET@ and this gate are one call. -}
gatePublicVersion :: ServeRuntime -> PackumentDeps -> PackageName -> Version -> Filename -> Maybe DbEtag -> Handler PublicArtifactGate
gatePublicVersion rt deps name version file advisoryEtag = do
    evalCtx <- liftIO (mkEvalContext (pdNow deps) (pure advisoryEtag))
    eval <-
        withPublicMetadataClient rt deps (pdPublicBaseUrl deps) $ \client ->
            liftIO (fetchVersionDetails client name version)
    case eval of
        VersionMetadataUnavailable -> pure (Refused upstreamUnavailable)
        VersionMissing -> pure (Refused versionAbsent)
        VersionPresent details ->
            -- The rule-eval span wraps the decision and records its verdict, so a denial
            -- is explainable from the trace. The outage and version-absent branches above
            -- are not rule evaluations and carry no span.
            liftIO $
                spanRuleEval (srTracing rt) name version $ do
                    (gate, seconds) <- timedSeconds (gateVersion evalCtx deps file details)
                    mpRuleEvalDuration (srMetrics rt) (evalTier (pdRules deps)) seconds
                    pure (gate, gateVerdict gate)

-- The serve verdict a gate outcome carries, for the rule-eval span.
gateVerdict :: PublicArtifactGate -> ServeDecision
gateVerdict = \case
    Admitted _ -> Admit
    Refused decision -> decision

{- Gate one requested artifact through the shared admission oracle the worker's ingest
re-evaluation also runs. The trusted private leg never reaches this gate. -}
gateVersion :: EvalContext -> PackumentDeps -> Filename -> PackageDetails -> IO PublicArtifactGate
gateVersion ctx deps file details =
    publicArtifactGate details <$> admitArtifact ctx (pdRules deps) (pdMinIntegrity deps) file details

-- | Render the shared admission verdict on the serve surface. Pure and total.
publicArtifactGate :: PackageDetails -> ArtifactAdmission -> PublicArtifactGate
publicArtifactGate details admission = case admission of
    -- The carried floor-checked digest set is the worker's ingest concern. The serve path
    -- streams without rehashing, so it has no consumer for the set.
    AdmissionAdmit _ artifact _ -> Admitted artifact
    AdmissionDenied decision -> Refused (serveDecisionOf details decision)
    AdmissionUndecidable decision -> Refused (rejectUnavailable transience (renderDecision details decision))
    AdmissionFileAbsent -> Refused versionAbsent
    AdmissionBelowFloor -> Refused integrityBelowFloor
    AdmissionIntegrityMissing -> Refused integrityMissing
  where
    -- The @503@-versus-@500@ transience is the shared projection's, the one the worker's
    -- retry-versus-drop reads. A settled verdict cannot be waited out.
    transience = fromMaybe WontResolve (admissionTransience admission)

-- A transient public-upstream outage (→ @503@).
upstreamUnavailable :: ServeDecision
upstreamUnavailable =
    versionUnresolved VersionMetadataUnavailable "the upstream registry was unavailable"

{- A version absent from the public metadata. Its cause is terminal, and
'artifactOutcomeStatus' overrides that status to a @404@ forwarded miss. -}
versionAbsent :: ServeDecision
versionAbsent =
    versionUnresolved VersionMissing "the requested version was not found upstream"

{- A first-party artifact the private upstream did not serve. No public artifact may
stand in for it, and 'artifactOutcomeStatus' renders it @404@. -}
firstPartyAbsent :: ServeDecision
firstPartyAbsent =
    versionUnresolved
        VersionMissing
        "the requested artifact is first-party to this deployment, so it is served from the private upstream only and is never fetched from the public registry"

{- The refusal a version the single-version read could not resolve renders as. Its transience
is the shared projection's, the one the worker's retry-versus-drop reads. -}
versionUnresolved :: VersionEvaluation -> Text -> ServeDecision
versionUnresolved eval = rejectUnavailable (fromMaybe WontResolve (versionTransience eval))

{- Stream the artifact from the public upstream at the 'Artifact''s own 'artUrl', and
anonymously, so the client credential never reaches the public upstream. A host the
tarball-host policy refuses takes the @403@ path and an unformable URL the @500@ path. A
failure while opening the connection, a TLS handshake included, commits no response and
renders the transient @503@. Only a failure after the stream is committed propagates, so a
half-sent artifact is never followed by a second response. An upstream @304@ goes back to
the client bodiless, and the best-effort mirror enqueue runs after the response is begun. -}
streamPublicArtifact ::
    ArtifactServe ->
    TarballReplies response ->
    ServeRuntime ->
    PackumentDeps ->
    RequestHeaders ->
    PackageName ->
    Version ->
    Filename ->
    Artifact ->
    -- | Observe the relay verdict (the anomaly log line and metric).
    (RelayVerdict -> IO ()) ->
    (response -> IO ResponseReceived) ->
    IO ResponseReceived
streamPublicArtifact mode replies rt deps validators name version file artifact observeVerdict respond
    | not hostHonoured = respond (crossHostRefused replies)
    | otherwise = case publicRequest of
        Left _ -> respond (internalArtifactError replies)
        Right req ->
            relayUpstreamWhen mode (srPublicManager rt) req (const True) relayJudged (relayResponder replies respond) >>= \case
                Just (verdict, received) -> do
                    observeVerdict verdict
                    -- Only a clean artifact relay back-fills: a relayed miss would enqueue a
                    -- doomed job, an oddly-shaped 2xx a misleading one. A serve-only mount
                    -- ('NoMirrorWrite') enqueues nothing, so no span or metric fires either.
                    case (verdict, pdMirror deps) of
                        (RelayedArtifact, MirrorOnAdmit _) -> enqueueOnFull mode (enqueueMirror rt deps name version file artifact)
                        (RelayedArtifact, NoMirrorWrite) -> pass
                        (RelayedOddShape _, _) -> pass
                        (RelayedNonSuccess _, _) -> pass
                    pure received
                Nothing -> respond (artifactError replies deps upstreamUnavailable)
  where
    hostHonoured = tarballHostHonoured UntrustedOrigin deps (thgPublicHostPort (pdTarballHostGate deps)) (hostPortAddress (artUrl artifact))

    publicRequest = withValidators validators . withMethod mode <$> artifactByUrl (pdArtifact deps) Nothing (artUrl artifact)

-- Adapt the route's typed response constructors to the streaming helper's callback. The
-- upstream connection stays open until the selected response completes.
relayResponder :: TarballReplies response -> (response -> IO received) -> RelayResponder received
relayResponder replies respond =
    RelayResponder
        (\status headers body -> respond (tarballStream replies status headers body))
        (\status headers -> respond (tarballEmpty replies status headers))

-- Run the demand-driven mirror enqueue only on the 'ServeFull' (GET) path. A 'ServeHead'
-- served no bytes, so it back-fills nothing.
enqueueOnFull :: ArtifactServe -> IO () -> IO ()
enqueueOnFull mode act = case mode of
    ServeFull -> act
    ServeHead -> pass

{- Enqueue a demand-driven mirror job for an admitted artifact, best-effort. It runs after
the client response is begun and swallows any failure, so a queue outage never fails or
delays the serve. The job carries the artifact's authoritative URL and the serve-time
admitted filename, and nothing else: no credential, no mirror target, no digest and no
size. The queue payload is a trust boundary the worker grants no authority, so the worker
mints its own token and derives its own descriptor from the artifact it re-admits. -}
enqueueMirror :: ServeRuntime -> PackumentDeps -> PackageName -> Version -> Filename -> Artifact -> IO ()
enqueueMirror rt deps name version file artifact =
    case pdEgressUrl deps (artUrl artifact) of
        Left _ -> mpMirrorEnqueueFailure (srMetrics rt)
        Right egressUrl ->
            void . spanMirrorEnqueue (srTracing rt) name version (artUrl artifact) enqueueErrorDetail $
                enqueueJob egressUrl
  where
    enqueueJob egressUrl traceContext = do
        enqueued <- enqueue (srQueue rt) (mirrorJob egressUrl traceContext)
        -- This counts the hand-off outcome and never propagates it. The composition root's
        -- buffer callbacks count drops and backend delivery failures behind the hand-off.
        either (const (mpMirrorEnqueueFailure (srMetrics rt))) (const (mpMirrorEnqueued (srMetrics rt))) enqueued
        -- Hand the outcome back so the span bracket can mark a swallowed failure errored
        -- on the producer span. The metric counts it, the span explains it.
        pure enqueued

    mirrorJob egressUrl traceContext =
        MirrorJob
            { jobPackage = name
            , jobVersion = version
            , jobArtifactUrl = egressUrl
            , jobArtifactFilename = file
            , -- The enqueueing span's trace context, captured by the span bracket, so
              -- the worker's per-job span links back across the hop.
              jobTraceContext = traceContext
            }

    -- Project the swallowed enqueue outcome onto the producer span's status, so a trace
    -- explains why the mirror was not enqueued.
    enqueueErrorDetail :: Either TransportFault () -> Maybe Text
    enqueueErrorDetail = either (Just . enqueueFailureDetail) (const Nothing)

    enqueueFailureDetail :: TransportFault -> Text
    enqueueFailureDetail fault = "mirror enqueue failed: " <> tfDetail fault

{- A @403@ for an artifact whose authoritative @url@ the tarball-host gate refuses. This is
a gate denial rather than a rule outcome, and it renders on the same @403@ surface with a
fixed reason. -}
crossHostRefused :: TarballReplies response -> response
crossHostRefused replies =
    tarballError replies status403 [] (mkRefusal Nothing "the upstream artifact host is not permitted by the tarball-host policy")

{- | The status a refused artifact request renders. A version-absent miss and a first-party miss
are the @404@s: every other inability keeps the @503@ or @500@ its transience earns.
-}
artifactOutcomeStatus :: ServeDecision -> ArtifactStatus
artifactOutcomeStatus decision
    | decision `elem` [versionAbsent, firstPartyAbsent] = NotFound
    | otherwise = artifactStatus decision

{- Render a non-admit artifact outcome as the serve error model. A transient status carries no
suggested delay, because the single-artifact path has none to offer. -}
artifactError :: TarballReplies response -> PackumentDeps -> ServeDecision -> response
artifactError replies deps decision =
    tarballError replies (artifactHttpStatus status) retryHeaders (mkRefusal (pdHelp deps) message)
  where
    status :: ArtifactStatus
    status = artifactOutcomeStatus decision

    retryHeaders :: ResponseHeaders
    retryHeaders = case status of
        Unavailable' retry -> retryAfterHeaders retry
        _ -> []

    message :: Text
    message = case decision of
        Admit -> "the artifact is available"
        Reject rej -> rejectionMessage rej

{- A @500@ for an unformable upstream artifact URL: a configuration fault, not a serve
decision. The package segment and filename are already known-safe, so only a misconfigured
base URL reaches here. -}
internalArtifactError :: TarballReplies response -> response
internalArtifactError replies =
    tarballError replies status500 [] (mkRefusal Nothing "could not form the upstream artifact URL")
