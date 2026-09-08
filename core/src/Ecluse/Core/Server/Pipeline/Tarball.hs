-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT
{-# LANGUAGE TupleSections #-}

{- | Serve artifacts from the private origin or an admitted public fallback.
Private access refusals stop fallback. Other private misses keep the first-party restriction.
GET and HEAD share policy, and private refusals never relay upstream error bodies.
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
import Network.HTTP.Types (RequestHeaders, ResponseHeaders, Status, status401, status403, status500, statusCode)
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
    MetadataClient (fetchVersionMetadata),
    MetadataError (MetadataAuthorisationFailure),
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

import Ecluse.Core.Registry (isAuthorisationFailure)
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

-- | The route-owned ways the tarball pipeline may answer.
data TarballReplies response = TarballReplies
    { tarballError :: Status -> ResponseHeaders -> Refusal -> response
    -- ^ An ecosystem-shaped local error.
    , tarballStream :: Status -> ResponseHeaders -> StreamingBody -> response
    -- ^ A transparent streamed upstream response.
    , tarballEmpty :: Status -> ResponseHeaders -> response
    -- ^ A transparent bodiless upstream response (@304@ or @HEAD@).
    }

-- | Serve an artifact with the caller's credential confined to the private origin.
serveTarball ::
    TarballReplies response ->
    PackageName ->
    Version ->
    Filename ->
    Request ->
    (response -> IO ResponseReceived) ->
    Handler ResponseReceived
serveTarball = tarballWith ServeFull

-- | Probe an artifact with HEAD through the same policy as GET, without pumping upstream bytes.
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
            Just (decision, received) -> do
                liftIO (mpServeDecision (srMetrics rt) decision)
                pure received
            -- A first-party name has one authority, so a private miss ends here rather than
            -- falling through to the public leg.
            Nothing
                | pdFirstParty deps name -> do
                    liftIO (mpServeDecision (srMetrics rt) Metric.Deny)
                    liftIO (respond (artifactError replies deps firstPartyAbsent))
                | otherwise -> servePublicArtifact mode replies rt deps validators name version file respond

-- An access refusal commits only the local error response, without reading upstream's body.
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
    Handler (Maybe (Metric.Decision, ResponseReceived))
streamPrivateArtifact mode replies rt deps token validators name version file respond =
    privateArtifactRequest rt deps token name version file >>= \case
        Left _ -> Just . (Metric.Deny,) <$> liftIO refuse
        Right (Just req) ->
            liftIO $
                fmap snd
                    <$> relayUpstreamWhen mode (srPrivateManager rt) (withValidators validators (withMethod mode req)) acceptPrivate relayUnjudged privateResponder
        Right Nothing -> pure Nothing
  where
    refuse = respond (tarballError replies status403 [] (privateAuthorisationRefusal (pdHelp deps)))
    acceptPrivate status = acceptArtifact status || isAuthorisationFailure (statusCode status)
    privateResponder =
        RelayResponder
            (\status headers body -> answerPrivate status (respond (tarballStream replies status headers body)))
            (\status headers -> answerPrivate status (respond (tarballEmpty replies status headers)))
    answerPrivate status admitted
        | isAuthorisationFailure (statusCode status) = (Metric.Deny,) <$> refuse
        | otherwise = (Metric.Admit,) <$> admitted

privateArtifactRequest ::
    ServeRuntime ->
    PackumentDeps ->
    Maybe ClientCredential ->
    PackageName ->
    Version ->
    Filename ->
    Handler (Either MetadataError (Maybe HTTP.Request))
privateArtifactRequest rt deps token name version file = case pdPrivateBaseUrl deps of
    Nothing -> pure (Right Nothing)
    Just privateBase
        | not (tarballHostHonoured TrustedOrigin deps privateHostPort privateHostPort) -> pure (Right Nothing)
        | null (artifactHosts (pdArtifact deps)) -> pure (Right (byConventionalPath privateBase))
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
        resolved <- tryAny (withPrivateMetadataClient rt deps privateBase token (\client -> fetchVersionMetadata client name version))
        pure $ case resolved of
            Right (Left refusal@MetadataAuthorisationFailure{}) -> Left refusal
            Right (Right details) -> Right (details >>= requestForDetails)
            _ -> Right Nothing
      where
        requestForDetails details = do
            artifact <- find ((== unFilename file) . artFilename) (pkgArtifacts details)
            let target = hostPortAddress (artUrl artifact)
            guard (artifactAuthorityHonoured (thgEcosystemHosts (pdTarballHostGate deps)) privateHostPort target)
            let carried = if target == privateHostPort then token else Nothing
            rightToMaybe (artifactByUrl (pdArtifact deps) carried (artUrl artifact))

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

-- | Preserve the admitted artifact's authoritative location through the public gate.
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

crossHostRefused :: TarballReplies response -> response
crossHostRefused replies =
    tarballError replies status403 [] (mkRefusal Nothing "the upstream artifact host is not permitted by the tarball-host policy")

-- | Missing versions and first-party misses map to 404. Other outcomes use 'artifactStatus'.
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

internalArtifactError :: TarballReplies response -> response
internalArtifactError replies =
    tarballError replies status500 [] (mkRefusal Nothing "could not form the upstream artifact URL")
