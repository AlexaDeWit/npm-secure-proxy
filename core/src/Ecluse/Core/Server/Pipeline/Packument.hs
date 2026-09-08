-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Merge trusted private metadata with admitted public versions and serve conditional responses.
Private access refusals stop the request even when the public origin succeeds.
First-party names consult only the private origin.
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

-- | The route-owned ways the ecosystem-neutral packument pipeline may answer.
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

-- | Serve merged metadata while retaining private access authority and package identity checks.
servePackument ::
    PackumentReplies response ->
    PackageName ->
    Request ->
    (response -> IO ResponseReceived) ->
    Handler ResponseReceived
servePackument = packumentWith PackumentFull

-- | Serve the packument's GET status and headers without its body.
headPackument ::
    PackumentReplies response ->
    PackageName ->
    Request ->
    (response -> IO ResponseReceived) ->
    Handler ResponseReceived
headPackument = packumentWith PackumentHead

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
    case privResult of
        OriginAuthorisationFailure _ -> do
            liftIO (mpServeDecision metrics Metric.Deny)
            liftIO (respond (packumentForbidden replies [] (privateAuthorisationRefusal (pdHelp deps))))
        _ -> do
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

admitTrusted :: MinTrustedIntegrity -> Maybe Manifest -> (Maybe Contribution, [ServeDecision])
admitTrusted minTrusted = \case
    Nothing -> (Nothing, [])
    Just manifest ->
        let (admissible, integrityRefusals) =
                admitByIntegrity minTrusted trustedIntegrityBelowFloor trustedIntegrityMissing (manifestInfo manifest)
         in if Map.null (infoVersions admissible)
                then (Nothing, integrityRefusals)
                else (Just (Contribution TrustedSource admissible (manifestRaw manifest) (manifestDigest manifest)), integrityRefusals)

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

decideVersions :: PackumentDeps -> EvalContext -> PackageInfo -> IO (Map Text Decision)
decideVersions deps ctx info =
    traverse (evalRules ctx (pdRules deps)) (infoVersions info)

projectDecisions :: PackageInfo -> [Decision] -> [VersionVerdict]
projectDecisions info =
    zipWith versionVerdict (Map.toList (infoVersions info))
  where
    versionVerdict (ver, details) d = VersionVerdict ver (serveDecisionOf details d)

-- The fully-assembled served body: the served document ('CachedDoc') to serialise and
-- answer against the conditional request.
newtype ServedBody = ServedBody {servedDoc :: CachedDoc}

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

-- | A validator derived from framed inputs so unchanged requests skip assembly. Bump the salt when assembly behaviour changes.
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

-- Distinct private views produce distinct cache keys, preventing reuse across clients.
-- A render escape breaks the totality contract and is wrapped only on a cache miss.
servedBytes :: ServeRuntime -> PackumentDeps -> [Contribution] -> MergePlan -> ETag -> IO ByteString
servedBytes rt deps sources plan etag =
    resolveAssembled (srMetrics rt) (srMetadataCache rt) (renderETag etag) $
        markRenderEscape $
            pure $!
                LBS.toStrict (metadataSerialise (pdMetadata deps) (servedDoc (renderServedBody deps sources plan)))
  where
    markRenderEscape :: IO ByteString -> IO ByteString
    markRenderEscape render = render `catchAny` (throwIO . RenderEscape)

renderServedBody :: PackumentDeps -> [Contribution] -> MergePlan -> ServedBody
renderServedBody deps sources plan =
    ServedBody (metadataAssemble (pdMetadata deps) (pdMountBaseUrl deps) bySource plan (baseDocument sources))
  where
    bySource :: Map SourceId CachedDoc
    bySource = Map.fromList (zip [0 ..] (map srcValue sources))

baseDocument :: [Contribution] -> Maybe CachedDoc
baseDocument sources =
    srcValue <$> (find ((== TrustedSource) . srcProvenance) sources <|> listToMaybe sources)

collectDecisions :: OriginResult -> OriginResult -> [ServeDecision] -> [ServeDecision]
collectDecisions privResult pubResult publicExclusions =
    privateDecision privResult <> publicMismatch pubResult <> publicExclusions
  where
    privateDecision :: OriginResult -> [ServeDecision]
    privateDecision = \case
        OriginAuthorisationFailure _ -> []
        OriginResolved _ -> []
        OriginUnresolved -> [neededUpstreamUnavailable]
        OriginNameMismatch -> [upstreamInvalidDecision]
        -- An unconfigured private leg (a serve-only pure gate) is not an outage:
        -- nothing was needed, so nothing is unavailable.
        OriginAbsent -> []

    publicMismatch :: OriginResult -> [ServeDecision]
    publicMismatch = \case
        OriginAuthorisationFailure _ -> []
        OriginNameMismatch -> [upstreamInvalidDecision]
        OriginResolved _ -> []
        OriginUnresolved -> []
        OriginAbsent -> []

    neededUpstreamUnavailable :: ServeDecision
    neededUpstreamUnavailable = Reject (Rejection (Unavailable (WillResolve Nothing)) "a needed upstream was unavailable")

    upstreamInvalidDecision :: ServeDecision
    upstreamInvalidDecision = Reject (Rejection UpstreamInvalid "an upstream returned a packument for a different package")

packumentResponse :: PackumentReplies response -> PackumentServe -> ETag -> ByteString -> response
packumentResponse replies mode etag bytes = case mode of
    PackumentFull ->
        packumentOk replies [etagHeader etag] (LBS.fromStrict bytes)
    PackumentHead ->
        packumentOk
            replies
            [etagHeader etag, (hContentLength, show (BS.length bytes))]
            (LBS.fromStrict bytes)

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
