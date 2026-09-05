-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Internal guts of the serve pipeline ("Ecluse.Core.Server.Pipeline"), exposed for
tests without widening that module's two-handler public API. This is the @.Internal@
convention "Ecluse.Core.Credential.Refresh.Internal" also uses. Importing it opts out of
the public module's stability promise.

It holds the operator-facing warning helpers for the bad-upstream and misconfiguration
conditions the response-bound guards leave silent:

* an upstream whose body does not decode into a usable packument ('logDecodeFailure')
* an upstream whose packument self-reports a name for a /different/ package
  ('logNameMismatch')
* a mount whose configured base URL cannot be formed into a request
  ('logUpstreamUnformable')
* an upstream the transport could not reach ('logUpstreamUnreachable')

Each surfaces at a 'WarningS' through the ambient @katip@ context before the contribution
degrades. The serve path classifies the conditions themselves as a typed
'Ecluse.Core.Registry.Metadata.MetadataError'. This module only renders their warning
lines. Alongside them sit the pure integrity-floor admission and the metric-label
projections the serve path records.
-}
module Ecluse.Core.Server.Pipeline.Internal (
    logDecodeFailure,
    logNameMismatch,
    logUpstreamUnformable,
    logUpstreamUnreachable,

    -- * Integrity-floor admission (pure)
    admitByIntegrity,

    -- * Metric-label projections (pure)
    packumentServeDecision,
    serveDecisionClass,
    denialLabels,
    evalTier,
    transienceCause,

    -- * Metric emits (off a serve outcome)
    recordDenials,
    recordEffectfulFailures,

    -- * Denial audit trail (structured log)
    VersionVerdict (..),
    Metadata (..),
    DenialAudit (..),
    denialAuditPayload,
    logDenials,
) where

import Data.Map.Strict qualified as Map
import Data.Text qualified as T
import Katip (KatipContext, Severity (WarningS), SimpleLogPayload, katipAddContext, logFM, ls, sl)

import Ecluse.Core.Cve (DbEtag (..))
import Ecluse.Core.Fault (TransportFault (tfCause, tfDetail))
import Ecluse.Core.Package (
    PackageDetails (pkgArtifacts),
    PackageInfo (infoDistTags, infoVersions),
    PackageName,
    renderPackageName,
 )
import Ecluse.Core.Package.Integrity (
    IntegrityFloor,
    VersionIntegrity (BelowFloor, NoIntegrity),
    partitionByFloor,
 )
import Ecluse.Core.Registry (UrlFormationError, renderUrlFormationError)
import Ecluse.Core.Rules (PreparedRule (prepResilience), cveIdsInReason)
import Ecluse.Core.Rules.Types (Decision (Undecidable))
import Ecluse.Core.Security.Authority (authorityLabel)
import Ecluse.Core.Server.Response (
    PackumentStatus (PackumentForbidden, PackumentOk),
    RejectReason (BelowIntegrityFloor, ByPolicy, MissingIntegrity, Unavailable, UpstreamInvalid),
    Rejection (Rejection),
    RuleName (RuleName),
    ServeDecision (Admit, Reject),
    Transience (WillResolve, WontResolve),
    packumentStatus,
 )
import Ecluse.Core.Telemetry.Metrics qualified as Metric
import Ecluse.Core.Telemetry.Record (MetricsPort, mpRuleDenial, mpRuleEffectfulFailure)
import Ecluse.Core.Version (renderVersion)

-- The operator-facing log filter key for this module's warnings, not the source module
-- path. Hold it stable so an operator's saved filter keeps matching.
pipelineInternalModule :: Text
pipelineInternalModule = "Ecluse.Server.Pipeline.Internal"

{- | Warn that an upstream body did not decode into a usable packument. The response-bound
guards leave this condition silent, so an operator would otherwise see nothing at all.
-}
logDecodeFailure :: (KatipContext m) => PackageName -> m ()
logDecodeFailure name =
    katipAddContext payload $ logFM WarningS (ls message)
  where
    payload = sl "module" pipelineInternalModule <> sl "package" (renderPackageName name)
    message :: Text
    message = "refused an upstream metadata document: it did not decode into a usable packument"

{- | Warn that an origin's packument self-reported a name for a different package, before
the serve path drops it as untrusted. An operator can then tell a misconfigured or hostile
upstream from an ordinary outage.
-}
logNameMismatch :: (KatipContext m) => PackageName -> Text -> Text -> m ()
logNameMismatch requested origin reported =
    katipAddContext payload $ logFM WarningS (ls message)
  where
    payload =
        sl "module" pipelineInternalModule
            <> sl "package" (renderPackageName requested)
            <> sl "origin" (authorityLabel origin)
            <> sl "upstreamName" reported
    message :: Text
    message = "dropped an upstream contribution: its packument self-reported a name for a different package"

{- | Warn that the configured base URL for this origin could not be formed into a request,
so no fetch was attempted. This is a configuration fault, so an operator sees a
misconfigured mount rather than an upstream that merely appears unreachable.
-}
logUpstreamUnformable :: (KatipContext m) => PackageName -> Text -> UrlFormationError -> m ()
logUpstreamUnformable name origin urlErr =
    katipAddContext payload $ logFM WarningS (ls message)
  where
    payload =
        sl "module" pipelineInternalModule
            <> sl "package" (renderPackageName name)
            <> sl "origin" (authorityLabel origin)
            <> sl "urlError" (renderUrlFormationError urlErr)
    message :: Text
    message = "refused an upstream metadata fetch: the configured base URL could not be formed into a request"

{- | Warn that the transport failed before a usable body returned, so this origin
contributes nothing to the request. An operator can then tell an outage from a decode
failure or a misconfigured mount.
-}
logUpstreamUnreachable :: (KatipContext m) => PackageName -> Text -> TransportFault -> m ()
logUpstreamUnreachable name origin fault =
    katipAddContext payload $ logFM WarningS (ls message)
  where
    payload =
        sl "module" pipelineInternalModule
            <> sl "package" (renderPackageName name)
            <> sl "origin" (authorityLabel origin)
            <> sl "transportCause" (show (tfCause fault) :: Text)
            <> sl "transportDetail" (tfDetail fault)
    message :: Text
    message = "an upstream metadata fetch could not reach the origin; its contribution degrades this request"

{- | Keep each version's artifacts whose strongest digest meets the integrity floor, prune
@dist-tags@ to the versions that keep at least one, and refuse the rest
('BelowIntegrityFloor' or 'MissingIntegrity').

The gate partitions __per artifact__. A file below the floor cannot be tied to a tamper-evident
fingerprint, so it is dropped rather than served to a client that could never verify it, and a
version drops only when no file of it survives. The surviving set is what the merge plan then
carries into the served listing, so the listing and the download gate refuse the same files.
-}
admitByIntegrity ::
    (IntegrityFloor floor) =>
    floor ->
    -- The refusal projected for a present-but-too-weak digest ('BelowFloor') …
    ServeDecision ->
    -- … and for a version carrying no digest at all ('NoIntegrity'). The public and
    -- trusted gates pass their own context-worded decisions.
    ServeDecision ->
    PackageInfo ->
    (PackageInfo, [ServeDecision])
admitByIntegrity floorSpec belowFloorRefusal missingRefusal info =
    ( info
        { infoVersions = admissible
        , infoDistTags = Map.filter ((`Map.member` admissible) . renderVersion) (infoDistTags info)
        }
    , refusals
    )
  where
    -- One walk of an up-to-100k-version map yields the surviving versions and both refusal
    -- buckets. The partitioned map is that large too.
    partitioned :: Map Text (Either VersionIntegrity PackageDetails)
    partitioned = Map.map admitArtifacts (infoVersions info)

    admitArtifacts details =
        (\survivors -> details{pkgArtifacts = survivors}) <$> partitionByFloor floorSpec (pkgArtifacts details)

    admissible :: Map Text PackageDetails
    admissible = Map.mapMaybe rightToMaybe partitioned

    -- 'Map.foldr' visits keys in ascending order and each arm prepends, so the below-floor
    -- refusals precede the missing-integrity ones, each in key order.
    refusals :: [ServeDecision]
    refusals = below <> missing
      where
        (below, missing) = Map.foldr bucket ([], []) partitioned
        bucket (Left BelowFloor) (b, m) = (belowFloorRefusal : b, m)
        bucket (Left NoIntegrity) (b, m) = (b, missingRefusal : m)
        -- 'partitionByFloor' never reports 'MeetsFloor' as a refusal: that arm is the survivors.
        bucket _ acc = acc

{- | Classify a no-survivors packument outcome into the bounded @ecluse.serve.decision@
value: a forbidden set is a denial, any other non-served status a transient unavailability.
-}
packumentServeDecision :: [ServeDecision] -> Metric.Decision
packumentServeDecision decisions = case packumentStatus decisions of
    PackumentForbidden -> Metric.Deny
    PackumentOk -> Metric.Admit
    _ -> Metric.Unavailable

-- | Classify a single artifact-path serve decision into the bounded metric decision.
serveDecisionClass :: ServeDecision -> Metric.Decision
serveDecisionClass = \case
    Admit -> Metric.Admit
    Reject (Rejection reason _) -> case reason of
        ByPolicy{} -> Metric.Deny
        MissingIntegrity -> Metric.Deny
        BelowIntegrityFloor -> Metric.Deny
        Unavailable{} -> Metric.Unavailable
        UpstreamInvalid -> Metric.Unavailable

{- | Map a reject reason to the @ecluse.rule.denials@ labels: the deciding rule (only a
policy denial names one) and the bounded reason class.
-}
denialLabels :: RejectReason -> (Maybe Text, Metric.ReasonClass)
denialLabels = \case
    ByPolicy (RuleName name) -> (Just name, Metric.ReasonPolicy)
    MissingIntegrity -> (Nothing, Metric.ReasonMissingIntegrity)
    BelowIntegrityFloor -> (Nothing, Metric.ReasonMissingIntegrity)
    Unavailable _ -> (Nothing, Metric.ReasonUnavailable)
    UpstreamInvalid -> (Nothing, Metric.ReasonUnavailable)

{- | The rule-evaluation tier a duration is attributed to, from the mount's rule set. The
two tiers are one engine, so a prepared rule's resilience policy is what marks it
effectful, not a separate list.
-}
evalTier :: [PreparedRule] -> Metric.Tier
evalTier rules = if any (isJust . prepResilience) rules then Metric.Effectful else Metric.Structural

{- | Map an undecidable verdict's transience to the bounded @ecluse.rule.effectful.failures@
cause.
-}
transienceCause :: Transience -> Metric.Cause
transienceCause = \case
    WillResolve _ -> Metric.Connection
    WontResolve -> Metric.OtherCause

{- | Record the @ecluse.rule.denials@ counter for each rejected decision, labelled by the
bounded reason class and, for a policy denial, the deciding rule.
-}
recordDenials :: MetricsPort -> [ServeDecision] -> IO ()
recordDenials metrics = traverse_ recordOne
  where
    recordOne :: ServeDecision -> IO ()
    recordOne = \case
        Admit -> pass
        Reject (Rejection reason _) ->
            let (rule, reasonClass) = denialLabels reason
             in mpRuleDenial metrics rule reasonClass

{- | Count each effectful-rule failure among a packument's per-version decisions. An
'Undecidable' is an effectful rule whose source could not be consulted, so it is the
effectful-failure signal.
-}
recordEffectfulFailures :: MetricsPort -> [Decision] -> IO ()
recordEffectfulFailures metrics = traverse_ recordOne
  where
    recordOne :: Decision -> IO ()
    recordOne = \case
        Undecidable transience _ -> mpRuleEffectfulFailure metrics (transienceCause transience)
        _ -> pass

{- | A per-version serve outcome that keeps the version alongside its decision, so a denial's
audit line can name the version it refused.
-}
data VersionVerdict = VersionVerdict
    { vvVersion :: Text
    , vvDecision :: ServeDecision
    }
    deriving stock (Eq, Show)

{- | An extensible bag of audit fields folded into a denial line's JSON at emit time. It
lives at the audit boundary and never on the pure 'Ecluse.Core.Rules.Types.Decision', so new
audit data joins here without threading a field through the rule engine.
-}
newtype Metadata = Metadata (Map Text Text)
    deriving stock (Eq, Show)

instance Semigroup Metadata where
    Metadata a <> Metadata b = Metadata (a <> b)

instance Monoid Metadata where
    mempty = Metadata Map.empty

{- | Everything one denial audit line records. The advisory 'DbEtag' is the database active
at emit, not the one the decision was evaluated against, because a shadow swap can land
mid-request.
-}
data DenialAudit = DenialAudit
    { daPackage :: PackageName
    , daVersion :: Text
    , daRule :: Maybe Text
    , daReasonClass :: Metric.ReasonClass
    , daAdvisoryEtag :: Maybe DbEtag
    , daExtra :: Metadata
    }

-- | Render a 'DenialAudit' to the structured payload katip folds into the line's @data@ object.
denialAuditPayload :: DenialAudit -> SimpleLogPayload
denialAuditPayload da =
    sl "module" pipelineInternalModule
        <> sl "package" (renderPackageName (daPackage da))
        <> sl "version" (daVersion da)
        <> maybe mempty (sl "rule") (daRule da)
        <> sl "reason_class" (show (daReasonClass da) :: Text)
        <> maybe mempty (\(DbEtag e) -> sl "active_advisory_db_etag" e) (daAdvisoryEtag da)
        <> metadataPayload (daExtra da)
  where
    metadataPayload (Metadata m) = Map.foldrWithKey (\k v acc -> sl k v <> acc) mempty m

{- | The advisory ids a denial named, recovered from its rendered message into a comma-joined
@cve@ field. Empty for a non-CVE denial, so the field appears only when an advisory drove
the refusal.
-}
cveMetadata :: Text -> Metadata
cveMetadata message = case cveIdsInReason message of
    [] -> mempty
    ids -> Metadata (Map.singleton "cve" (T.intercalate ", " ids))

{- | Emit one audit log line per denied version, __denials only__. 'recordDenials' counts the
same denials as metrics.
-}
logDenials :: (KatipContext m) => PackageName -> Maybe DbEtag -> [VersionVerdict] -> m ()
logDenials pkg etag = traverse_ logOne
  where
    logOne vv = case vvDecision vv of
        Admit -> pass
        Reject (Rejection reason message) ->
            let (rule, reasonClass) = denialLabels reason
                audit = DenialAudit pkg (vvVersion vv) rule reasonClass etag (cveMetadata message)
             in katipAddContext (denialAuditPayload audit) $
                    logFM WarningS (ls ("denied" :: Text))
