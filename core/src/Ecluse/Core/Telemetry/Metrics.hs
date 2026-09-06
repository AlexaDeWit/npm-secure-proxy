-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The @ecluse.*@ metric catalogue and its bounded-label discipline.

An inline proxy sees thousands of distinct packages, so the failure mode for metrics is
a series explosion. A single high-cardinality label (a package name, a version, a denial
message), multiplied across every package, turns a handful of series into millions. This
module is the structural defence. It defines the catalogue of metric names and,
crucially, the closed set of label types a metric may carry, every one a small,
fixed-domain enum.

== Bounded labels

'Label' is a closed sum pairing a bounded-domain key with a bounded value. The
high-cardinality identifiers (@package@, @version@, @scope@, a denial @message@) have no
constructor, so the type system keeps them off a metric. They ride the spans and the
structured log line ("Ecluse.Log") instead. The exception is @rule@, a rule's configured
name, bounded by a deployment's small fixed rule set rather than by an enum, and the sole
label carrying free text. @docs\/architecture\/observability.md@ holds the catalogue.
-}
module Ecluse.Core.Telemetry.Metrics (
    -- * The metric-name catalogue
    MetricName (..),
    metricName,

    -- * Label keys (the closed set)
    LabelKey (..),
    labelKeyName,

    -- * Bounded label values
    Decision (..),
    ReasonClass (..),
    Upstream (..),
    StatusClass (..),
    Provider (..),
    Cause (..),
    Tier (..),
    CacheResult (..),
    MirrorResult (..),
    SweepResult (..),
    CredentialResult (..),
    AdvisorySyncResult (..),
    advisorySyncResultName,
    AdvisoryDropCause (..),
    AdvisoryCompileResult (..),
    BreakerSource (..),
    RequestFaultCause (..),
    RelayAnomaly (..),

    -- * Breaker state (a bounded gauge value, not a label)
    BreakerState (..),
    breakerStateCode,

    -- * Labels
    Label (..),
    labelKey,
    renderLabel,

    -- * Attribute construction
    metricAttributes,
) where

-- relude's prelude exports a Bounded/Enum-based `universe`. Hide it so the
-- Generic-derived `Data.Universe.Class.universe` is the one in scope here.
import Prelude hiding (universe)

import OpenTelemetry.Attributes (
    Attributes,
    addAttributesFromBuilder,
    attr,
    defaultAttributeLimits,
    emptyAttributes,
 )

import Data.Universe.Class (Universe (..))
import Data.Universe.Generic (universeGeneric)

import Ecluse.Core.Ecosystem (Ecosystem, ecosystemName)

{- | The catalogue of metric instruments Écluse emits, each mapped to its wire name
through 'metricName'.

Queue backlog and DLQ depth are deliberately absent. Those are cloud-native metrics
(CloudWatch, Cloud Monitoring), not signals Écluse re-emits.
-}
data MetricName
    = -- | @http.server.request.duration@: server request latency (histogram).
      HttpServerRequestDuration
    | -- | @ecluse.serve.decision@: admit\/deny\/unavailable (counter).
      ServeDecision
    | -- | @ecluse.rule.denials@: rule denials by rule and reason class (counter).
      RuleDenials
    | -- | @ecluse.rule.eval.duration@: rule-evaluation latency by tier (histogram).
      RuleEvalDuration
    | -- | @ecluse.rule.effectful.failures@: effectful-rule failures (counter).
      RuleEffectfulFailures
    | -- | @ecluse.rule.breaker.state@: effectful\/mint breaker state by source (gauge).
      RuleBreakerState
    | -- | @ecluse.serve.admission.in_flight@: in-flight metadata parses (up-down counter).
      ServeAdmissionInFlight
    | -- | @ecluse.serve.admission.queued@: admissions that waited for a slot (counter).
      ServeAdmissionQueued
    | -- | @ecluse.publish.body.in_flight_bytes@: bytes reserved for buffered publish bodies (up-down counter).
      PublishBodyInFlightBytes
    | -- | @ecluse.publish.body.shed@: publishes shed at the body-byte budget (counter).
      PublishBodyShed
    | -- | @ecluse.registry.merge.divergence@: cross-upstream integrity divergences detected in the packument merge (counter).
      MergeDivergence
    | -- | @ecluse.upstream.fetch.duration@: upstream fetch latency (histogram).
      UpstreamFetchDuration
    | -- | @ecluse.upstream.fetch.errors@: upstream fetch errors (counter).
      UpstreamFetchErrors
    | -- | @ecluse.metadata_cache.requests@: metadata-cache hit\/miss (counter).
      MetadataCacheRequests
    | -- | @ecluse.metadata_cache.entries@: metadata-cache occupancy (gauge).
      MetadataCacheEntries
    | -- | @ecluse.metadata_cache.resident_bytes@: full-packument cache resident bytes (gauge).
      MetadataCacheResidentBytes
    | -- | @ecluse.metadata_cache.version.resident_bytes@: single-version cache resident bytes (gauge).
      SingleVersionCacheResidentBytes
    | -- | @ecluse.metadata_cache.assembled.resident_bytes@: assembled-representation store resident bytes (gauge).
      AssembledCacheResidentBytes
    | -- | @ecluse.serve.perimeter.faults@: pre-commit handler escapes the request perimeter answered (counter).
      ServePerimeterFaults
    | -- | @ecluse.serve.relay.anomalies@: public relays that were not the admitted artifact (counter).
      ServeRelayAnomalies
    | -- | @ecluse.mirror.enqueued@: mirror jobs enqueued (counter).
      MirrorEnqueued
    | -- | @ecluse.mirror.enqueue.failures@: mirror enqueue failures (counter).
      MirrorEnqueueFailures
    | -- | @ecluse.mirror.jobs.processed@: mirror jobs processed by result (counter).
      MirrorJobsProcessed
    | -- | @ecluse.mirror.publish.duration@: mirror publish latency (histogram).
      MirrorPublishDuration
    | -- | @ecluse.dredger.versions@: mirror-store versions one sweep cycle disposed of, by result (counter).
      DredgerVersions
    | -- | @ecluse.credential.refresh@: credential refreshes by result and provider (counter).
      CredentialRefresh
    | -- | @ecluse.credential.token.ttl.seconds@: remaining token lifetime by provider (gauge).
      CredentialTokenTtlSeconds
    | -- | @ecluse.advisory.sync.attempts@: advisory sync attempts by ecosystem and result (counter).
      AdvisorySyncAttempts
    | -- | @ecluse.advisory.sync.duration@: advisory sync attempt latency by ecosystem and result (histogram).
      AdvisorySyncDuration
    | -- | @ecluse.advisory.database.age.seconds@: seconds since this ecosystem's last swap (gauge).
      AdvisoryDatabaseAgeSeconds
    | -- | @ecluse.advisory.compile.accepted@: advisory entries a compile pass accepted (counter).
      AdvisoryCompileAccepted
    | -- | @ecluse.advisory.compile.dropped@: advisory entries a compile pass dropped, by cause (counter).
      AdvisoryCompileDropped
    | -- | @ecluse.advisory.compile.runs@: compile passes by ecosystem and result (counter).
      AdvisoryCompileRuns
    deriving stock (Eq, Generic, Ord, Show)

instance Universe MetricName where universe = universeGeneric

-- | The wire name of a 'MetricName'.
metricName :: MetricName -> Text
metricName = \case
    HttpServerRequestDuration -> "http.server.request.duration"
    ServeDecision -> "ecluse.serve.decision"
    RuleDenials -> "ecluse.rule.denials"
    RuleEvalDuration -> "ecluse.rule.eval.duration"
    RuleEffectfulFailures -> "ecluse.rule.effectful.failures"
    RuleBreakerState -> "ecluse.rule.breaker.state"
    ServeAdmissionInFlight -> "ecluse.serve.admission.in_flight"
    ServeAdmissionQueued -> "ecluse.serve.admission.queued"
    PublishBodyInFlightBytes -> "ecluse.publish.body.in_flight_bytes"
    PublishBodyShed -> "ecluse.publish.body.shed"
    MergeDivergence -> "ecluse.registry.merge.divergence"
    UpstreamFetchDuration -> "ecluse.upstream.fetch.duration"
    UpstreamFetchErrors -> "ecluse.upstream.fetch.errors"
    MetadataCacheRequests -> "ecluse.metadata_cache.requests"
    MetadataCacheEntries -> "ecluse.metadata_cache.entries"
    MetadataCacheResidentBytes -> "ecluse.metadata_cache.resident_bytes"
    SingleVersionCacheResidentBytes -> "ecluse.metadata_cache.version.resident_bytes"
    AssembledCacheResidentBytes -> "ecluse.metadata_cache.assembled.resident_bytes"
    ServePerimeterFaults -> "ecluse.serve.perimeter.faults"
    ServeRelayAnomalies -> "ecluse.serve.relay.anomalies"
    MirrorEnqueued -> "ecluse.mirror.enqueued"
    MirrorEnqueueFailures -> "ecluse.mirror.enqueue.failures"
    MirrorJobsProcessed -> "ecluse.mirror.jobs.processed"
    MirrorPublishDuration -> "ecluse.mirror.publish.duration"
    DredgerVersions -> "ecluse.dredger.versions"
    CredentialRefresh -> "ecluse.credential.refresh"
    CredentialTokenTtlSeconds -> "ecluse.credential.token.ttl.seconds"
    AdvisorySyncAttempts -> "ecluse.advisory.sync.attempts"
    AdvisorySyncDuration -> "ecluse.advisory.sync.duration"
    AdvisoryDatabaseAgeSeconds -> "ecluse.advisory.database.age.seconds"
    AdvisoryCompileAccepted -> "ecluse.advisory.compile.accepted"
    AdvisoryCompileDropped -> "ecluse.advisory.compile.dropped"
    AdvisoryCompileRuns -> "ecluse.advisory.compile.runs"

{- | The closed set of metric label keys. Every label Écluse attaches is one of these
bounded-domain keys. The high-cardinality identifiers (@package@, @version@, @scope@, a
denial @message@) are deliberately absent, so they can never become a metric label.
-}
data LabelKey
    = KeyDecision
    | KeyReasonClass
    | KeyRule
    | KeyEcosystem
    | KeyMount
    | KeyUpstream
    | KeyStatusClass
    | KeyResult
    | KeyProvider
    | KeyCause
    | KeyBreakerSource
    | KeyTier
    deriving stock (Eq, Generic, Ord, Show)

instance Universe LabelKey where universe = universeGeneric

-- | The wire name of a 'LabelKey'.
labelKeyName :: LabelKey -> Text
labelKeyName = \case
    KeyDecision -> "decision"
    KeyReasonClass -> "reason_class"
    KeyRule -> "rule"
    KeyEcosystem -> "ecosystem"
    KeyMount -> "mount"
    KeyUpstream -> "upstream"
    KeyStatusClass -> "status_class"
    KeyResult -> "result"
    KeyProvider -> "provider"
    KeyCause -> "cause"
    KeyBreakerSource -> "source"
    KeyTier -> "tier"

-- | The serve decision (@ecluse.serve.decision@).
data Decision = Admit | Deny | Unavailable
    deriving stock (Eq, Generic, Show)

instance Universe Decision where universe = universeGeneric

{- | The bucketed class of a denial reason: a bounded summary of
"Ecluse.Core.Server.Response.RejectReason". It is not the rule name or the message,
which are high-cardinality and stay on the log line.
-}
data ReasonClass = ReasonPolicy | ReasonMissingIntegrity | ReasonUnavailable | ReasonLimit
    deriving stock (Eq, Generic, Show)

instance Universe ReasonClass where universe = universeGeneric

-- | Which upstream a data-plane fetch targeted.
data Upstream = Private | Public
    deriving stock (Eq, Generic, Show)

instance Universe Upstream where universe = universeGeneric

-- | The HTTP status class of an upstream response (the bounded summary of the code).
data StatusClass = Status2xx | Status3xx | Status4xx | Status5xx | StatusOther
    deriving stock (Eq, Generic, Show)

instance Universe StatusClass where universe = universeGeneric

{- | The store a mirror-write credential's refresh\/ttl signal concerns: one value per store tag
the configuration admits, so a dashboard and a mount's declaration spell the same word.
-}
data Provider = ProviderRegistry | ProviderCodeArtifact | ProviderVerdaccio
    deriving stock (Eq, Generic, Show)

instance Universe Provider where universe = universeGeneric

-- | A bounded error class for a failure signal (never the exception text).
data Cause = Timeout | Connection | Decode | UpstreamStatus | OtherCause
    deriving stock (Eq, Generic, Show)

instance Universe Cause where universe = universeGeneric

-- | The rule-evaluation tier a duration is measured at.
data Tier = Structural | Effectful
    deriving stock (Eq, Generic, Show)

instance Universe Tier where universe = universeGeneric

{- | Why the request perimeter had to answer for an escaped fault
(@ecluse.serve.perimeter.faults@). The unbounded detail rides the perimeter's log line,
never a label.
-}
data RequestFaultCause = RenderFault | UnclassifiedFault
    deriving stock (Eq, Generic, Show)

instance Universe RequestFaultCause where universe = universeGeneric

{- | What a public artifact relay passed through when it did not carry the admitted
artifact (@ecluse.serve.relay.anomalies@). It is a 2xx whose headers do not look like an
artifact, or a non-success relayed verbatim. The unbounded detail rides the paired
WARNING log line, never a label.
-}
data RelayAnomaly = RelayOddShape | RelayNonSuccess
    deriving stock (Eq, Generic, Show)

instance Universe RelayAnomaly where universe = universeGeneric

-- | A metadata-cache lookup result.
data CacheResult = Hit | Miss
    deriving stock (Eq, Generic, Show)

instance Universe CacheResult where universe = universeGeneric

{- | A processed mirror job's result. The worker counts the idempotent "already present"
outcome (a registry @409@) as 'Published', not as a distinct value.
-}
data MirrorResult
    = -- | The artifact reached the mirror target (an already-present version included).
      Published
    | -- | The job did not publish, and its message stays in the queue's own hands.
      Failed
    | {- | The worker retired the message itself, after it spent the queue's redelivery
      budget ('Ecluse.Core.Queue.deliveryBudgetSpent'). Distinct from 'Failed' because
      this is the terminus a deployment with no dead-letter queue has. An operator
      alerts on it, since nothing else captured a discarded job.
      -}
      Discarded
    deriving stock (Eq, Generic, Show)

instance Universe MirrorResult where universe = universeGeneric

{- | What the mirror sweep did with one version it examined. Every version counts once as
'SweepExamined' and once more under its disposition, so deletions read as a fraction of what was seen.
-}
data SweepResult
    = -- | The sweep evaluated the version.
      SweepExamined
    | -- | A named decisive deny removed it.
      SweepDeleted
    | -- | A named decisive deny would have removed it, under a dry run.
      SweepWouldDelete
    | -- | Nothing decisively denied it, so it stays.
      SweepKept
    | -- | A safety control held it back: the first-party belt, or the cycle's deletion cap.
      SweepGuardSkipped
    deriving stock (Eq, Generic, Show)

instance Universe SweepResult where universe = universeGeneric

-- | A credential-refresh result.
data CredentialResult = Refreshed | RefreshFailed
    deriving stock (Eq, Generic, Show)

instance Universe CredentialResult where universe = universeGeneric

{- | What one advisory sync attempt concluded. The value labels the
@ecluse.advisory.sync.*@ signals and the advisory sync span, mirroring the outcomes of
@Ecluse.Runtime.Cve.Sync@.
-}
data AdvisorySyncResult
    = -- | The sync verified a new artifact and swapped it into the read path.
      AdvisorySwapped
    | -- | The remote artifact matches the last seen one.
      AdvisoryUnchanged
    | -- | No artifact exists in the bucket yet.
      AdvisoryNonePublished
    | -- | The fetch itself did not deliver the object.
      AdvisoryFetchFailed
    | -- | Verification refused the downloaded artifact.
      AdvisoryRefused
    deriving stock (Eq, Generic, Show)

instance Universe AdvisorySyncResult where universe = universeGeneric

{- | The wire value of an advisory sync result. The metric label and the sync span's
result attribute must read identically, so the two signals join on it.
-}
advisorySyncResultName :: AdvisorySyncResult -> Text
advisorySyncResultName = \case
    AdvisorySwapped -> "swapped"
    AdvisoryUnchanged -> "unchanged"
    AdvisoryNonePublished -> "none_published"
    AdvisoryFetchFailed -> "fetch_failed"
    AdvisoryRefused -> "refused"

{- | Why a compile pass dropped one advisory entry (@ecluse.advisory.compile.dropped@). The
entry's own name and bytes stay on the drop log line, never a label.
-}
data AdvisoryDropCause
    = -- | The entry breached the per-advisory byte cap.
      DropOversize
    | -- | The entry's JSON did not decode.
      DropMalformed
    deriving stock (Eq, Generic, Show)

instance Universe AdvisoryDropCause where universe = universeGeneric

{- | What one compile pass concluded (@ecluse.advisory.compile.runs@). A pass that never
concluded, because a fetch or a filesystem fault escaped it, records neither value.
-}
data AdvisoryCompileResult
    = -- | The pass finalised an artifact.
      CompileCompleted
    | -- | The pass abandoned the artifact over a systemic drop rate.
      CompileAborted
    deriving stock (Eq, Generic, Show)

instance Universe AdvisoryCompileResult where universe = universeGeneric

-- | Which circuit breaker a state gauge concerns.
data BreakerSource = EffectfulRule | CredentialMint
    deriving stock (Eq, Generic, Show)

instance Universe BreakerSource where universe = universeGeneric

{- | The circuit-breaker state, recorded as the value of the @ecluse.rule.breaker.state@
gauge (labelled by 'BreakerSource'). It is a bounded measurement, not a label.
-}
data BreakerState = Closed | HalfOpen | Open
    deriving stock (Eq, Generic, Show)

instance Universe BreakerState where universe = universeGeneric

{- | The gauge code for a breaker state. Closed is @0@, so a dashboard alarms on "not
closed" without a high-cardinality label.
-}
breakerStateCode :: BreakerState -> Int64
breakerStateCode = \case
    Closed -> 0
    HalfOpen -> 1
    Open -> 2

{- | A single metric label: a bounded key paired with its bounded value. There is no
constructor for a package, version, scope, or message, so nothing can turn a
high-cardinality identifier into a label. 'LRule' carries a rule's configured name, the
one operator-bounded label: a deployment defines a small, fixed rule set.
-}
data Label
    = LDecision Decision
    | LReasonClass ReasonClass
    | LRule Text
    | LEcosystem Ecosystem
    | LMount Ecosystem
    | LUpstream Upstream
    | LStatusClass StatusClass
    | LCacheResult CacheResult
    | LMirrorResult MirrorResult
    | LSweepResult SweepResult
    | LCredentialResult CredentialResult
    | LAdvisorySyncResult AdvisorySyncResult
    | LAdvisoryCompileResult AdvisoryCompileResult
    | LAdvisoryDropCause AdvisoryDropCause
    | LProvider Provider
    | LCause Cause
    | LBreakerSource BreakerSource
    | LTier Tier
    | LPerimeterCause RequestFaultCause
    | LRelayAnomaly RelayAnomaly
    deriving stock (Eq, Show)

-- | The 'LabelKey' a 'Label' is filed under.
labelKey :: Label -> LabelKey
labelKey = \case
    LDecision{} -> KeyDecision
    LReasonClass{} -> KeyReasonClass
    LRule{} -> KeyRule
    LEcosystem{} -> KeyEcosystem
    LMount{} -> KeyMount
    LUpstream{} -> KeyUpstream
    LStatusClass{} -> KeyStatusClass
    LCacheResult{} -> KeyResult
    LMirrorResult{} -> KeyResult
    LSweepResult{} -> KeyResult
    LCredentialResult{} -> KeyResult
    LAdvisorySyncResult{} -> KeyResult
    LAdvisoryCompileResult{} -> KeyResult
    LAdvisoryDropCause{} -> KeyCause
    LProvider{} -> KeyProvider
    LCause{} -> KeyCause
    LBreakerSource{} -> KeyBreakerSource
    LTier{} -> KeyTier
    LPerimeterCause{} -> KeyCause
    LRelayAnomaly{} -> KeyCause

-- | Project a 'Label' to its @(key, value)@ wire pair.
renderLabel :: Label -> (Text, Text)
renderLabel label = (labelKeyName (labelKey label), labelValue label)

labelValue :: Label -> Text
labelValue = \case
    LDecision d -> case d of
        Admit -> "admit"
        Deny -> "deny"
        Unavailable -> "unavailable"
    LReasonClass r -> case r of
        ReasonPolicy -> "policy"
        ReasonMissingIntegrity -> "missing_integrity"
        ReasonUnavailable -> "unavailable"
        ReasonLimit -> "limit"
    LRule name -> name
    LEcosystem eco -> ecosystemName eco
    LMount eco -> ecosystemName eco
    LUpstream u -> case u of
        Private -> "private"
        Public -> "public"
    LStatusClass s -> case s of
        Status2xx -> "2xx"
        Status3xx -> "3xx"
        Status4xx -> "4xx"
        Status5xx -> "5xx"
        StatusOther -> "other"
    LCacheResult c -> case c of
        Hit -> "hit"
        Miss -> "miss"
    LMirrorResult m -> case m of
        Published -> "published"
        Failed -> "failed"
        Discarded -> "discarded"
    LSweepResult r -> case r of
        SweepExamined -> "examined"
        SweepDeleted -> "deleted"
        SweepWouldDelete -> "would_delete"
        SweepKept -> "kept"
        SweepGuardSkipped -> "guard_skipped"
    LCredentialResult c -> case c of
        Refreshed -> "refreshed"
        RefreshFailed -> "failed"
    LAdvisorySyncResult r -> advisorySyncResultName r
    LAdvisoryCompileResult r -> case r of
        CompileCompleted -> "completed"
        CompileAborted -> "aborted"
    LAdvisoryDropCause c -> case c of
        DropOversize -> "oversize"
        DropMalformed -> "malformed"
    LProvider p -> case p of
        ProviderRegistry -> "registry"
        ProviderCodeArtifact -> "codeArtifact"
        ProviderVerdaccio -> "verdaccio"
    LCause c -> case c of
        Timeout -> "timeout"
        Connection -> "connection"
        Decode -> "decode"
        UpstreamStatus -> "upstream_status"
        OtherCause -> "other"
    LBreakerSource b -> case b of
        EffectfulRule -> "effectful_rule"
        CredentialMint -> "credential_mint"
    LTier t -> case t of
        Structural -> "structural"
        Effectful -> "effectful"
    LPerimeterCause c -> case c of
        RenderFault -> "render"
        UnclassifiedFault -> "unclassified"
    LRelayAnomaly a -> case a of
        RelayOddShape -> "odd_shape"
        RelayNonSuccess -> "non_success"

{- | Materialise a label list into the OpenTelemetry 'Attributes' an instrument records
with. Every label value is bounded, so an instrument's attribute set stays a small fixed
product of the label domains.
-}
metricAttributes :: [Label] -> Attributes
metricAttributes labels =
    addAttributesFromBuilder
        defaultAttributeLimits
        emptyAttributes
        (foldMap (\label -> let (key, value) = renderLabel label in attr key value) labels)
