-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The runtime metric instruments and the typed emit helpers the hot path records
through: the IO layer over the pure @ecluse.*@ catalogue
("Ecluse.Core.Telemetry.Metrics").

"Ecluse.Core.Telemetry.Metrics" defines /what/ the catalogue is: the names and the
closed set of bounded labels. This module turns that catalogue into live OpenTelemetry
instruments and exposes one typed @record*@ per signal. Each helper takes only the
bounded label values its metric carries, never a free identifier. The type therefore
enforces the bounded-label discipline at the call site. The attribute set an instrument ever
sees is drawn from a small fixed product of the label domains.

== Gating: inert when telemetry is off

'newMetrics' builds the instruments from the 'Telemetry' handle's meter provider when
telemetry is enabled, and from the SDK's __no-op meter provider__ when it is not. A
no-op instrument discards every measurement, so the hot path calls the @record*@
helpers __unconditionally__. They are genuinely inert when telemetry is off: no
per-call branch, no provider fabricated at the edge. The 'Metrics' handle is therefore
total, with a real instrument for every signal whichever posture the proxy is in. The
no-op recording function ignores its arguments, so the 'metricAttributes' a call passes
is never forced. No attribute set is materialised when telemetry is off, only a thunk
that is discarded.

@docs\/architecture\/observability.md@ describes the catalogue and the cardinality
rule.
-}
module Ecluse.Runtime.Telemetry.Instruments (
    -- * The instrument handle
    Metrics,
    newMetrics,

    -- * The core recording ports
    metricsPortOf,
    workerMetricsPortOf,
    dredgerMetricsPortOf,
    advisorySyncMetricsPortOf,
    advisoryCompileMetricsPortOf,

    -- * Timing
    timedSeconds,

    -- * Serve decision
    recordServeDecision,

    -- * Rule gate
    recordRuleDenial,
    recordRuleEvalDuration,
    recordRuleEffectfulFailure,
    recordBreakerState,

    -- * Upstream fetch (data plane)
    recordUpstreamFetch,
    recordUpstreamFetchError,

    -- * Metadata cache
    recordCacheRequest,
    recordCacheEntries,

    -- * Mirror
    recordMirrorEnqueued,
    recordMirrorEnqueueFailure,
    recordMirrorJobProcessed,
    recordMirrorPublishDuration,

    -- * Mirror sweep
    recordSweptVersion,

    -- * Credentials
    recordCredentialRefresh,
    recordCredentialTokenTtl,

    -- * Advisory sync
    recordAdvisorySyncAttempt,
    recordAdvisorySyncDuration,

    -- * Advisory database age (observable)
    registerAdvisoryDatabaseAge,
    reportAdvisoryDatabaseAge,

    -- * Advisory compile
    recordAdvisoryCompileAccepted,
    recordAdvisoryCompileDropped,
    recordAdvisoryCompileRun,
) where

import GHC.Clock (getMonotonicTime)
import OpenTelemetry.Metric.Core (
    Counter (counterAdd),
    Gauge (gaugeRecord),
    Histogram (histogramRecord),
    Meter,
    MeterProvider,
    ObservableGauge (observableGaugeRegisterCallback),
    ObservableResult (observe),
    UpDownCounter (upDownCounterAdd),
    defaultAdvisoryParameters,
    getMeter,
    meterCreateCounterInt64,
    meterCreateGaugeInt64,
    meterCreateHistogram,
    meterCreateObservableGaugeInt64,
    meterCreateUpDownCounterInt64,
    noopMeterProvider,
 )

import Ecluse.Core.Ecosystem (Ecosystem)
import Ecluse.Core.Telemetry.Metrics (
    AdvisoryCompileResult,
    AdvisoryDropCause,
    AdvisorySyncResult,
    BreakerSource,
    BreakerState,
    CacheResult,
    Cause,
    CredentialResult,
    Decision,
    Label (LAdvisoryCompileResult, LAdvisoryDropCause, LAdvisorySyncResult, LBreakerSource, LCacheResult, LCause, LCredentialResult, LDecision, LEcosystem, LMirrorResult, LPerimeterCause, LProvider, LReasonClass, LRelayAnomaly, LRule, LStatusClass, LSweepResult, LTier, LUpstream),
    MetricName (..),
    MirrorResult,
    Provider,
    ReasonClass,
    RelayAnomaly,
    RequestFaultCause,
    StatusClass,
    SweepResult,
    Tier,
    Upstream,
    breakerStateCode,
    metricAttributes,
    metricName,
 )
import Ecluse.Core.Telemetry.Record (AdvisoryCompileMetricsPort (..), AdvisorySyncMetricsPort (..), DredgerMetricsPort (..), MetricsPort (..), WorkerMetricsPort (..), timedSeconds)
import Ecluse.Core.Telemetry.Span (ecluseScope)
import Ecluse.Runtime.Telemetry (Telemetry, telemetryMeterProvider)

{- | The live metric instruments, one per @ecluse.*@ signal, built by 'newMetrics' on one meter.

@http.server.request.duration@ is not here. The WAI instrumentation emits it from the server-span
meter ("Ecluse.Runtime.Telemetry.Tracing"), so duplicating it would double the series.
-}
data Metrics = Metrics
    { mServeDecision :: Counter Int64
    , mServeAdmissionInFlight :: UpDownCounter Int64
    , mServeAdmissionQueued :: Counter Int64
    , mPublishBodyInFlightBytes :: UpDownCounter Int64
    , mPublishBodyShed :: Counter Int64
    , mMergeDivergence :: Counter Int64
    , mRuleDenials :: Counter Int64
    , mRuleEvalDuration :: Histogram
    , mRuleEffectfulFailures :: Counter Int64
    , mRuleBreakerState :: Gauge Int64
    , mUpstreamFetchDuration :: Histogram
    , mUpstreamFetchErrors :: Counter Int64
    , mMetadataCacheRequests :: Counter Int64
    , mMetadataCacheEntries :: Gauge Int64
    , mMetadataCacheResidentBytes :: Gauge Int64
    , mSingleVersionCacheResidentBytes :: Gauge Int64
    , mAssembledCacheResidentBytes :: Gauge Int64
    , mServeRelayAnomalies :: Counter Int64
    , mServePerimeterFaults :: Counter Int64
    , mMirrorEnqueued :: Counter Int64
    , mMirrorEnqueueFailures :: Counter Int64
    , mMirrorJobsProcessed :: Counter Int64
    , mMirrorPublishDuration :: Histogram
    , mDredgerVersions :: Counter Int64
    , mCredentialRefresh :: Counter Int64
    , mCredentialTokenTtlSeconds :: Gauge Int64
    , mAdvisorySyncAttempts :: Counter Int64
    , mAdvisorySyncDuration :: Histogram
    , mAdvisoryDatabaseAgeSeconds :: ObservableGauge Int64
    , mAdvisoryCompileAccepted :: Counter Int64
    , mAdvisoryCompileDropped :: Counter Int64
    , mAdvisoryCompileRuns :: Counter Int64
    }

{- | Build the metric instruments from a 'Telemetry' handle.

When telemetry is disabled the instruments are created on the SDK's no-op meter provider, so every
@record*@ helper is inert.
-}
newMetrics :: Telemetry -> IO Metrics
newMetrics telemetry = do
    let meterProvider :: MeterProvider
        meterProvider = fromMaybe noopMeterProvider (telemetryMeterProvider telemetry)
    meter <- getMeter meterProvider ecluseScope
    Metrics
        <$> counter meter ServeDecision "{decision}" "serve decisions by admit/deny/unavailable"
        <*> upDownCounter meter ServeAdmissionInFlight "{request}" "in-flight metadata parses"
        <*> counter meter ServeAdmissionQueued "{request}" "admissions that waited for a slot"
        <*> upDownCounter meter PublishBodyInFlightBytes "By" "bytes reserved for buffered publish bodies"
        <*> counter meter PublishBodyShed "{request}" "publishes shed at the body-byte budget"
        <*> counter meter MergeDivergence "{divergence}" "cross-upstream integrity divergences detected in the packument merge"
        <*> counter meter RuleDenials "{denial}" "rule denials by rule and reason class"
        <*> histogram meter RuleEvalDuration "rule-evaluation latency by tier"
        <*> counter meter RuleEffectfulFailures "{failure}" "effectful-rule failures by cause"
        <*> gauge meter RuleBreakerState "circuit-breaker state by source (0 closed, 1 half-open, 2 open)"
        <*> histogram meter UpstreamFetchDuration "upstream metadata-fetch latency by upstream and status class"
        <*> counter meter UpstreamFetchErrors "{error}" "upstream metadata-fetch errors by upstream and cause"
        <*> counter meter MetadataCacheRequests "{request}" "metadata-cache lookups by hit/miss"
        <*> gauge meter MetadataCacheEntries "metadata-cache occupancy"
        <*> gauge meter MetadataCacheResidentBytes "full-packument metadata-cache resident bytes"
        <*> gauge meter SingleVersionCacheResidentBytes "single-version metadata-cache resident bytes"
        <*> gauge meter AssembledCacheResidentBytes "assembled-representation store resident bytes"
        <*> counter meter ServeRelayAnomalies "{relay}" "public relays that were not the admitted artifact, by class"
        <*> counter meter ServePerimeterFaults "{fault}" "pre-commit handler escapes answered by the request perimeter, by cause"
        <*> counter meter MirrorEnqueued "{job}" "mirror jobs enqueued"
        <*> counter meter MirrorEnqueueFailures "{failure}" "mirror enqueue failures"
        <*> counter meter MirrorJobsProcessed "{job}" "mirror jobs processed by result"
        <*> histogram meter MirrorPublishDuration "mirror publish latency"
        <*> counter meter DredgerVersions "{version}" "mirror-store versions a sweep cycle disposed of, by result"
        <*> counter meter CredentialRefresh "{refresh}" "credential refreshes by result and provider"
        <*> gauge meter CredentialTokenTtlSeconds "remaining outbound-token lifetime by provider"
        <*> counter meter AdvisorySyncAttempts "{attempt}" "advisory sync attempts by ecosystem and result"
        <*> histogram meter AdvisorySyncDuration "advisory sync attempt latency by ecosystem and result"
        <*> observableGauge meter AdvisoryDatabaseAgeSeconds "seconds since this ecosystem's serving advisory database was installed"
        <*> counter meter AdvisoryCompileAccepted "{advisory}" "advisory entries a compile pass accepted, by ecosystem"
        <*> counter meter AdvisoryCompileDropped "{advisory}" "advisory entries a compile pass dropped, by ecosystem and cause"
        <*> counter meter AdvisoryCompileRuns "{run}" "advisory compile passes by ecosystem and result"

counter :: Meter -> MetricName -> Text -> Text -> IO (Counter Int64)
counter meter name unit description =
    meterCreateCounterInt64 meter (metricName name) (Just unit) (Just description) defaultAdvisoryParameters

histogram :: Meter -> MetricName -> Text -> IO Histogram
histogram meter name description =
    meterCreateHistogram meter (metricName name) (Just "s") (Just description) defaultAdvisoryParameters

upDownCounter :: Meter -> MetricName -> Text -> Text -> IO (UpDownCounter Int64)
upDownCounter meter name unit description =
    meterCreateUpDownCounterInt64 meter (metricName name) (Just unit) (Just description) defaultAdvisoryParameters

gauge :: Meter -> MetricName -> Text -> IO (Gauge Int64)
gauge meter name description =
    meterCreateGaugeInt64 meter (metricName name) Nothing (Just description) defaultAdvisoryParameters

-- An asynchronous instrument: it carries no value of its own and reports what its registered
-- callbacks observe at each collection. It ships with none, so nothing reports until a
-- 'registerAdvisoryDatabaseAge' call attaches one.
observableGauge :: Meter -> MetricName -> Text -> IO (ObservableGauge Int64)
observableGauge meter name description =
    meterCreateObservableGaugeInt64 meter (metricName name) Nothing (Just description) defaultAdvisoryParameters []

{- | Project the instruments onto the core 'MetricsPort' that "Ecluse.Core.Server.Pipeline" records
through. It is inert when telemetry is off, since the instruments are.
-}
metricsPortOf :: Metrics -> MetricsPort
metricsPortOf m =
    MetricsPort
        { mpServeDecision = recordServeDecision m
        , mpServeAdmissionInFlight = recordServeAdmissionInFlight m
        , mpServeAdmissionQueued = recordServeAdmissionQueued m
        , mpPublishBodyInFlightBytes = \delta -> addDelta (mPublishBodyInFlightBytes m) (fromIntegral delta) []
        , mpPublishBodyShed = addOne (mPublishBodyShed m) []
        , mpMergeDivergence = recordMergeDivergence m
        , mpRuleDenial = recordRuleDenial m
        , mpRuleEvalDuration = recordRuleEvalDuration m
        , mpRuleEffectfulFailure = recordRuleEffectfulFailure m
        , mpUpstreamFetch = recordUpstreamFetch m
        , mpUpstreamFetchError = recordUpstreamFetchError m
        , mpCacheRequest = recordCacheRequest m
        , mpCacheEntries = recordCacheEntries m
        , mpCacheResidentBytes = recordCacheResidentBytes m
        , mpVersionCacheResidentBytes = recordVersionCacheResidentBytes m
        , mpAssembledCacheResidentBytes = recordAssembledCacheResidentBytes m
        , mpMirrorEnqueued = recordMirrorEnqueued m
        , mpPublicRelayAnomaly = recordPublicRelayAnomaly m
        , mpRequestPerimeterFault = recordRequestPerimeterFault m
        , mpMirrorEnqueueFailure = recordMirrorEnqueueFailure m
        }

{- | Project the instruments onto the core 'WorkerMetricsPort' that "Ecluse.Core.Worker" records
through. It is inert when telemetry is off, since the instruments are.
-}
workerMetricsPortOf :: Metrics -> WorkerMetricsPort
workerMetricsPortOf m =
    WorkerMetricsPort
        { wmpMirrorJobProcessed = recordMirrorJobProcessed m
        , wmpMirrorPublishDuration = recordMirrorPublishDuration m
        }

{- | Project the instruments onto the core 'DredgerMetricsPort' that "Ecluse.Core.Registry.Sweep"
records through. It is inert when telemetry is off, since the instruments are.
-}
dredgerMetricsPortOf :: Metrics -> DredgerMetricsPort
dredgerMetricsPortOf m = DredgerMetricsPort{dmpSweptVersion = recordSweptVersion m}

{- | Project the instruments onto the core 'AdvisorySyncMetricsPort' that "Ecluse.Runtime.Cve.Sync"
records through. It is inert when telemetry is off, since the instruments are.
-}
advisorySyncMetricsPortOf :: Metrics -> AdvisorySyncMetricsPort
advisorySyncMetricsPortOf m =
    AdvisorySyncMetricsPort
        { asmpSyncAttempt = recordAdvisorySyncAttempt m
        , asmpSyncDuration = recordAdvisorySyncDuration m
        }

{- | Project the instruments onto the core 'AdvisoryCompileMetricsPort' that
"Ecluse.Core.Osv.Compile" records through, bound to the ecosystem the pass compiles. The label
domain is the closed 'Ecosystem' enum, so a pass over a name outside it records no series at all.
-}
advisoryCompileMetricsPortOf :: Metrics -> Maybe Ecosystem -> AdvisoryCompileMetricsPort
advisoryCompileMetricsPortOf m = maybe inertCompilePort boundPort
  where
    boundPort eco =
        AdvisoryCompileMetricsPort
            { acmpCompileAccepted = recordAdvisoryCompileAccepted m eco
            , acmpCompileDropped = recordAdvisoryCompileDropped m eco
            , acmpCompileRun = recordAdvisoryCompileRun m eco
            }

-- No bounded label to record under, so nothing is recorded.
inertCompilePort :: AdvisoryCompileMetricsPort
inertCompilePort =
    AdvisoryCompileMetricsPort
        { acmpCompileAccepted = const pass
        , acmpCompileDropped = \_ _ -> pass
        , acmpCompileRun = const pass
        }

-- | Record one serve decision (@ecluse.serve.decision@): admit, deny, or unavailable.
recordServeDecision :: (MonadIO m) => Metrics -> Decision -> m ()
recordServeDecision m decision =
    addOne (mServeDecision m) [LDecision decision]

-- Record a change in in-flight metadata parses (@ecluse.serve.admission.in_flight@).
recordServeAdmissionInFlight :: (MonadIO m) => Metrics -> Int -> m ()
recordServeAdmissionInFlight m delta =
    addDelta (mServeAdmissionInFlight m) (fromIntegral delta) []

-- Record one admission that waited for a slot before proceeding (@ecluse.serve.admission.queued@).
recordServeAdmissionQueued :: (MonadIO m) => Metrics -> m ()
recordServeAdmissionQueued m =
    addOne (mServeAdmissionQueued m) []

{- Record one cross-upstream integrity divergence (@ecluse.registry.merge.divergence@),
incremented once per contradicting version. Label-free: the package, version, and digest
bodies live on the @WARNING@ log line, never a metric label (the bounded-label discipline).
-}
recordMergeDivergence :: (MonadIO m) => Metrics -> m ()
recordMergeDivergence m =
    addOne (mMergeDivergence m) []

{- | Record one rule denial (@ecluse.rule.denials@) by reason class and, for a policy denial, the
deciding rule. A non-policy refusal has no rule to attribute, so none is labelled.
-}
recordRuleDenial :: (MonadIO m) => Metrics -> Maybe Text -> ReasonClass -> m ()
recordRuleDenial m rule reasonClass =
    addOne (mRuleDenials m) (maybe [] (\name -> [LRule name]) rule <> [LReasonClass reasonClass])

-- | Record a rule-evaluation latency sample (@ecluse.rule.eval.duration@) by tier.
recordRuleEvalDuration :: (MonadIO m) => Metrics -> Tier -> Double -> m ()
recordRuleEvalDuration m tier seconds =
    record (mRuleEvalDuration m) seconds [LTier tier]

-- | Record one effectful-rule failure (@ecluse.rule.effectful.failures@) by cause.
recordRuleEffectfulFailure :: (MonadIO m) => Metrics -> Cause -> m ()
recordRuleEffectfulFailure m cause =
    addOne (mRuleEffectfulFailures m) [LCause cause]

{- | Record the current circuit-breaker state (@ecluse.rule.breaker.state@) for a
source as the gauge's bounded ordinal (0 closed, 1 half-open, 2 open).
-}
recordBreakerState :: (MonadIO m) => Metrics -> BreakerSource -> BreakerState -> m ()
recordBreakerState m source breakerState =
    set (mRuleBreakerState m) (breakerStateCode breakerState) [LBreakerSource source]

-- | Record an upstream metadata-fetch latency sample to @ecluse.upstream.fetch.duration@.
recordUpstreamFetch :: (MonadIO m) => Metrics -> Upstream -> StatusClass -> Double -> m ()
recordUpstreamFetch m upstream statusClass seconds =
    record (mUpstreamFetchDuration m) seconds [LUpstream upstream, LStatusClass statusClass]

-- | Record one upstream metadata-fetch error to @ecluse.upstream.fetch.errors@.
recordUpstreamFetchError :: (MonadIO m) => Metrics -> Upstream -> Cause -> m ()
recordUpstreamFetchError m upstream cause =
    addOne (mUpstreamFetchErrors m) [LUpstream upstream, LCause cause]

-- | Record one metadata-cache lookup (@ecluse.metadata_cache.requests@) as a hit or miss.
recordCacheRequest :: (MonadIO m) => Metrics -> CacheResult -> m ()
recordCacheRequest m result =
    addOne (mMetadataCacheRequests m) [LCacheResult result]

-- | Record the metadata cache's current occupancy (@ecluse.metadata_cache.entries@).
recordCacheEntries :: (MonadIO m) => Metrics -> Int -> m ()
recordCacheEntries m entries =
    set (mMetadataCacheEntries m) (fromIntegral entries) []

{- | Record the full-packument metadata cache's resident bytes
(@ecluse.metadata_cache.resident_bytes@).
-}
recordCacheResidentBytes :: (MonadIO m) => Metrics -> Int -> m ()
recordCacheResidentBytes m bytes =
    set (mMetadataCacheResidentBytes m) (fromIntegral bytes) []

{- | Record the single-version metadata cache's resident bytes
(@ecluse.metadata_cache.version.resident_bytes@).
-}
recordVersionCacheResidentBytes :: (MonadIO m) => Metrics -> Int -> m ()
recordVersionCacheResidentBytes m bytes =
    set (mSingleVersionCacheResidentBytes m) (fromIntegral bytes) []

{- | Record the assembled-representation store's resident bytes
(@ecluse.metadata_cache.assembled.resident_bytes@).
-}
recordAssembledCacheResidentBytes :: (MonadIO m) => Metrics -> Int -> m ()
recordAssembledCacheResidentBytes m bytes =
    set (mAssembledCacheResidentBytes m) (fromIntegral bytes) []

-- | Record one mirror job enqueued (@ecluse.mirror.enqueued@).
recordMirrorEnqueued :: (MonadIO m) => Metrics -> m ()
recordMirrorEnqueued m = addOne (mMirrorEnqueued m) []

-- | Record one mirror enqueue failure (@ecluse.mirror.enqueue.failures@).
recordMirrorEnqueueFailure :: (MonadIO m) => Metrics -> m ()
recordMirrorEnqueueFailure m = addOne (mMirrorEnqueueFailures m) []

-- Record one perimeter-answered handler escape (@ecluse.serve.perimeter.faults@) by cause.
recordRequestPerimeterFault :: (MonadIO m) => Metrics -> RequestFaultCause -> m ()
recordRequestPerimeterFault m cause = addOne (mServePerimeterFaults m) [LPerimeterCause cause]

-- Record one anomalous public relay (@ecluse.serve.relay.anomalies@) by class.
recordPublicRelayAnomaly :: (MonadIO m) => Metrics -> RelayAnomaly -> m ()
recordPublicRelayAnomaly m cls = addOne (mServeRelayAnomalies m) [LRelayAnomaly cls]

-- | Record one processed mirror job (@ecluse.mirror.jobs.processed@) by its result.
recordMirrorJobProcessed :: (MonadIO m) => Metrics -> MirrorResult -> m ()
recordMirrorJobProcessed m result =
    addOne (mMirrorJobsProcessed m) [LMirrorResult result]

-- | Record one disposition of one swept mirror-store version (@ecluse.dredger.versions@).
recordSweptVersion :: (MonadIO m) => Metrics -> SweepResult -> m ()
recordSweptVersion m result = addOne (mDredgerVersions m) [LSweepResult result]

-- | Record a mirror publish latency sample (@ecluse.mirror.publish.duration@).
recordMirrorPublishDuration :: (MonadIO m) => Metrics -> Double -> m ()
recordMirrorPublishDuration m seconds =
    record (mMirrorPublishDuration m) seconds []

-- | Record one credential refresh (@ecluse.credential.refresh@) by result and provider.
recordCredentialRefresh :: (MonadIO m) => Metrics -> Provider -> CredentialResult -> m ()
recordCredentialRefresh m provider result =
    addOne (mCredentialRefresh m) [LProvider provider, LCredentialResult result]

{- | Record an outbound token's remaining lifetime in whole seconds
(@ecluse.credential.token.ttl.seconds@). A stuck refresh alarms as the gauge decays towards zero.
-}
recordCredentialTokenTtl :: (MonadIO m) => Metrics -> Provider -> Int -> m ()
recordCredentialTokenTtl m provider seconds =
    set (mCredentialTokenTtlSeconds m) (fromIntegral seconds) [LProvider provider]

-- | Record one advisory sync attempt to @ecluse.advisory.sync.attempts@.
recordAdvisorySyncAttempt :: (MonadIO m) => Metrics -> Ecosystem -> AdvisorySyncResult -> m ()
recordAdvisorySyncAttempt m eco result =
    addOne (mAdvisorySyncAttempts m) [LEcosystem eco, LAdvisorySyncResult result]

-- | Record one advisory sync attempt's latency in seconds (@ecluse.advisory.sync.duration@).
recordAdvisorySyncDuration :: (MonadIO m) => Metrics -> Ecosystem -> AdvisorySyncResult -> Double -> m ()
recordAdvisorySyncDuration m eco result seconds =
    record (mAdvisorySyncDuration m) seconds [LEcosystem eco, LAdvisorySyncResult result]

{- | Attach one ecosystem's advisory-database age to @ecluse.advisory.database.age.seconds@.

@installedAt@ is the slot's install stamp ('Ecluse.Core.Cve.Slot.generationInstalledAt'). The SDK
invokes the callback at each collection, so the reported age climbs on its own: no task has to be
alive to push it, and a sync task that dies or restarts cannot freeze or reset it. Registering is
inert when telemetry is off, because the no-op instrument never calls back.
-}
registerAdvisoryDatabaseAge :: Metrics -> Ecosystem -> IO Double -> IO ()
registerAdvisoryDatabaseAge m eco installedAt =
    void (observableGaugeRegisterCallback (mAdvisoryDatabaseAgeSeconds m) (reportAdvisoryDatabaseAge eco installedAt))

{- | What one collection of @ecluse.advisory.database.age.seconds@ reports: whole seconds from the
install stamp to now, under the ecosystem label. The reading is monotonic, so an age is never
negative, and the clamp holds that even for a stamp from the future.
-}
reportAdvisoryDatabaseAge :: Ecosystem -> IO Double -> ObservableResult Int64 -> IO ()
reportAdvisoryDatabaseAge eco installedAt result = do
    stamp <- installedAt
    now <- getMonotonicTime
    observe result (max 0 (floor (now - stamp))) (metricAttributes [LEcosystem eco])

-- | Record the advisory entries one compile pass accepted (@ecluse.advisory.compile.accepted@).
recordAdvisoryCompileAccepted :: (MonadIO m) => Metrics -> Ecosystem -> Int -> m ()
recordAdvisoryCompileAccepted m eco entries =
    addCount (mAdvisoryCompileAccepted m) entries [LEcosystem eco]

{- | Record the advisory entries one compile pass dropped for a bounded cause
(@ecluse.advisory.compile.dropped@).
-}
recordAdvisoryCompileDropped :: (MonadIO m) => Metrics -> Ecosystem -> AdvisoryDropCause -> Int -> m ()
recordAdvisoryCompileDropped m eco cause entries =
    addCount (mAdvisoryCompileDropped m) entries [LEcosystem eco, LAdvisoryDropCause cause]

-- | Record how one compile pass concluded (@ecluse.advisory.compile.runs@).
recordAdvisoryCompileRun :: (MonadIO m) => Metrics -> Ecosystem -> AdvisoryCompileResult -> m ()
recordAdvisoryCompileRun m eco result =
    addOne (mAdvisoryCompileRuns m) [LEcosystem eco, LAdvisoryCompileResult result]

addOne :: (MonadIO m) => Counter Int64 -> [Label] -> m ()
addOne instrument labels = liftIO (counterAdd instrument 1 (metricAttributes labels))

-- A counter never goes backwards, so a negative tally adds nothing.
addCount :: (MonadIO m) => Counter Int64 -> Int -> [Label] -> m ()
addCount instrument n labels = liftIO (counterAdd instrument (fromIntegral (max 0 n)) (metricAttributes labels))

addDelta :: (MonadIO m) => UpDownCounter Int64 -> Int64 -> [Label] -> m ()
addDelta instrument delta labels = liftIO (upDownCounterAdd instrument delta (metricAttributes labels))

record :: (MonadIO m) => Histogram -> Double -> [Label] -> m ()
record instrument value labels = liftIO (histogramRecord instrument value (metricAttributes labels))

-- Set a gauge under the given bounded labels: the last value wins per collect.
set :: (MonadIO m) => Gauge Int64 -> Int64 -> [Label] -> m ()
set instrument value labels = liftIO (gaugeRecord instrument value (metricAttributes labels))
