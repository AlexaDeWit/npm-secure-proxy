-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The metric-recording ports: the abstract interfaces the core serve path and
mirror worker record through, decoupled from any telemetry backend.

"Ecluse.Core.Telemetry.Metrics" defines /what/ the @ecluse.*@ catalogue is: the names
and the closed set of bounded labels. This module defines the recording interfaces over
that catalogue as records of @IO@ functions (the Handle pattern, as
"Ecluse.Core.Registry" and "Ecluse.Core.Queue" use it). There is one field per signal a
consumer emits, each taking only the bounded label values its metric carries. A consumer
records through its port and never names an OpenTelemetry instrument. The application
supplies the OTel-backed implementations behind them (see
@Ecluse.Runtime.Telemetry.Instruments@), and a test supplies an inert or recording
double.

There are five ports. 'MetricsPort' serves the serve path: serve decisions, the rule
gate, the data-plane upstream fetch, the metadata cache, and mirror enqueue.
'WorkerMetricsPort' serves the mirror worker: jobs processed, publish latency.
'DredgerMetricsPort' serves the mirror sweep: what each cycle did with the versions it
examined. 'AdvisorySyncMetricsPort' serves the advisory sync task: attempts and their
latency. 'AdvisoryCompileMetricsPort' serves the Pilot compile: the entries one pass
accepted or dropped, and how the pass concluded. The credential signals stay in the
application instrument set. Each port carries exactly the signals its consumer emits.

The advisory database's age is not here. It reads from the slot at each collection
(@Ecluse.Runtime.Telemetry.Instruments@), so no consumer has to push it.
-}
module Ecluse.Core.Telemetry.Record (
    -- * The serve-path recording port
    MetricsPort (..),

    -- * The worker recording port
    WorkerMetricsPort (..),

    -- * The mirror sweep recording port
    DredgerMetricsPort (..),

    -- * The advisory sync recording port
    AdvisorySyncMetricsPort (..),

    -- * The advisory compile recording port
    AdvisoryCompileMetricsPort (..),

    -- * Timing
    timedSeconds,
) where

import GHC.Clock (getMonotonicTime)

import Ecluse.Core.Ecosystem (Ecosystem)
import Ecluse.Core.Telemetry.Metrics (
    AdvisoryCompileResult,
    AdvisoryDropCause,
    AdvisorySyncResult,
    CacheResult,
    Cause,
    Decision,
    MirrorResult,
    ReasonClass,
    RelayAnomaly,
    RequestFaultCause,
    StatusClass,
    SweepResult,
    Tier,
    Upstream,
 )

{- | The metric-recording port over a telemetry backend, one field per @ecluse.*@ signal.
The closed label types in "Ecluse.Core.Telemetry.Metrics" bound each signal's cardinality.
-}
data MetricsPort = MetricsPort
    { mpServeDecision :: Decision -> IO ()
    -- ^ Record one serve decision (@ecluse.serve.decision@): admit, deny, or unavailable.
    , mpServeAdmissionInFlight :: Int -> IO ()
    {- ^ Record a change (+1 or -1) to in-flight metadata parses
    (@ecluse.serve.admission.in_flight@).
    -}
    , mpServeAdmissionQueued :: IO ()
    {- ^ Record one admission that waited for a slot before proceeding
    (@ecluse.serve.admission.queued@).
    -}
    , mpPublishBodyInFlightBytes :: Int -> IO ()
    {- ^ Record a change (the reserved weight, positive or negative) in bytes held
    for buffered publish bodies (@ecluse.publish.body.in_flight_bytes@).
    -}
    , mpPublishBodyShed :: IO ()
    -- ^ Record one publish shed at the body-byte budget (@ecluse.publish.body.shed@).
    , mpMergeDivergence :: IO ()
    {- ^ Record one cross-upstream integrity divergence found in the packument merge
    (@ecluse.registry.merge.divergence@), once per contradicting version. The
    high-cardinality identifiers (package, version, the digest bodies) go on the
    'WARNING' log line, never a metric label.
    -}
    , mpRuleDenial :: Maybe Text -> ReasonClass -> IO ()
    {- ^ Record one rule denial (@ecluse.rule.denials@) by reason class and, for a
    policy denial, the deciding rule. A non-policy refusal carries no rule.
    -}
    , mpRuleEvalDuration :: Tier -> Double -> IO ()
    -- ^ Record a rule-evaluation latency sample (@ecluse.rule.eval.duration@) by tier.
    , mpRuleEffectfulFailure :: Cause -> IO ()
    -- ^ Record one effectful-rule failure (@ecluse.rule.effectful.failures@) by cause.
    , mpUpstreamFetch :: Upstream -> StatusClass -> Double -> IO ()
    {- ^ Record an upstream metadata-fetch latency sample
    (@ecluse.upstream.fetch.duration@) by upstream and the response's status class.
    -}
    , mpUpstreamFetchError :: Upstream -> Cause -> IO ()
    {- ^ Record one upstream metadata-fetch error (@ecluse.upstream.fetch.errors@) by
    upstream and the bounded cause.
    -}
    , mpCacheRequest :: CacheResult -> IO ()
    {- ^ Record one metadata-cache lookup (@ecluse.metadata_cache.requests@) as a hit
    or a miss.
    -}
    , mpCacheEntries :: Int -> IO ()
    -- ^ Record the metadata cache's current occupancy (@ecluse.metadata_cache.entries@).
    , mpCacheResidentBytes :: Int -> IO ()
    {- ^ Record the full-packument metadata cache's resident bytes
    (@ecluse.metadata_cache.resident_bytes@).
    -}
    , mpVersionCacheResidentBytes :: Int -> IO ()
    {- ^ Record the single-version metadata cache's resident bytes
    (@ecluse.metadata_cache.version.resident_bytes@).
    -}
    , mpAssembledCacheResidentBytes :: Int -> IO ()
    {- ^ Record the assembled-representation store's resident bytes
    (@ecluse.metadata_cache.assembled.resident_bytes@).
    -}
    , mpPublicRelayAnomaly :: RelayAnomaly -> IO ()
    {- ^ Record one public artifact relay that did not carry the admitted artifact
    (@ecluse.serve.relay.anomalies@) by its bounded class. Steady state is zero.
    -}
    , mpRequestPerimeterFault :: RequestFaultCause -> IO ()
    {- ^ Record one pre-commit handler escape the request perimeter answered
    (@ecluse.serve.perimeter.faults@) by its bounded classified cause.
    -}
    , mpMirrorEnqueued :: IO ()
    {- ^ Record one mirror job accepted for enqueue (@ecluse.mirror.enqueued@): the
    serve path's hand-off to the enqueue buffer, not the backend write.
    -}
    , mpMirrorEnqueueFailure :: IO ()
    {- ^ Record one mirror enqueue failure (@ecluse.mirror.enqueue.failures@): a
    refused hand-off or a failed backend delivery.
    -}
    }

{- | The mirror worker's metric-recording port: the worker analogue of 'MetricsPort'. The two
consumers share no field. @Ecluse.Runtime.Telemetry.Instruments@ supplies the OTel implementation.
-}
data WorkerMetricsPort = WorkerMetricsPort
    { wmpMirrorJobProcessed :: MirrorResult -> IO ()
    {- ^ Record one processed mirror job (@ecluse.mirror.jobs.processed@) by its
    terminal result (published, or failed).
    -}
    , wmpMirrorPublishDuration :: Double -> IO ()
    -- ^ Record one mirror publish-latency sample (@ecluse.mirror.publish.duration@).
    }

{- | The mirror sweep's metric-recording port, recorded by "Ecluse.Core.Registry.Sweep". The
package and version a disposition concerns ride the sweep's own audit line, never a label.
-}
newtype DredgerMetricsPort = DredgerMetricsPort
    { dmpSweptVersion :: SweepResult -> IO ()
    {- ^ Record one disposition of one examined version (@ecluse.dredger.versions@). A version
    counts once as examined and once more under what the sweep did with it.
    -}
    }

{- | The advisory sync task's metric-recording port, recorded by the sync loop in
@Ecluse.Runtime.Cve.Sync@. Ecosystem and result are the only labels, so the series stays bounded.
-}
data AdvisorySyncMetricsPort = AdvisorySyncMetricsPort
    { asmpSyncAttempt :: Ecosystem -> AdvisorySyncResult -> IO ()
    -- ^ Record one advisory sync attempt (@ecluse.advisory.sync.attempts@) by ecosystem and result.
    , asmpSyncDuration :: Ecosystem -> AdvisorySyncResult -> Double -> IO ()
    {- ^ Record one advisory sync attempt's latency in seconds
    (@ecluse.advisory.sync.duration@) by ecosystem and result.
    -}
    }

{- | The Pilot compile's metric-recording port, recorded by @Ecluse.Core.Osv.Compile@. One port
is bound to one ecosystem, so no field carries the ecosystem the compile holds as free text.
@Ecluse.Runtime.Telemetry.Instruments@ binds the label when it builds the port.
-}
data AdvisoryCompileMetricsPort = AdvisoryCompileMetricsPort
    { acmpCompileAccepted :: Int -> IO ()
    {- ^ Record the advisory entries one compile pass accepted
    (@ecluse.advisory.compile.accepted@).
    -}
    , acmpCompileDropped :: AdvisoryDropCause -> Int -> IO ()
    {- ^ Record the advisory entries one compile pass dropped for a bounded cause
    (@ecluse.advisory.compile.dropped@). A pass with no drops records zero, so the series
    exists before the first drop.
    -}
    , acmpCompileRun :: AdvisoryCompileResult -> IO ()
    -- ^ Record how one compile pass concluded (@ecluse.advisory.compile.runs@).
    }

{- | Run an action and return its result with the elapsed seconds. It measures on the monotonic
clock, so a system-clock step never yields a negative or absurd duration.
-}
timedSeconds :: (MonadIO m) => m a -> m (a, Double)
timedSeconds action = do
    start <- liftIO getMonotonicTime
    result <- action
    end <- liftIO getMonotonicTime
    pure (result, end - start)
