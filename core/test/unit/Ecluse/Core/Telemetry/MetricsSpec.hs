-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Core.Telemetry.MetricsSpec (spec) where

import Prelude hiding (universe)

import Data.Text qualified as T
import Data.Universe.Class (universe)
import Test.Hspec

import Ecluse.Core.Ecosystem (Ecosystem (Npm, PyPI, RubyGems))
import Ecluse.Core.Telemetry.Metrics (
    AdvisoryCompileResult (CompileAborted, CompileCompleted),
    AdvisoryDropCause (DropMalformed, DropOversize),
    AdvisorySyncResult (AdvisoryFetchFailed, AdvisorySwapped),
    BreakerState (Closed, HalfOpen, Open),
    CacheResult (..),
    CredentialResult (..),
    Decision (..),
    Label (..),
    LabelKey,
    MirrorResult (..),
    Provider (ProviderCodeArtifact, ProviderRegistry, ProviderVerdaccio),
    ReasonClass (..),
    breakerStateCode,
    labelKey,
    labelKeyName,
    metricAttributes,
    metricName,
    renderLabel,
 )
import Ecluse.Test.Metrics (allLabelKeys, allMetricNames, highCardinalityKeys)

{- | Tests for the @ecluse.*@ catalogue and the bounded-label discipline. The crux is the
cardinality guard: package, version, scope, and message must never become metric labels.
-}
spec :: Spec
spec = do
    catalogueSpec
    labelKeySpec
    boundedDomainSpec
    renderSpec

catalogueSpec :: Spec
catalogueSpec = describe "metric-name catalogue" $ do
    it "renders the ecluse.* catalogue and the HTTP semantic convention to their wire names" $ do
        let names = map metricName allMetricNames
        names
            `shouldContain` [ "ecluse.serve.decision"
                            , "ecluse.rule.denials"
                            , "ecluse.rule.eval.duration"
                            , "ecluse.rule.effectful.failures"
                            , "ecluse.rule.breaker.state"
                            , "ecluse.serve.admission.in_flight"
                            , "ecluse.serve.admission.queued"
                            , "ecluse.publish.body.in_flight_bytes"
                            , "ecluse.publish.body.shed"
                            , "ecluse.registry.merge.divergence"
                            , "ecluse.upstream.fetch.duration"
                            , "ecluse.upstream.fetch.errors"
                            , "ecluse.metadata_cache.requests"
                            , "ecluse.metadata_cache.entries"
                            , "ecluse.metadata_cache.resident_bytes"
                            , "ecluse.metadata_cache.version.resident_bytes"
                            , "ecluse.metadata_cache.assembled.resident_bytes"
                            , "ecluse.serve.perimeter.faults"
                            , "ecluse.serve.relay.anomalies"
                            , "ecluse.mirror.enqueued"
                            , "ecluse.mirror.enqueue.failures"
                            , "ecluse.mirror.jobs.processed"
                            , "ecluse.mirror.publish.duration"
                            , "ecluse.dredger.versions"
                            , "ecluse.credential.refresh"
                            , "ecluse.credential.token.ttl.seconds"
                            , "ecluse.advisory.sync.attempts"
                            , "ecluse.advisory.sync.duration"
                            , "ecluse.advisory.database.age.seconds"
                            , "ecluse.advisory.compile.accepted"
                            , "ecluse.advisory.compile.dropped"
                            , "ecluse.advisory.compile.runs"
                            ]
        names `shouldContain` ["http.server.request.duration"]

    it "namespaces every metric under ecluse.* or the OTel http.* convention" $ do
        let names = map metricName allMetricNames
        all (\n -> "ecluse." `T.isPrefixOf` n || "http." `T.isPrefixOf` n) names `shouldBe` True

    it "does not re-emit cloud-native queue metrics" $
        map metricName allMetricNames
            `shouldNotContain` ["ecluse.queue.backlog", "ecluse.mirror.queue.depth", "ecluse.mirror.dlq.depth"]

labelKeySpec :: Spec
labelKeySpec = describe "label keys (the cardinality guard)" $ do
    it "is exactly the closed bounded-enum set" $
        map labelKeyName allLabelKeys
            `shouldMatchList` [ "decision"
                              , "reason_class"
                              , "rule"
                              , "ecosystem"
                              , "mount"
                              , "upstream"
                              , "status_class"
                              , "result"
                              , "provider"
                              , "cause"
                              , "source"
                              , "tier"
                              ]

    it "REJECTS high-cardinality identifiers as labels (the crux)" $
        -- No 'Label' constructor produces a high-cardinality key, and the closed key set holds none
        -- either, so nothing can attach an unbounded label.
        filter (`elem` highCardinalityKeys) (map labelKeyName allLabelKeys) `shouldBe` []

    it "files every bounded label under a key in the closed set" $
        all (\l -> labelKey l `elem` (allLabelKeys :: [LabelKey])) allBoundedLabels `shouldBe` True

boundedDomainSpec :: Spec
boundedDomainSpec = describe "bounded label value domains" $ do
    it "draws the whole bounded-label series space from a small, fixed product" $
        -- The operator-bounded `rule` aside, this handful is the whole space of label values, never
        -- the unbounded space of package identifiers. An infinite domain has no Universe to
        -- enumerate.
        length allBoundedLabels `shouldSatisfy` (< 64)

    it "renders every bounded label to a non-empty value under a closed key" $
        all
            ( \l ->
                let (key, value) = renderLabel l
                 in key `elem` map labelKeyName allLabelKeys && not (T.null value)
            )
            allBoundedLabels
            `shouldBe` True

    it
        "materialises OpenTelemetry attributes for every bounded label without error"
        (traverse_ (evaluateWHNF . metricAttributes . (: [])) allBoundedLabels :: IO ())

    it "encodes breaker state as a small ordinal gauge value, not a label" $
        map breakerStateCode [Closed, HalfOpen, Open] `shouldBe` [0, 1, 2]

renderSpec :: Spec
renderSpec = describe "renderLabel" $ do
    it "renders the serve decision to admit/deny/unavailable" $ do
        renderLabel (LDecision Admit) `shouldBe` ("decision", "admit")
        renderLabel (LDecision Deny) `shouldBe` ("decision", "deny")
        renderLabel (LDecision Unavailable) `shouldBe` ("decision", "unavailable")

    it "carries the configured rule name as the one operator-bounded label" $
        renderLabel (LRule "min-age") `shouldBe` ("rule", "min-age")

    it "spells each credential provider as the configuration spells its store tag" $ do
        -- The value an operator declares a store under is the value their dashboard filters on.
        renderLabel (LProvider ProviderRegistry) `shouldBe` ("provider", "registry")
        renderLabel (LProvider ProviderCodeArtifact) `shouldBe` ("provider", "codeArtifact")
        renderLabel (LProvider ProviderVerdaccio) `shouldBe` ("provider", "verdaccio")

    it "buckets a denial reason into a bounded class, never the message" $
        renderLabel (LReasonClass ReasonMissingIntegrity) `shouldBe` ("reason_class", "missing_integrity")

    it "renders an advisory sync attempt's outcome, never the artifact it fetched" $ do
        renderLabel (LAdvisorySyncResult AdvisorySwapped) `shouldBe` ("result", "swapped")
        renderLabel (LAdvisorySyncResult AdvisoryFetchFailed) `shouldBe` ("result", "fetch_failed")

    it "renders an advisory compile's verdict and its bounded drop cause" $ do
        renderLabel (LAdvisoryCompileResult CompileCompleted) `shouldBe` ("result", "completed")
        renderLabel (LAdvisoryCompileResult CompileAborted) `shouldBe` ("result", "aborted")
        -- The dropped entry's own name and bytes stay on the log line.
        renderLabel (LAdvisoryDropCause DropOversize) `shouldBe` ("cause", "oversize")
        renderLabel (LAdvisoryDropCause DropMalformed) `shouldBe` ("cause", "malformed")

    it "shares the result key across cache/mirror/credential/advisory outcomes" $ do
        fst (renderLabel (LCacheResult Hit)) `shouldBe` "result"
        fst (renderLabel (LMirrorResult Published)) `shouldBe` "result"
        fst (renderLabel (LCredentialResult Refreshed)) `shouldBe` "result"
        fst (renderLabel (LAdvisorySyncResult AdvisorySwapped)) `shouldBe` "result"
        fst (renderLabel (LAdvisoryCompileResult CompileCompleted)) `shouldBe` "result"

-- Every label constructible from a finite value domain, the operator-bounded `rule` excepted
-- because its domain is configuration. An unbounded label could not be enumerated here.
allBoundedLabels :: [Label]
allBoundedLabels =
    concat
        [ LDecision <$> universe
        , LReasonClass <$> universe
        , LEcosystem <$> ecosystems
        , LMount <$> ecosystems
        , LUpstream <$> universe
        , LStatusClass <$> universe
        , LCacheResult <$> universe
        , LMirrorResult <$> universe
        , LCredentialResult <$> universe
        , LAdvisorySyncResult <$> universe
        , LAdvisoryCompileResult <$> universe
        , LAdvisoryDropCause <$> universe
        , LProvider <$> universe
        , LCause <$> universe
        , LBreakerSource <$> universe
        , LTier <$> universe
        ]
  where
    ecosystems :: [Ecosystem]
    ecosystems = [Npm, PyPI, RubyGems]
