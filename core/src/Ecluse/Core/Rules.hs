-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The policy engine denies by default and decides in boot order.
Effectful evaluation may overlap, but precedence governs the result.
-}
module Ecluse.Core.Rules (
    -- * The boot-bound rule capabilities
    RuleDeps (..),

    -- * The built-in rule dispatch
    evalRule,

    -- * The engine's prepared rule
    PreparedRule (..),
    Resilience (..),
    prepare,

    -- * Boot-time ordering
    bootOrder,
    renderBootOrder,

    -- * Evaluation
    evalRules,
    renderDecision,
    renderDuration,
    cveIdsInReason,

    -- * The resilience harness
    runEffectfulRule,
    FaultReporter (..),
) where

import Data.Text qualified as T
import Data.Text.Short qualified as TS
import Data.Time (NominalDiffTime, diffUTCTime, getCurrentTime, nominalDiffTimeToSeconds)
import UnliftIO (tryAny)
import UnliftIO.Async (Async, async, cancel, uninterruptibleCancel, wait)
import UnliftIO.Exception (bracket)

import Ecluse.Core.Breaker (BreakerReporter (..))
import Ecluse.Core.Cve (AdvisoryRange (..), CveLookup (..), DbEtag, insideAffectedRange, scoreAtLeast)
import Ecluse.Core.Ecosystem (Ecosystem)
import Ecluse.Core.Osv.Types (UpperBound (FixedBefore))
import Ecluse.Core.Package
import Ecluse.Core.Rules.Effectful (
    FaultReporter (..),
    Resilience (..),
    defaultEffectfulConfig,
    newBreaker,
    runResilient,
 )
import Ecluse.Core.Rules.Types
import Ecluse.Core.Text (displayExceptionT)
import Ecluse.Core.Version (renderVersion)

-- | Pin one advisory generation for an evaluation, or supply 'Nothing' before the first sync.
data RuleDeps = RuleDeps
    { rdWithCveLookup :: forall a. (Maybe CveLookup -> IO a) -> IO a
    -- ^ Bracketed access to the current advisory database view, if one is loaded.
    , rdCurrentAdvisoryEtag :: IO (Maybe DbEtag)
    {- ^ A non-pinning read of the active advisory database's 'DbEtag', or 'Nothing' when none
    is loaded. It holds no generation open, so it never delays a shadow-swap.
    -}
    , rdBreakerReporter :: BreakerReporter
    {- ^ The observer that effectful rules report their breaker transitions to, as
    @ecluse.rule.breaker.state@. 'Ecluse.Core.Breaker.noBreakerReporter' when unobserved.
    -}
    , rdFaultReporter :: FaultReporter
    -- ^ Reports exhausted faults to the operator log without exposing them to clients.
    }

-- | Lookup faults escape to the resilience policy attached by 'prepare'.
evalRule :: RuleDeps -> EvalContext -> Rule -> PackageDetails -> IO RuleVerdict
evalRule _ _ (AllowScope scope) pd =
    pure $ case pkgNamespace (pkgName pd) of
        Just s
            | s == scope ->
                Allow ("scope " <> renderScope scope <> " is allow-listed")
        _ ->
            NoDecision ("scope is not the allow-listed " <> renderScope scope)
evalRule _ ctx (AllowIfOlderThan minAge) pd =
    pure $ case pkgPublishedAt pd of
        Nothing -> NoDecision "publish time is unknown"
        Just publishedAt ->
            let age = diffUTCTime (ctxNow ctx) publishedAt
             in if age >= minAge
                    then
                        Allow
                            ( "published "
                                <> renderDuration age
                                <> " ago (at least "
                                <> renderDuration minAge
                                <> " old)"
                            )
                    else
                        NoDecision
                            ( "published only "
                                <> renderDuration age
                                <> " ago, minimum age is "
                                <> renderDuration minAge
                            )
evalRule _ _ DenyInstallTimeExecution pd =
    pure $ case pkgInstallCode pd of
        RunsCodeOnInstall how -> Deny ("runs code on install: " <> how)
        NoCodeOnInstall -> NoDecision "no install-time code execution"
        CodeExecUnknown -> NoDecision "install-time code execution not yet determined"
evalRule _ _ (DenyByIdentity ident) pd =
    pure $
        if matchesIdentity ident pd
            then Deny ("identity " <> ident <> " is revoked by operator")
            else NoDecision ("identity is not the revoked " <> ident)
evalRule _ _ (AllowByIdentity ident) pd =
    pure $
        if matchesIdentity ident pd
            then Allow ("identity " <> ident <> " is allow-listed by operator")
            else NoDecision ("identity is not the allow-listed " <> ident)
evalRule deps _ AllowIfRemediatesCve pd =
    rdWithCveLookup deps $ \case
        Nothing -> pure (NoDecision "no advisory database is loaded")
        Just cve -> remediationVerdict cve pd
evalRule deps _ (DenyIfCve params) pd =
    rdWithCveLookup deps $ \case
        Nothing -> pure (noAdvisoryDbVerdict "DenyIfCve" (dicOnUnavailable params))
        Just cve -> advisoryDenyVerdict "CVSS" (dicMinCvss params) arSeverity cve pd
evalRule deps _ (DenyIfEpss params) pd =
    rdWithCveLookup deps $ \case
        Nothing -> pure (noAdvisoryDbVerdict "DenyIfEpss" (dieOnUnavailable params))
        Just cve -> advisoryDenyVerdict "EPSS" (dieMinEpss params) arEpss cve pd

{- The verdict when no advisory database is loaded. It is a 'CannotVet' verdict and not a
fault, because no in-process retry could load one, so the harness never retries it. -}
noAdvisoryDbVerdict :: Text -> FailureAlignment -> RuleVerdict
noAdvisoryDbVerdict rule alignment = CannotVet alignment (rule <> ": no advisory database loaded")

{- The shape both scored deny rules share: deny when an affecting advisory's score reaches the
threshold, naming the deciders. An unscored advisory clears every threshold ('scoreAtLeast'). -}
advisoryDenyVerdict :: Text -> Double -> (AdvisoryRange -> Maybe Double) -> CveLookup -> PackageDetails -> IO RuleVerdict
advisoryDenyVerdict metric threshold scoreOf cve pd = do
    ranges <- cveAdvisoriesFor cve name
    let blocking =
            ordNub
                [ arCveId ar
                | ar <- ranges
                , insideAffectedRange eco version ar
                , scoreAtLeast threshold (scoreOf ar)
                ]
    pure $ case blocking of
        [] -> NoDecision ("no advisory at or above the " <> metric <> " threshold affects this version")
        ids -> Deny ("affected by " <> T.intercalate ", " ids <> " (" <> metric <> " >= " <> show threshold <> ")")
  where
    eco = pkgEcosystem (pkgName pd)
    name = TS.toText (pkgCanonical (pkgName pd))
    version = renderVersion (pkgVersion pd)

-- | Read the advisory identifiers from a scored denial reason, or return none.
cveIdsInReason :: Text -> [Text]
cveIdsInReason message
    | T.null afterThreshold = []
    | otherwise = filter (not . T.null) (map T.strip (T.splitOn ", " ids))
  where
    -- 'stripPrefix' drops the marker without an O(n) 'Data.Text.length' on it (STAN-0208).
    -- An absent marker leaves the body empty, so the guard yields @[]@.
    (_, afterAffected) = T.breakOn "affected by " message
    body = fromMaybe "" (T.stripPrefix "affected by " afterAffected)
    (ids, afterThreshold) = T.breakOn " (" body

-- The CVE rule's verdict against a loaded advisory database.
remediationVerdict :: CveLookup -> PackageDetails -> IO RuleVerdict
remediationVerdict cve pd = do
    fixes <- cveRemediationProbe cve name version
    if not fixes
        then pure (NoDecision "no advisory names this version as its fix")
        else do
            -- The probe hit, so the version is some advisory's exact fixed bound.
            ranges <- cveAdvisoriesFor cve name
            pure (classifyRanges (pkgEcosystem (pkgName pd)) version ranges)
  where
    name = TS.toText (pkgCanonical (pkgName pd))
    version = renderVersion (pkgVersion pd)

-- A version still inside any advisory's affected range, an unfixed one included, must not
-- fast-track. Otherwise credit the advisories that name it as their exact fixed bound.
classifyRanges :: Ecosystem -> Text -> [AdvisoryRange] -> RuleVerdict
classifyRanges eco version ranges =
    case (remediated, stillOpen) of
        (_, _ : _) ->
            NoDecision
                ("fixes " <> T.intercalate ", " remediated <> " but is still affected by " <> T.intercalate ", " stillOpen)
        ([], []) ->
            -- Unreachable under one acquisition (the probe and the
            -- fetch see the same artifact), kept total.
            NoDecision "no advisory names this version as its fix"
        (ids, []) -> Allow ("remediates " <> T.intercalate ", " ids)
  where
    remediated = ordNub [arCveId ar | ar <- ranges, arUpperBound ar == FixedBefore version]
    stillOpen = ordNub [arCveId ar | ar <- ranges, insideAffectedRange eco version ar]

-- The one identity test the by-identity twins share: the exact rendered package
-- name, or the exact package@version.
matchesIdentity :: Text -> PackageDetails -> Bool
matchesIdentity ident pd =
    let pkgStr = renderPackageName (pkgName pd)
        pkgAtVer = pkgStr <> "@" <> renderVersion (pkgVersion pd)
     in ident == pkgStr || ident == pkgAtVer

-- | Config obtains evaluators only through 'prepare', never from arbitrary code.
data PreparedRule = PreparedRule
    { prepName :: Text
    {- ^ The stable, human-facing name. It is the boot-order tiebreak and the credited
    identity.
    -}
    , prepPrecedence :: Int
    -- ^ The precedence at which this rule competes. Higher wins in the boot order.
    , prepResilience :: Maybe Resilience
    -- ^ The resilience policy, or 'Nothing' for a rule run directly.
    , prepEval :: EvalContext -> PackageDetails -> IO RuleVerdict
    {- ^ The rule's raw verdict for one version. For a resilient rule it may do IO that
    fails or hangs, and 'runEffectfulRule' wraps it.
    -}
    }

-- | Allocate each effectful rule's breaker once. Unconfirmed remediation claims abstain.
prepare :: RuleDeps -> [PrecededRule] -> IO [PreparedRule]
prepare deps = traverse (prepareRule deps)

prepareRule :: RuleDeps -> PrecededRule -> IO PreparedRule
prepareRule deps (PrecededRule prec rule) = do
    resilience <- resilienceFor deps rule
    pure
        PreparedRule
            { prepName = ruleName rule
            , prepPrecedence = prec
            , prepResilience = resilience
            , prepEval = \ctx -> evalRule deps ctx rule
            }

-- The resilience a rule needs. The effectful CVE rule carries the fail-open policy,
-- allocating its per-source breaker. The pure rules carry none.
resilienceFor :: RuleDeps -> Rule -> IO (Maybe Resilience)
resilienceFor deps = \case
    AllowIfRemediatesCve -> effectful FailNoDecision
    -- A deny rule aligns per its config. The same alignment governs a lookup that throws or
    -- times out (here) and a database that is not loaded ('noAdvisoryDbVerdict').
    DenyIfCve params -> effectful (dicOnUnavailable params)
    DenyIfEpss params -> effectful (dieOnUnavailable params)
    _ -> pure Nothing
  where
    effectful alignment = do
        breaker <- newBreaker
        pure $
            Just
                Resilience
                    { resConfig = defaultEffectfulConfig
                    , resAlignment = alignment
                    , resBreaker = breaker
                    , resBreakerReporter = rdBreakerReporter deps
                    , resFaultReporter = rdFaultReporter deps
                    , resClock = getCurrentTime
                    }

-- | Sort by descending precedence, then ascending rule name, independently of configuration order.
bootOrder :: [PreparedRule] -> [PreparedRule]
bootOrder = sortOn (\r -> bootKey (prepPrecedence r) (prepName r))

-- Both 'bootOrder' and the engine order through this one key, so the tiebreak lives in
-- exactly one place.
bootKey :: Int -> Text -> (Down Int, Text)
bootKey prec name = (Down prec, name)

{- | Render the boot order as one line per rule, in evaluation order, so an operator sees
at boot how their policy will resolve.
-}
renderBootOrder :: [PreparedRule] -> [Text]
renderBootOrder rules = zipWith line [1 :: Int ..] (bootOrder rules)
  where
    line i r =
        "rule "
            <> show i
            <> ": "
            <> prepName r
            <> " (precedence "
            <> show (prepPrecedence r)
            <> ")"

-- | Decide in boot order despite concurrent lookups. Unexpected direct-rule faults refuse admission.
evalRules :: EvalContext -> [PreparedRule] -> PackageDetails -> IO Decision
evalRules ctx rules pd = step (bootOrder rules) []
  where
    -- 'reasons' accumulates non-decisive reasons in reverse boot order. The final
    -- deny-by-default list reverses them back into boot order.
    step :: [PreparedRule] -> [Reason] -> IO Decision
    step [] reasons = pure (BlockedByDefault (reverse reasons))
    step (r : rs) reasons
        | isNothing (prepResilience r) = do
            -- A direct rule is zero-cost, so run it in place. Reaching it means every
            -- earlier rule was non-decisive, so it moots no speculated IO.
            evaluated <- tryAny (prepEval r ctx pd)
            case evaluated of
                Left escape ->
                    -- A direct-rule exception breaks its contract and must refuse admission.
                    pure (Undecidable (WillResolve Nothing) (prepName r <> ": the rule threw: " <> displayExceptionT escape))
                Right verdict -> do
                    let res = Decided verdict
                    case decisive (prepName r) res of
                        Just d -> pure d
                        Nothing -> step rs (reasonOf res : reasons)
        | otherwise =
            -- Stopping the block at the next direct rule keeps the "no mooted IO" guarantee: that
            -- rule runs, and may decide, before the engine launches any resilient rule beyond it.
            let (block, rest) = span (isJust . prepResilience) (r : rs)
             in evalBlock ctx pd block >>= \case
                    Left d -> pure d
                    Right blockReasons -> step rest (reverse blockReasons <> reasons)

-- Launch a contiguous resilient block concurrently, then await in boot order. 'Left' is
-- the earliest decisive winner, 'Right' the block's non-decisive reasons in boot order.
evalBlock :: EvalContext -> PackageDetails -> [PreparedRule] -> IO (Either Decision [Reason])
evalBlock ctx pd block =
    bracket
        (traverse (\r -> async (runEffectfulRule ctx r pd)) block)
        (traverse_ uninterruptibleCancel)
        (\asyncs -> awaitInOrder (zip block asyncs) [])

-- Await a launched block's evaluations in boot order. A decisive winner cancels
-- every strictly-later one.
awaitInOrder :: [(PreparedRule, Async RuleEvaluation)] -> [Reason] -> IO (Either Decision [Reason])
awaitInOrder [] reasons = pure (Right (reverse reasons))
awaitInOrder ((r, a) : rest) reasons = do
    res <- wait a
    case decisive (prepName r) res of
        Just d -> do
            traverse_ (cancel . snd) rest
            pure (Left d)
        Nothing -> awaitInOrder rest (reasonOf res : reasons)

-- 'CannotVet' has no transience evidence, so it produces a plain retryable refusal.
decisive :: Text -> RuleEvaluation -> Maybe Decision
decisive name = \case
    Decided (Allow reason) -> Just (Admitted name reason)
    Decided (Deny reason) -> Just (Blocked name reason)
    Decided (NoDecision _) -> Nothing
    Decided (CannotVet FailDeny reason) -> Just (Undecidable (WillResolve Nothing) reason)
    Decided (CannotVet FailNoDecision _) -> Nothing
    Unavailable transience FailDeny reason -> Just (Undecidable transience reason)
    Unavailable _ FailNoDecision _ -> Nothing

-- The audit reason carried by any result, gathered for the deny-by-default trail.
reasonOf :: RuleEvaluation -> Reason
reasonOf (Unavailable _ _ reason) = reason
reasonOf (Decided verdict) = case verdict of
    Allow reason -> reason
    Deny reason -> reason
    NoDecision reason -> reason
    CannotVet _ reason -> reason

-- | Apply resilience to effectful rules. Direct-rule exceptions remain the caller's responsibility.
runEffectfulRule :: EvalContext -> PreparedRule -> PackageDetails -> IO RuleEvaluation
runEffectfulRule ctx rule pd = case prepResilience rule of
    Nothing -> Decided <$> prepEval rule ctx pd
    Just res -> runResilient res (prepName rule) (prepEval rule ctx) pd

{- | A human-readable summary of a decision, suitable for logs and the denial
response body.
-}
renderDecision :: PackageDetails -> Decision -> Text
renderDecision pd decision =
    let subject = renderPackageName (pkgName pd) <> "@" <> renderVersion (pkgVersion pd)
     in case decision of
            Admitted name reason ->
                subject <> " was approved by " <> name <> ": " <> reason
            Blocked name reason ->
                subject <> " was denied by " <> name <> ": " <> reason
            BlockedByDefault reasons ->
                subject
                    <> " was denied (no rule allowed it)"
                    <> if null reasons
                        then ""
                        else ": " <> T.intercalate "; " reasons
            Undecidable _ reason ->
                subject <> " could not be evaluated: " <> reason

-- | Keep two non-zero units to distinguish near-threshold durations. Negative values render as zero.
renderDuration :: NominalDiffTime -> Text
renderDuration d = case take 2 (durationComponents secs) of
    [] -> "0 seconds"
    parts -> T.unwords (map renderDurationPart parts)
  where
    secs = max 0 (round (nominalDiffTimeToSeconds d)) :: Integer

durationLadder :: [(Text, Integer)]
durationLadder =
    [ ("day", 86400)
    , ("hour", 3600)
    , ("minute", 60)
    , ("second", 1)
    ]

durationComponents :: Integer -> [(Text, Integer)]
durationComponents = go durationLadder
  where
    go [] _ = []
    go ((unit, size) : rest) r =
        let (q, r') = r `divMod` size
         in [(unit, q) | q > 0] <> go rest r'

-- Render one @(unit, count)@ component, pluralising the unit (@1 minute@, @30 seconds@).
renderDurationPart :: (Text, Integer) -> Text
renderDurationPart (unit, n) = show n <> " " <> unit <> (if n == 1 then "" else "s")
