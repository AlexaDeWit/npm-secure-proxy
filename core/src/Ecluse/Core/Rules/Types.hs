-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Data types for the policy rules engine.

The evaluation model lives in "Ecluse.Core.Rules". This module holds only the
dependency-light types it operates on. Those are the closed built-in rule vocabulary
config selects from, a rule's per-version result, and the overall decision.

A 'Rule' is __evaluation-agnostic data__. It says /what/ a rule is, never /how/ it is
evaluated. How a rule decides is a separate concern that lives in "Ecluse.Core.Rules".
'Ecluse.Core.Rules.evalRule' dispatches over this data, and the engine wraps it in a
'Ecluse.Core.Rules.PreparedRule' to run it.
-}
module Ecluse.Core.Rules.Types (
    -- * The built-in rule vocabulary
    Rule (..),
    DenyIfCveParams (..),
    DenyIfEpssParams (..),
    ruleName,
    readsAdvisories,

    -- * Precedence
    PrecededRule (..),
    defaultPrecedence,
    defaultAllowIfOlderThanPrecedence,
    defaultAllowIfRemediatesCvePrecedence,
    defaultAllowScopePrecedence,
    defaultDenyIfCvePrecedence,
    defaultDenyIfEpssPrecedence,
    defaultAllowByIdentityPrecedence,
    defaultDenyInstallTimeExecutionPrecedence,

    -- * Evaluation
    EvalContext (..),
    mkEvalContext,
    Reason,
    RuleVerdict (..),
    RuleEvaluation (..),
    FailureAlignment (..),
    Decision (..),

    -- * Unavailability
    Transience (..),
    RetryAfter (..),
) where

import Data.Time (NominalDiffTime, UTCTime)
import Ecluse.Core.Cve (DbEtag)
import Ecluse.Core.Fault (RetryAfter (..))
import Ecluse.Core.Package (Scope)

{- | The closed, evaluation-agnostic vocabulary of __built-in__ rules an operator selects
and refines in config. "Ecluse.Core.Rules" prepares each one into the engine's runtime
'Ecluse.Core.Rules.PreparedRule', binding /how/ it is evaluated.

Security boundary: untrusted config only ever yields closed 'Rule' data, never an
arbitrary evaluation closure. A rule whose evaluation performs IO is a plain constructor
here that 'Ecluse.Core.Rules.evalRule' dispatches on.
-}
data Rule
    = -- | Unconditionally allow every package under the given scope.
      AllowScope Scope
    | {- | Allow a version only if it was published at least this long ago.
      Guards against race-to-publish supply-chain attacks where an attacker
      publishes a malicious version and hopes it is consumed before takedown.
      -}
      AllowIfOlderThan NominalDiffTime
    | {- | Deny any package version that runs code at install time: npm install
      scripts, a RubyGems native-extension build, or a PyPI sdist build backend. That
      is a common arbitrary-code-execution vector. Yields no decision otherwise.
      -}
      DenyInstallTimeExecution
    | {- | A hard deny for a specific package or package@version. Evaluated at top
      precedence (above AllowScope) as a post-mirror revocation mechanism.
      -}
      DenyByIdentity Text
    | {- | Allow a specific package or package\@version by exact identity: the allow
      twin of 'DenyByIdentity', and the operator's explicit escape hatch. One use is a
      security fix published under a version string the remediation fast lane's
      exact-match probe cannot see. Top of the allow band, still under every deny
      default.
      -}
      AllowByIdentity Text
    | {- | Fast-track a version a synced advisory names as its __exact fix__, so a
      security patch is admitted immediately rather than waiting out the
      publish-age quarantine. Effectful: it consults the local advisory database
      ('Ecluse.Core.Cve.CveLookup') through the boot-bound
      'Ecluse.Core.Rules.RuleDeps', and abstains when no database is loaded, when
      the version is not an exact fixed bound, or when the version still sits
      inside another advisory's affected range.
      -}
      AllowIfRemediatesCve
    | {- | Deny a version a synced advisory records as __affected__, at or above the
      configured severity threshold. This is the deny direction over the same advisory
      database as 'AllowIfRemediatesCve', with the deliberately __opposite failure
      mode__. Where an unconfirmable remediation merely falls back to the quarantine,
      an unanswerable deny check refuses the version, unless the operator configured it
      fail-open (see 'DenyIfCveParams'). It ships opt-in, not in the default policy:
      enabled before the mirror is warmed, it would deny the historical versions an
      existing build already depends on.
      -}
      DenyIfCve DenyIfCveParams
    | {- | Deny a version a synced advisory records as __affected__ when that advisory's EPSS
      score reaches the configured threshold. The 'DenyIfCve' twin over the same database and
      failure model, gating on the probability of exploitation rather than on the damage. An
      advisory with no EPSS score counts as above every threshold, which on the npm feed is
      most of them: malware advisories carry no CVE alias for the feed to key on. Opt-in.
      -}
      DenyIfEpss DenyIfEpssParams
    deriving stock (Eq, Show)

{- | 'DenyIfCve''s configured behaviour: a separate record rather than fields on
the constructor, so its selectors stay total under the sum (@-Wpartial-fields@).
-}
data DenyIfCveParams = DenyIfCveParams
    { dicMinCvss :: Double
    {- ^ The CVSS base score (0 to 10) at or above which an affecting advisory denies. A
    qualitative label counts as its band's ceiling, and an unscored advisory counts as
    above every threshold ('Ecluse.Core.Cve.scoreAtLeast'). Severity that cannot be
    proven low must not slip a deny gate.
    -}
    , dicOnUnavailable :: FailureAlignment
    {- ^ How the rule resolves when the advisory database cannot answer. 'FailDeny' refuses
    the version and is the shipped default. 'FailNoDecision' skips the rule, and the
    decision's audit reasons record the skip.
    -}
    }
    deriving stock (Eq, Show)

-- | 'DenyIfEpss''s configured behaviour, the EPSS twin of 'DenyIfCveParams'.
data DenyIfEpssParams = DenyIfEpssParams
    { dieMinEpss :: Double
    {- ^ The EPSS probability (0 to 1) at or above which an affecting advisory denies. An
    unscored advisory counts as above every threshold ('Ecluse.Core.Cve.scoreAtLeast'):
    exploitability that cannot be proven low must not slip a deny gate.
    -}
    , dieOnUnavailable :: FailureAlignment
    -- ^ How the rule resolves when the advisory database cannot answer, as 'dicOnUnavailable'.
    }
    deriving stock (Eq, Show)

{- | A stable, human-facing name for a rule: its identity, derived from the data. It is
the boot-order tiebreak and the credited identity in logs and denial messages.
-}

{- | Whether a rule reads the advisory database. A rule set with none never needs one, and a set
with one is worth waiting a bounded while for the first sync before deciding anything.
-}
readsAdvisories :: Rule -> Bool
readsAdvisories = \case
    AllowIfRemediatesCve -> True
    DenyIfCve{} -> True
    DenyIfEpss{} -> True
    AllowScope{} -> False
    AllowIfOlderThan{} -> False
    DenyInstallTimeExecution -> False
    DenyByIdentity{} -> False
    AllowByIdentity{} -> False

ruleName :: Rule -> Text
ruleName = \case
    AllowScope{} -> "AllowScope"
    AllowIfOlderThan{} -> "AllowIfOlderThan"
    DenyInstallTimeExecution -> "DenyInstallTimeExecution"
    DenyByIdentity{} -> "DenyByIdentity"
    AllowByIdentity{} -> "AllowByIdentity"
    AllowIfRemediatesCve -> "AllowIfRemediatesCve"
    DenyIfCve{} -> "DenyIfCve"
    DenyIfEpss{} -> "DenyIfEpss"

{- | A 'Rule' paired with the integer precedence at which it competes, higher first.
'Ecluse.Core.Rules.bootOrder' turns precedence, and at equal precedence the rule name,
into the single total order the engine walks.

Precedence is a field, not an @Ord@ instance: equal precedence is legal, so a derived
'Ord' would be non-antisymmetric.
-}
data PrecededRule = PrecededRule
    { rulePrecedence :: Int
    -- ^ The precedence at which this rule competes. Higher wins.
    , prRule :: Rule
    -- ^ The rule itself.
    }
    deriving stock (Eq, Show)

{- | The default precedence for a rule /type/, used when a policy omits an explicit
precedence.

The ladder climbs most-passive to most-decisive:

@AllowIfOlderThan@ (100) < @AllowIfRemediatesCve@ (150) < @AllowScope@ (200) <
@DenyIfCve@ = @DenyIfEpss@ (225) < @AllowByIdentity@ (250) <
@DenyInstallTimeExecution@ (300) < @DenyByIdentity@ (400)

The two advisory denies are the only ones below an allow, so an operator's exact-identity
pin overrides either. They share a rung, and the boot order breaks that tie by name.
-}
defaultPrecedence :: Rule -> Int
defaultPrecedence = \case
    AllowIfOlderThan{} -> defaultAllowIfOlderThanPrecedence
    AllowIfRemediatesCve -> defaultAllowIfRemediatesCvePrecedence
    AllowScope{} -> defaultAllowScopePrecedence
    DenyIfCve{} -> defaultDenyIfCvePrecedence
    DenyIfEpss{} -> defaultDenyIfEpssPrecedence
    AllowByIdentity{} -> defaultAllowByIdentityPrecedence
    DenyInstallTimeExecution -> defaultDenyInstallTimeExecutionPrecedence
    DenyByIdentity{} -> defaultDenyByIdentityPrecedence

{- | Default precedence of 'AllowIfOlderThan': the lowest band, a passive
quarantine that yields to an explicit allow-list and to every deny.
-}
defaultAllowIfOlderThanPrecedence :: Int
defaultAllowIfOlderThanPrecedence = 100

{- | Default precedence of 'AllowIfRemediatesCve': above the passive age quarantine, so a
security fix is admitted immediately instead of waiting out @min-age@. Below
'AllowScope', so a scoped package an operator already trusts never pays the advisory probe.
-}
defaultAllowIfRemediatesCvePrecedence :: Int
defaultAllowIfRemediatesCvePrecedence = 150

{- | Default precedence of 'AllowScope': above the passive age quarantine, because an
explicit allow-list is a stronger statement than the time gate. Still below every deny.
-}
defaultAllowScopePrecedence :: Int
defaultAllowScopePrecedence = 200

{- | Default precedence of 'DenyIfCve': above the age gate, the remediation lane, and a
scope allow-list, but deliberately below 'AllowByIdentity', so an operator's identity pin
can override an advisory deny. It is the one deny type not strictly above every allow.
-}
defaultDenyIfCvePrecedence :: Int
defaultDenyIfCvePrecedence = 225

{- | Default precedence of 'DenyIfEpss': the same rung as 'DenyIfCve', which reads the
same database and answers to the same identity-pin override. A tie resolves by name.
-}
defaultDenyIfEpssPrecedence :: Int
defaultDenyIfEpssPrecedence = defaultDenyIfCvePrecedence

{- | Default precedence of 'AllowByIdentity': the top of the allow band, above both advisory
denies so an identity pin overrides them, and below 'DenyInstallTimeExecution' and
'DenyByIdentity' so those two keep the last word.
-}
defaultAllowByIdentityPrecedence :: Int
defaultAllowByIdentityPrecedence = 250

{- | Default precedence of 'DenyInstallTimeExecution': the deny band, strictly above
every allow default, so a matching deny overrides any allow out of the box.
-}
defaultDenyInstallTimeExecutionPrecedence :: Int
defaultDenyInstallTimeExecutionPrecedence = 300

{- Default precedence of 'DenyByIdentity': the top precedence, strictly above
every other rule (including explicit allow-lists), to serve as a hard revocation.
-}
defaultDenyByIdentityPrecedence :: Int
defaultDenyByIdentityPrecedence = 400

-- | Ambient information a rule may need that is not part of the package itself.
data EvalContext = EvalContext
    { ctxNow :: UTCTime
    -- ^ The wall-clock "now" for age-based rules.
    , ctxAdvisoryEtag :: Maybe DbEtag
    {- ^ The advisory database 'DbEtag' a denial's audit line names as active at emit, or
    'Nothing' when none is loaded. It is deliberately __not__ the database the decision was
    evaluated against, because a shadow swap may land mid-request.
    -}
    }
    deriving stock (Eq, Show)

{- | Assemble the ambient evaluation context, the one assembly point every consumer shares.

'ctxNow' must come from the mount's injected clock ('Ecluse.Core.Server.Context.pdNow'),
never an ad-hoc 'Data.Time.getCurrentTime', so the age gate cannot drift between
consumers. 'ctxAdvisoryEtag' is audit-only and never enters a rule's decision.
-}
mkEvalContext :: IO UTCTime -> IO (Maybe DbEtag) -> IO EvalContext
mkEvalContext now advisoryEtag = EvalContext <$> now <*> advisoryEtag

-- | A human-facing reason a rule attaches to its result, kept for the audit trail.
type Reason = Text

{- | What a single rule returns for a single package version: a __deterministic__ verdict.
A rule cannot manufacture an 'Unavailable', so the harness takes every verdict at face
value and never retries one.

A verdict is __decisive__ iff it is 'Allow', 'Deny', or @'CannotVet' 'FailDeny' _@. The
engine collects every other reason, in boot order, for the deny-by-default audit trail.
-}
data RuleVerdict
    = -- | This rule admits the package (with a human reason). Decisive.
      Allow Reason
    | -- | This rule blocks the package (with a human reason). Decisive.
      Deny Reason
    | -- | This rule has no opinion. The reason stays for the audit trail. A no-op.
      NoDecision Reason
    | {- | The rule reached the package but cannot vet it: a __deterministic,
      in-process absence__, not a fault. Today that means no advisory database is
      loaded. It carries its own __failure alignment__. A 'FailDeny' rule is decisive
      (fail-closed, → 'Undecidable'), and a 'FailNoDecision' rule is a no-op
      (fail-open). It carries __no__ 'Transience' on purpose: the absence is
      deterministic, so no in-process retry can change it, which is exactly why the
      harness must not route it through the retry\/breaker path.
      -}
      CannotVet FailureAlignment Reason
    deriving stock (Eq, Show)

{- | The outcome the resilience harness produces for one rule. Only the harness constructs
'Unavailable', so the retry and breaker machinery reacts only to a fault the harness itself
observed, never to a verdict a rule returned.

An evaluation is decisive iff it credits a 'Decision': a decisive 'RuleVerdict', or an
@'Unavailable' _ 'FailDeny' _@. The engine gathers every other reason for the audit trail.
-}
data RuleEvaluation
    = -- | The rule returned a verdict, and the harness takes it at face value.
      Decided RuleVerdict
    | {- | The harness could not obtain a verdict: the rule's IO failed, timed out, or
      its source circuit breaker is open. It carries the rule's __failure alignment__
      (a 'FailDeny' evaluation is decisive → 'Undecidable', a 'FailNoDecision' one is a
      no-op) and a 'Transience' recording whether a retry can help. Only the harness
      builds this.
      -}
      Unavailable Transience FailureAlignment Reason
    deriving stock (Eq, Show)

{- | How a rule aligns when it cannot vet a version, or its evaluation faults.

There is deliberately __no @FailAllow@__: a failed or uncomputable check must never
/admit/ unvetted bytes. A rule whose verdict is load-bearing for safety fails closed
('FailDeny'). A remediation or allow-direction rule whose missing signal should not block
availability fails open ('FailNoDecision').
-}
data FailureAlignment
    = -- | __Fail closed.__ An uncomputable result is decisive: the version is not admitted.
      FailDeny
    | -- | __Fail open.__ An uncomputable result is a no-op: the rule simply does not fire.
      FailNoDecision
    deriving stock (Eq, Show)

{- | The overall decision for a package version against a whole rule set. It credits the
deciding rule by __name__ (see 'ruleName'), independent of how the engine evaluates it.
-}
data Decision
    = -- | Admitted by the named rule, with its reason.
      Admitted Text Reason
    | -- | Blocked by the named rule, with its reason.
      Blocked Text Reason
    | {- | No rule was decisive. Deny-by-default; carries every non-decisive reason,
      in boot order, so the denial response can explain what was considered.
      -}
      BlockedByDefault [Reason]
    | {- | Undecidable: a 'FailDeny' rule that could not be computed __won__, so the
      version could not be vetted. Fail-closed, so it is not admitted. A packument
      filters it out like a denial, and a concrete artifact surfaces a @503@\/@500@ by
      the serve error model. The 'Transience' carries whether a retry can help, and the
      'Reason' is the audit reason.
      -}
      Undecidable Transience Reason
    deriving stock (Eq, Show)

{- | Whether an unavailability is expected to resolve on its own. The serve status mapping
turns on this distinction alone: 'WillResolve' is a @503@, 'WontResolve' a @500@.

The resilience harness treats an upstream outage, rate limit, timeout, or open breaker as
transient, and an internal or parse fault as not.
-}
data Transience
    = {- | Transient: a retry may succeed (an advisory source briefly down, a
      timeout, an open circuit breaker). The optional 'RetryAfter' is the delay to
      suggest to the client.
      -}
      WillResolve (Maybe RetryAfter)
    | {- | Not expected to self-heal (an internal or parse error). Retrying cannot
      help, so the request is a @500@, never a @503@.
      -}
      WontResolve
    deriving stock (Eq, Show)
