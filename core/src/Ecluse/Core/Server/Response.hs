-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The serve-outcome model, the per-outcome status mapping, and the agnostic
shape of an error body.

Every client-facing reply is the rendering of one __serve outcome__: admit the
request, or reject it. An error therefore maps to the status a client can act on
rather than a generic 403\/500. The model and the per-outcome status mapping live
here. The WAI layer that turns an 'ArtifactStatus' into an actual response and
streams the body is separate (see @docs\/architecture\/web-layer.md@).

This module decides the HTTP /status/ of a refusal but holds __no body shape of
its own__. The bytes a client reads an error from are an ecosystem's: npm's
@{"error": …}@ JSON, a different surface for PyPI. The ecosystem's route-scoped
'Ecluse.Core.Server.Contract.ResponseContract' supplies the response constructor and
codec, and the agnostic pipeline selects it through injected reply factories.
'appendHelp' is the ecosystem-neutral operation those factories reuse: it joins the
operator help message onto a denial.

== The outcome model

A 'ServeDecision' is 'Admit' or 'Reject' with a 'Rejection' carrying a
'RejectReason'. A rejection is either __by policy__ (a rule denied the version,
including deny-by-default) or __unavailable__. An unavailable rejection could not be
decided, and carries its 'Transience': whether the evaluator believes the condition
will self-heal. The whole verdict pipeline ("Ecluse.Core.Rules") feeds this. A rules
'Decision' projects to a 'ServeDecision' via 'serveDecisionOf'.

== Status follows the cause

For a __concrete artifact__ (one specific version) the outcome renders to a
single 'ArtifactStatus'. The load-bearing rule is __503 only when we believe it
will resolve__. A transient upstream or advisory condition invites a retry. A
permanent or internal inability to decide ('WontResolve') is a @500@, because
retrying it cannot help and we should not invite it. A policy rejection is a
@403@ whose body the route's response contract shapes. A __packument__ request has
no single status: the pipeline filters its versions and chooses the status over the
surviving set. This module therefore maps __per outcome__, not per request.

'appendHelp' appends the operator help message, when configured, to every denial, so
clients are told where to ask. How the joined text is then wrapped into bytes is the
route contract's concern.
-}
module Ecluse.Core.Server.Response (
    -- * Serve outcomes
    ServeDecision (..),
    Rejection (..),
    RejectReason (..),
    Transience (..),
    RetryAfter (..),
    RuleName (..),
    rejectUnavailable,
    serveDecisionOf,

    -- * Concrete-artifact status
    ArtifactStatus (..),
    artifactStatus,
    artifactHttpStatus,

    -- * Packument status (over the merged survivor set)
    PackumentStatus (..),
    packumentStatus,
    longestRetry,

    -- * Denial help text
    HelpMessage,
    mkHelpMessage,
    appendHelp,

    -- * A refusal's two parts
    Refusal (..),
    mkRefusal,
    renderRefusal,
) where

import Data.Semigroup (Max (Max, getMax))
import Data.Text qualified as T
import Network.HTTP.Types (Status, status200, status403, status404, status500, status503)

import Ecluse.Core.Package (PackageDetails)
import Ecluse.Core.Rules (renderDecision)
import Ecluse.Core.Rules.Types (
    Decision (Admitted, Blocked, BlockedByDefault, Undecidable),
    RetryAfter (..),
    Transience (..),
 )

{- | The outcome of deciding a request: serve it, or refuse it with a reason. Every client-facing
reply renders one of these.
-}
data ServeDecision
    = -- | Serve the request (the @200@ stream for an artifact).
      Admit
    | -- | Refuse the request, with the reason and a client-facing message.
      Reject Rejection
    deriving stock (Eq, Show)

-- | A refusal: /why/ the request was refused, and an intuitive message for the client.
data Rejection = Rejection
    { rejectionReason :: RejectReason
    -- ^ The cause of the refusal, which decides the status.
    , rejectionMessage :: Text
    -- ^ The client-facing explanation (the rendered decision, or the cause).
    }
    deriving stock (Eq, Show)

{- | Why a request was refused. A policy refusal is a deliberate verdict and is final for this
request. An unavailability is an /inability to decide/, and its 'Transience' separates a
retryable @503@ from a terminal @500@.
-}
data RejectReason
    = {- | A rule denied the version (including deny-by-default). The 'RuleName'
      is the rule that decided, for the audit trail and the denial body.
      -}
      ByPolicy RuleName
    | {- | The version could not be decided. An effectful rule the evaluator needed
      could not be consulted (advisory source down, timeout). This is
      __fail-closed__: a never-vetted version is not admitted just because the
      scanner is unreachable. The 'Transience' says whether a retry can help.
      -}
      Unavailable Transience
    | {- | The version's selected artifact carries __no integrity digest of any
      kind__ (neither an SRI nor a legacy shasum), so its bytes cannot be tied to
      a tamper-evident fingerprint. Nothing can detect a divergence, so such a
      version is inadmissible from an /untrusted/ (public) upstream and admission
      refuses it outright. This is a deliberate, deny-by-default __admission
      policy__, not a rule decision and not a retryable inability: it maps to a
      @403@. The trusted private upstream is exempt, and this reason never arises
      on that path.
      -}
      MissingIntegrity
    | {- | The version's selected artifact carries an integrity digest, but its
      strongest one is __weaker than the configured minimum algorithm__ (e.g. a
      legacy SHA-1 shasum only, under the default SHA-256 floor). A collision-broken
      digest cannot tie the bytes to a tamper-evident fingerprint, so the version is
      inadmissible from an /untrusted/ (public) upstream. This reason is distinct
      from 'MissingIntegrity' (which has no digest at all), so the audit trail says
      which. It is a deny-by-default __admission policy__ that maps to a @403@. The
      trusted private upstream is exempt, and this reason never arises on that path.
      -}
      BelowIntegrityFloor
    | {- | A responding upstream returned an __invalid response__ for the requested
      package. Its packument self-reported a name for a /different/ package, so that
      origin is untrusted for this request and contributes no document to the merge.
      It is a /gateway/ fault, not a policy verdict and not a retryable inability.
      When no origin yields a valid packument and a responding one was invalid this
      way, the packument request maps to a @502@. A genuine absence (no such package
      at all) is distinct, and is not refused this way. This reason arises on the
      packument path only, because the artifact path never validates a packument
      name.
      -}
      UpstreamInvalid
    deriving stock (Eq, Show)

{- | The name of the rule that decided a refusal, carried for the audit trail and the denial
body.
-}
newtype RuleName = RuleName Text
    deriving stock (Eq, Ord, Show)

{- | Project a rules 'Decision' (see "Ecluse.Core.Rules") into a serve outcome. Pure and total.
An 'Undecidable' decision rejects as 'Unavailable', which is __fail-closed__: a version no rule
could vet is never admitted.
-}
serveDecisionOf :: PackageDetails -> Decision -> ServeDecision
serveDecisionOf pd decision = case decision of
    Admitted{} -> Admit
    Blocked name _ -> Reject (rejectAs (ByPolicy (RuleName name)))
    BlockedByDefault{} -> Reject (rejectAs (ByPolicy (RuleName "BlockedByDefault")))
    Undecidable transience _ -> rejectUnavailable transience (renderDecision pd decision)
  where
    rejectAs :: RejectReason -> Rejection
    rejectAs reason = Rejection reason (renderDecision pd decision)

{- | Refuse a request that could not be decided. The 'Transience' it carries is what
'artifactStatus' renders as a @503@ or a @500@, so a caller states that rather than a status.
-}
rejectUnavailable :: Transience -> Text -> ServeDecision
rejectUnavailable transience message = Reject (Rejection (Unavailable transience) message)

{- | The HTTP status a __concrete-artifact__ request renders to. A packument request has no
single status, because the pipeline filters its versions and chooses one over the survivors, so
'PackumentStatus' models that case.
-}
data ArtifactStatus
    = -- | @200@: admitted, so the proxy streams the artifact.
      Ok
    | -- | @403@: refused by policy. The route's response contract shapes the body.
      Forbidden
    | {- | @503@: a transient inability to decide. The 'RetryAfter', if known,
      becomes the @Retry-After@ header.
      -}
      Unavailable' (Maybe RetryAfter)
    | -- | @500@: a permanent or internal inability to decide. Not retryable.
      ServerError
    | -- | @404@: the upstream did not have the artifact (forwarded miss).
      NotFound
    deriving stock (Eq, Show)

{- | Map a serve outcome to its concrete-artifact status. Pure and total. The load-bearing rule
is __@503@ only when we believe it will resolve__, so a 'WontResolve' unavailability is a @500@.
A @404@ upstream miss is not a serve decision, so this function never produces one.
-}
artifactStatus :: ServeDecision -> ArtifactStatus
artifactStatus = \case
    Admit -> Ok
    Reject rej -> case rejectionReason rej of
        ByPolicy{} -> Forbidden
        MissingIntegrity -> Forbidden
        BelowIntegrityFloor -> Forbidden
        Unavailable (WillResolve retryAfter) -> Unavailable' retryAfter
        Unavailable WontResolve -> ServerError
        -- The artifact path never validates a packument name, so this cause does not arise here. A
        -- misbehaving upstream on this path is an internal inability to serve.
        UpstreamInvalid -> ServerError

-- | The HTTP status an 'ArtifactStatus' renders as. Pure and total.
artifactHttpStatus :: ArtifactStatus -> Status
artifactHttpStatus = \case
    Ok -> status200
    Forbidden -> status403
    Unavailable'{} -> status503
    ServerError -> status500
    NotFound -> status404

{- | The HTTP status a __packument__ request renders to, chosen over the merged survivor set
(see 'packumentStatus'). There is no @404@: a packument whose versions were all withheld is not
a miss, because the package exists, and a genuine absence is decided before the merge.
-}
data PackumentStatus
    = -- | @200@: at least one version survived, so the proxy serves the merged, filtered packument.
      PackumentOk
    | {- | @403@: no version survived and every exclusion was a policy denial. The
      response body collects the denial reasons.
      -}
      PackumentForbidden
    | {- | @503@: no version survived, but at least one exclusion may self-heal (a
      transient rule outcome, or a needed upstream that was unavailable). A retry may
      yet yield survivors. The 'RetryAfter', if any was suggested, becomes the
      @Retry-After@ header.
      -}
      PackumentUnavailable (Maybe RetryAfter)
    | {- | @502@: no version survived, because a responding upstream returned an
      __invalid response__ and no origin yielded a valid packument. The invalid
      response is a packument self-reporting a different package's name. A gateway
      fault, distinct from a genuine absence (no such package) and from a retryable
      outage. The upstream answered, but with a document for the wrong package.
      -}
      PackumentBadGateway
    | {- | @500@: no version survived, no exclusion is retryable, and at least one is
      a permanent or internal inability to decide. Retrying cannot help.
      -}
      PackumentServerError
    deriving stock (Eq, Show)

{- | Choose a packument's status from the per-version serve outcomes, including any 'Reject' a
needed-but-unavailable upstream contributes. Pure and total. Any 'Admit' serves the document.
With no survivor the status follows the __most recoverable cause__ among the exclusions, so it
invites a retry exactly when a retry might yield survivors:

* 'Unavailable' 'WillResolve' → @503@, suggesting the longest 'RetryAfter' asked for, so every
transient cause has likely cleared by then.
* Otherwise 'UpstreamInvalid' → @502@, a concrete gateway fault. It ranks below @503@, because a
transient origin may yet return a valid document.
* Otherwise 'Unavailable' 'WontResolve' → @500@, because a retry cannot help.
* Otherwise every exclusion is deny-by-default, __the empty input included__ → @403@.
-}
packumentStatus :: [ServeDecision] -> PackumentStatus
packumentStatus decisions
    | tallyAdmit tally = PackumentOk
    | not (null willResolveDelays) = PackumentUnavailable (longestRetry willResolveDelays)
    | tallyUpstreamInvalid tally = PackumentBadGateway
    | tallyWontResolve tally = PackumentServerError
    | otherwise = PackumentForbidden
  where
    -- One strict pass over the outcomes collects every signal the guards weigh, so the
    -- all-denied path walks the exclusions once, not once per guard.
    tally :: PackumentTally
    tally = foldl' weigh (PackumentTally False [] False False) decisions

    willResolveDelays :: [Maybe RetryAfter]
    willResolveDelays = tallyWillResolveDelays tally

    weigh :: PackumentTally -> ServeDecision -> PackumentTally
    weigh acc = \case
        Admit -> acc{tallyAdmit = True}
        Reject rej -> case rejectionReason rej of
            Unavailable (WillResolve delay) ->
                acc{tallyWillResolveDelays = delay : tallyWillResolveDelays acc}
            UpstreamInvalid -> acc{tallyUpstreamInvalid = True}
            Unavailable WontResolve -> acc{tallyWontResolve = True}
            -- A deny-by-default cause (policy or admission refusal) leaves no signal
            -- of its own. An empty tally is exactly the @403@ floor.
            ByPolicy{} -> acc
            MissingIntegrity -> acc
            BelowIntegrityFloor -> acc

{- | The signals 'packumentStatus' weighs over the per-version serve outcomes, accumulated in a
single pass. The fields are strict ('StrictData'), so the tally does not thunk across a large
survivor set.
-}
data PackumentTally = PackumentTally
    { tallyAdmit :: Bool
    -- ^ At least one 'Admit' was seen, so the merged document has a survivor.
    , tallyWillResolveDelays :: [Maybe RetryAfter]
    -- ^ The suggested delay of every transient ('WillResolve') exclusion.
    , tallyUpstreamInvalid :: Bool
    -- ^ A responding upstream returned a packument naming a different package.
    , tallyWontResolve :: Bool
    -- ^ An exclusion was a permanent ('WontResolve') inability to decide.
    }

{- | The longest suggested 'RetryAfter' among transient causes, or 'Nothing' when
none of them suggested a delay.
-}
longestRetry :: [Maybe RetryAfter] -> Maybe RetryAfter
longestRetry = fmap getMax . foldMap (fmap Max)

{- | An operator-configured message appended to every denial, typically where to ask for help.
Stored trimmed, so an all-blank value contributes nothing.
-}
newtype HelpMessage = HelpMessage Text
    deriving stock (Eq, Show)

-- | Build a 'HelpMessage', trimming surrounding whitespace.
mkHelpMessage :: Text -> HelpMessage
mkHelpMessage = HelpMessage . T.strip

{- | Append a non-blank operator 'HelpMessage' to a denial message, separated by a single space.
A blank or absent help message contributes nothing.
-}
appendHelp :: Maybe HelpMessage -> Text -> Text
appendHelp help = renderRefusal . mkRefusal help

{- | A refusal's text in its two parts, so an ecosystem renders whichever its own denial surface
carries and the help message is not dropped for one with no envelope to hold both.
-}
data Refusal = Refusal
    { refusalReason :: Text
    -- ^ Why Écluse refused, in its own words. Always present.
    , refusalHelp :: Maybe Text
    -- ^ The operator's help message, absent when none is configured or it is blank.
    }
    deriving stock (Eq, Show)

-- | Pair a decided reason with the mount's configured help message, if it has a non-blank one.
mkRefusal :: Maybe HelpMessage -> Text -> Refusal
mkRefusal help message = Refusal message (nonBlankHelp =<< help)
  where
    nonBlankHelp (HelpMessage h) = if T.null h then Nothing else Just h

-- | The refusal as one line: the reason, with the help message appended after a single space.
renderRefusal :: Refusal -> Text
renderRefusal (Refusal reason help) = maybe reason ((T.strip reason <> " ") <>) help
