-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Shared utilities for the data-plane handler modules.

Edge authentication, the admission shed with its @Retry-After@ hint, and the serve
rejections the integrity floor produces. The packument, tarball, and publish handlers all
use them, so the three answer an unauthenticated client and a shed request alike.
-}
module Ecluse.Core.Server.Pipeline.Shared (
    -- * Edge authentication
    edgeTokenMatches,
    forwardedCredential,
    unauthorisedMessage,

    -- * Admission shed
    withAdmissionOrShed,
    shedStatus,
    shedMessage,
    hRetryAfter,
    shedRetryAfter,
    retryAfterHeaders,

    -- * Integrity-floor rejections
    integrityMissing,
    integrityBelowFloor,
    trustedIntegrityMissing,
    trustedIntegrityBelowFloor,
) where

import Network.HTTP.Types (Header, HeaderName, ResponseHeaders, Status, status503)
import Network.Wai (Request, requestHeaders)
import UnliftIO (MonadUnliftIO)

import Ecluse.Core.Credential (ClientCredential (credSecret), Secret)
import Ecluse.Core.Registry.Request (credentialRecover)
import Ecluse.Core.Server.Admission (ServeAdmission, withServeAdmission)
import Ecluse.Core.Server.Admission.Weighted (admissionWaitMicros)
import Ecluse.Core.Server.Context (MountBinding (bindingCredential))
import Ecluse.Core.Server.Response (
    RejectReason (BelowIntegrityFloor, MissingIntegrity),
    Rejection (Rejection),
    RetryAfter (RetryAfter),
    ServeDecision (Reject),
 )
import Ecluse.Core.Telemetry.Metrics qualified as Metric
import Ecluse.Core.Telemetry.Record (MetricsPort (mpServeDecision))

hRetryAfter :: HeaderName
hRetryAfter = "Retry-After"

{- | The status a brief-wait admission shed renders on the read and publish paths:
@503 Service Unavailable@, the server-capacity signal, not a @429@ rate limit.
-}
shedStatus :: Status
shedStatus = status503

{- | The @Retry-After@ header a shed @503@ carries: whole seconds derived from
'admissionWaitMicros', so a shed client is never told to return sooner than a queued
request waits in process.
-}
shedRetryAfter :: Header
shedRetryAfter = (hRetryAfter, show (admissionWaitMicros `div` 1_000_000))

-- | The body every read-path shed answers with, so the three handlers say one thing.
shedMessage :: Text
shedMessage = "server is busy; retry later"

{- | Render a serve decision's suggested delay as a @Retry-After@ header. 'Nothing' carries
no header, because a transience with no suggested delay has nothing to promise.
-}
retryAfterHeaders :: Maybe RetryAfter -> ResponseHeaders
retryAfterHeaders = maybe [] (\(RetryAfter secs) -> [(hRetryAfter, show secs)])

{- | Run the gated work under the serve admission bound, counting one unavailable serve decision
when it sheds. @answer@ runs __outside__ the slot, so committing a response never holds one.
-}
withAdmissionOrShed ::
    (MonadUnliftIO m) =>
    MetricsPort ->
    ServeAdmission ->
    -- | The shed answer, built by the caller's own reply factory.
    m received ->
    -- | The gated work, run while holding one admission slot.
    m a ->
    -- | What to answer with the gated work's result.
    (a -> m received) ->
    m received
withAdmissionOrShed metrics admission shed gated answer =
    withServeAdmission metrics admission gated >>= \case
        Just result -> answer result
        Nothing -> do
            liftIO (mpServeDecision metrics Metric.Unavailable)
            shed

{- | The shared edge gate against a configured inbound token. With no token configured the
edge is open, and with one configured the presented credential must match it exactly.
'Secret' equality compares the full bytes with no content-dependent early out, so this gate
leaks no prefix of the configured token through timing.
-}
edgeTokenMatches :: Maybe Secret -> Maybe ClientCredential -> Bool
edgeTokenMatches expected forwarded = case expected of
    Nothing -> True
    Just want -> fmap credSecret forwarded == Just want

{- | The body every handler answers a failed edge gate with. It names no configured token
and no presented one, so a probe learns only that the edge is closed.
-}
unauthorisedMessage :: Text
unauthorisedMessage = "authentication required"

{- The credential a client of this mount presented, recovered through the mount's own
ecosystem presentation ('bindingCredential'). A mount therefore accepts exactly its
ecosystem's presentation, and this pipeline names no scheme of its own. -}
forwardedCredential :: MountBinding -> Request -> Maybe ClientCredential
forwardedCredential mount = credentialRecover (bindingCredential mount) . requestHeaders

{- A __public__ version whose selected artifact carries no integrity digest at all. A
deliberate deny-by-default refusal ('MissingIntegrity', rendered @403@), not a rule denial
and not a retryable outage. The trusted path uses 'trustedIntegrityMissing'. -}
integrityMissing :: ServeDecision
integrityMissing =
    Reject (Rejection MissingIntegrity "this version carries no integrity digest and cannot be served from a public upstream")

{- A __public__ version whose strongest integrity digest is weaker than the configured
minimum algorithm. A deliberate deny-by-default refusal ('BelowIntegrityFloor', rendered
@403@), kept distinct from 'integrityMissing' so the audit trail says which. The trusted
path uses 'trustedIntegrityBelowFloor'. -}
integrityBelowFloor :: ServeDecision
integrityBelowFloor =
    Reject (Rejection BelowIntegrityFloor "this version's integrity digest is weaker than the configured minimum and cannot be served from a public upstream")

{- A __trusted__ (private) version carrying no integrity digest at all. The same
'MissingIntegrity' @403@ as 'integrityMissing', and it surfaces only in the no-survivors
body, when no private or public version is admissible. -}
trustedIntegrityMissing :: ServeDecision
trustedIntegrityMissing =
    Reject (Rejection MissingIntegrity "this private version carries no integrity digest and was not served")

{- A __trusted__ (private) version whose strongest digest is weaker than the configured
trusted minimum, which an operator may loosen below SHA-256. The same
'BelowIntegrityFloor' @403@ as the public refusal, worded for the private path. -}
trustedIntegrityBelowFloor :: ServeDecision
trustedIntegrityBelowFloor =
    Reject (Rejection BelowIntegrityFloor "this private version's integrity digest is weaker than the configured trusted minimum and was not served")
