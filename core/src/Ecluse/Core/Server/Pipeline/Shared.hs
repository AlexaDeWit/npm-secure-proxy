-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

-- | Authentication, admission shedding, and refusals shared by the data-plane handlers.
module Ecluse.Core.Server.Pipeline.Shared (
    -- * Edge authentication
    edgeTokenMatches,
    forwardedCredential,
    unauthorisedMessage,
    privateAuthorisationRefusal,

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
    HelpMessage,
    Refusal,
    RejectReason (BelowIntegrityFloor, MissingIntegrity),
    Rejection (Rejection),
    RetryAfter (RetryAfter),
    ServeDecision (Reject),
    mkRefusal,
 )
import Ecluse.Core.Telemetry.Metrics qualified as Metric
import Ecluse.Core.Telemetry.Record (MetricsPort (mpServeDecision))

-- | The fixed refusal shared by private metadata and artifact access failures.
privateAuthorisationRefusal :: Maybe HelpMessage -> Refusal
privateAuthorisationRefusal help = mkRefusal help "the private upstream refused access, so public content cannot replace it"

hRetryAfter :: HeaderName
hRetryAfter = "Retry-After"

-- | The status a brief-wait admission shed renders on the read and publish paths: @503 Service Unavailable@, the server-capacity signal, not a @429@ rate limit.
shedStatus :: Status
shedStatus = status503

-- | The shed retry delay, rounded down to whole seconds from 'admissionWaitMicros'.
shedRetryAfter :: Header
shedRetryAfter = (hRetryAfter, show (admissionWaitMicros `div` 1_000_000))

-- | The body every read-path shed answers with, so the three handlers say one thing.
shedMessage :: Text
shedMessage = "server is busy; retry later"

-- | Render a serve decision's suggested delay as a @Retry-After@ header. 'Nothing' carries no header, because a transience with no suggested delay has nothing to promise.
retryAfterHeaders :: Maybe RetryAfter -> ResponseHeaders
retryAfterHeaders = maybe [] (\(RetryAfter secs) -> [(hRetryAfter, show secs)])

-- | Run the gated work under the serve admission bound, counting one unavailable serve decision when it sheds. @answer@ runs __outside__ the slot, so committing a response never holds one.
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

-- | Match the configured inbound secret without content-dependent early exit. An unconfigured edge is open.
edgeTokenMatches :: Maybe Secret -> Maybe ClientCredential -> Bool
edgeTokenMatches expected forwarded = case expected of
    Nothing -> True
    Just want -> fmap credSecret forwarded == Just want

-- | The body every handler answers a failed edge gate with. It names no configured token and no presented one, so a probe learns only that the edge is closed.
unauthorisedMessage :: Text
unauthorisedMessage = "authentication required"

forwardedCredential :: MountBinding -> Request -> Maybe ClientCredential
forwardedCredential mount = credentialRecover (bindingCredential mount) . requestHeaders

integrityMissing :: ServeDecision
integrityMissing =
    Reject (Rejection MissingIntegrity "this version carries no integrity digest and cannot be served from a public upstream")

integrityBelowFloor :: ServeDecision
integrityBelowFloor =
    Reject (Rejection BelowIntegrityFloor "this version's integrity digest is weaker than the configured minimum and cannot be served from a public upstream")

trustedIntegrityMissing :: ServeDecision
trustedIntegrityMissing =
    Reject (Rejection MissingIntegrity "this private version carries no integrity digest and was not served")

trustedIntegrityBelowFloor :: ServeDecision
trustedIntegrityBelowFloor =
    Reject (Rejection BelowIntegrityFloor "this private version's integrity digest is weaker than the configured trusted minimum and was not served")
