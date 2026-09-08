-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Shared authentication, admission shedding, and refusal handling.
Route handlers keep their own response formats while sharing these policy decisions.
-}
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

-- | Use 503 to report server admission capacity, without implying a client rate limit.
shedStatus :: Status
shedStatus = status503

-- | The shed retry delay, rounded down to whole seconds from 'admissionWaitMicros'.
shedRetryAfter :: Header
shedRetryAfter = (hRetryAfter, show (admissionWaitMicros `div` 1_000_000))

-- | The body every read-path shed answers with, so the three handlers say one thing.
shedMessage :: Text
shedMessage = "server is busy; retry later"

-- | Emit Retry-After only when a decision supplies a delay.
retryAfterHeaders :: Maybe RetryAfter -> ResponseHeaders
retryAfterHeaders = maybe [] (\(RetryAfter secs) -> [(hRetryAfter, show secs)])

-- | Hold admission only during gated work. Respond outside the slot and record shedding as unavailable.
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

-- | Report edge authentication failure without disclosing either token.
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
