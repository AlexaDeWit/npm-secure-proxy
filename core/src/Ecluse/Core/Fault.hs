-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The core-owned transport-fault vocabulary: why a network operation could not
deliver a response, reported as a value.

A client library reports a transport failure as its own exception type
(@http-client@'s @HttpException@, @amazonka@'s error sum). Carrying those types
through the agnostic tiers would couple every consumer to every client library. The
adapter edge is the one place a library's exception type is already in scope, so it
classifies the failure into this closed vocabulary. Everything above reasons over the
value. The classification is coarse on purpose. It distinguishes only the causes a
consumer or an operator reads differently: a timeout, an unreachable peer, a TLS
refusal, or any other protocol-level fault. Everything finer rides in 'tfDetail',
rendered for a log line and never parsed.

This is a leaf module by design. The registry read path, the mirror queue, and the
advisory sync all speak it, so it must sit below each of them.
-}
module Ecluse.Core.Fault (
    -- * Transport faults
    TransportFault (..),
    transportFault,
    TransportCause (..),
    renderTransportCause,
    transportRetryable,

    -- * Retry delays
    RetryAfter (..),

    -- * The shared detail budget
    boundedDetail,
) where

import Data.Text qualified as T

{- | One classified transport failure. Build it with 'transportFault' so the detail stays
bounded.
-}
data TransportFault = TransportFault
    { tfCause :: TransportCause
    -- ^ The closed classification a consumer or an operator reads.
    , tfDetail :: Text
    {- ^ The client library's rendered detail, bounded to a log-line-sized budget.
    Diagnostic text only: it is never parsed, and no decision may branch on it.
    -}
    }
    deriving stock (Eq, Show)

{- | Why the transport could not deliver. Coarse on purpose: each constructor is a
distinction an operator reads differently, and anything finer belongs in 'tfDetail'.
-}
data TransportCause
    = -- | The peer did not answer in time (a connect or response timeout).
      TransportTimeout
    | {- | The peer could not be reached at all: a refused or reset connection, or a
      name that did not resolve.
      -}
      TransportUnreachable
    | -- | The TLS layer refused the peer (a handshake or certificate failure).
      TransportTls
    | {- | Any other client-reported fault (a malformed response, an unparseable
      URL, an internal client error): the closed catch-all, so the sum stays total
      over whatever a client library reports.
      -}
      TransportProtocol
    deriving stock (Eq, Show)

{- | Is a fault with this cause worth another attempt? A timeout and an unreachable peer
can clear on their own. A TLS refusal and a protocol fault need an operator or a fix.
-}
transportRetryable :: TransportCause -> Bool
transportRetryable = \case
    TransportTimeout -> True
    TransportUnreachable -> True
    TransportTls -> False
    TransportProtocol -> False

-- | What a transport cause says happened, for a line an operator reads.
renderTransportCause :: TransportCause -> Text
renderTransportCause = \case
    TransportTimeout -> "the peer did not answer in time"
    TransportUnreachable -> "the peer could not be reached"
    TransportTls -> "the TLS layer refused the peer"
    TransportProtocol -> "the peer's answer could not be used"

{- | A @Retry-After@ delay, in whole seconds. A 'newtype' so a raw count of seconds is
never confused with some other integer when it reaches a response header or a sweep's wait.
-}
newtype RetryAfter = RetryAfter Int
    deriving stock (Eq, Ord, Show)

{- | Build a 'TransportFault' with the detail truncated to the log-line budget, so a
pathological rendered exception cannot bloat a log line or a held error value.
-}
transportFault :: TransportCause -> Text -> TransportFault
transportFault cause detail = TransportFault cause (boundedDetail detail)

{- | Truncate a rendered detail to the shared log-line budget. Every fault vocabulary that
carries diagnostic text bounds it identically.
-}
boundedDetail :: Text -> Text
boundedDetail = T.take maxDetailChars

-- The rendered-detail budget: generous enough for any realistic client-library
-- message, small enough that a held fault value stays log-line sized.
maxDetailChars :: Int
maxDetailChars = 512
