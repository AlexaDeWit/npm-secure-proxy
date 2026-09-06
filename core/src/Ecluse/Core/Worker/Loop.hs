-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Failure handling and supervision for the worker's consume loop. A single bad iteration
cannot kill the loop: a failed @receive@ arrives as the queue handle's typed fault value, which
the step logs and backs off from at its own pacing. Residue, an exception escaping a dependency's
typed contract, is 'Ecluse.Core.Supervision.superviseLoop''s concern under the caller's policy,
which retries transient residue and fails the process up on a wiring fault the policy names
'Ecluse.Core.Supervision.Permanent'. Each poll and each completed job advances the
'WorkerHeartbeat'. Shutdown cancels the loop thread, and an un-acked in-flight message simply
redelivers, which is safe because publishing is idempotent.
-}
module Ecluse.Core.Worker.Loop (
    workerLoop,
) where

import Katip (Severity (DebugS, WarningS), logFM, ls)
import UnliftIO.Concurrent (threadDelay)

import Ecluse.Core.Fault (tfDetail)
import Ecluse.Core.Queue (MirrorQueue (receive))
import Ecluse.Core.Supervision (SupervisionPolicy, superviseLoop)
import Ecluse.Core.Worker.Realise (processBatch)
import Ecluse.Core.Worker.Types

{- | The continuous consume loop: long-poll, process, repeat, under the supervision policy. The
heartbeat advances only on progress, so a persistently faulting @receive@ goes stale on @\/livez@.
-}
workerLoop :: SupervisionPolicy -> WorkerM Void
workerLoop policy = superviseLoop policy pollAndProcess
  where
    pollAndProcess :: WorkerM ()
    pollAndProcess = do
        queue <- asks wrQueue
        liftIO (receive queue) >>= \case
            Left fault -> do
                -- No heartbeat advance: the loop is retrying, not healthy-idle, and the stale
                -- heartbeat on @\/livez@ is what escalates. The supervisor backs off only on
                -- residue, so this step paces the typed-fault channel itself.
                logFM WarningS (ls ("worker receive failed, backing off: " <> tfDetail fault))
                backoff
            Right messages -> do
                case messages of
                    [] -> pass
                    _ -> logFM DebugS (ls ("worker received " <> show (length messages) <> " messages" :: Text))
                -- Beat on every successful poll: an empty long-poll is a healthy idle.
                -- 'processBatch' beats again after each job, so a long batch cannot starve it.
                recordWorkerProgress
                processBatch messages

-- The fixed pause after a faulted poll, so the loop retries a persistently failing
-- queue backend at a bounded rate rather than hot-looping.
backoff :: WorkerM ()
backoff = threadDelay 1_000_000
