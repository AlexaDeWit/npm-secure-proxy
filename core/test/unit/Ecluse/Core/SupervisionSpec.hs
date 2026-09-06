-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Core.SupervisionSpec (spec) where

import Control.Retry (simulatePolicy)
import Data.Text qualified as T
import Katip (SimpleLogPayload, closeScribes)
import Katip.Monadic (runKatipContextT)
import Test.Hspec
import UnliftIO (timeout)
import UnliftIO.Async (asyncWithUnmask, cancel, waitCatch)
import UnliftIO.Concurrent (threadDelay)
import UnliftIO.Exception (throwIO, try)

import Ecluse.Core.Supervision (
    BackoffSchedule (BackoffSchedule, bsBaseMicros, bsCapMicros),
    FaultDisposition (Permanent, Transient),
    SupervisionPolicy (SupervisionPolicy, spBackoff, spClassify, spLabel),
    backoffMicros,
    delayListPolicy,
    superviseLoop,
    transientPolicy,
 )
import Ecluse.Test.Log (captureStdout, jsonLogEnv, runQuietKatip)

-- | A typed fault for the loop under test to throw, never stringly.
newtype StepFault = StepFault Text
    deriving stock (Eq, Show)

instance Exception StepFault

-- | A policy over the given classifier with a tiny backoff, so a test never sleeps long.
fastPolicy :: (SomeException -> FaultDisposition) -> SupervisionPolicy
fastPolicy classify =
    SupervisionPolicy
        { spLabel = "test-loop"
        , spClassify = classify
        , spBackoff = BackoffSchedule{bsBaseMicros = 1_000, bsCapMicros = 8_000}
        }

spec :: Spec
spec = do
    describe "backoffMicros" $ do
        it "doubles from the base towards the cap, then saturates" $ do
            let schedule = BackoffSchedule{bsBaseMicros = 100, bsCapMicros = 1_000}
            map (backoffMicros schedule) [0 .. 5] `shouldBe` [100, 200, 400, 800, 1_000, 1_000]

        it "a base equal to the cap is a fixed-interval retry" $ do
            let schedule = BackoffSchedule{bsBaseMicros = 500, bsCapMicros = 500}
            map (backoffMicros schedule) [0, 1, 7] `shouldBe` [500, 500, 500]

        it "the exponent clamp keeps a huge failure count finite (constant past the clamp, never negative)" $ do
            let schedule = BackoffSchedule{bsBaseMicros = 100, bsCapMicros = 30_000_000}
            backoffMicros schedule 10_000 `shouldBe` backoffMicros schedule 12
            backoffMicros schedule 10_000 `shouldSatisfy` (> 0)

    describe "delayListPolicy -- a delay list as a retry policy" $ do
        -- 'simulatePolicy' walks the policy without sleeping. The list's length is the
        -- retry budget, and the policy yields 'Nothing' once it runs out.
        it "waits the nth delay at the nth retry, then stops" $ do
            delays <- simulatePolicy 2 (delayListPolicy [100_000, 250_000])
            map snd delays `shouldBe` [Just 100_000, Just 250_000, Nothing]

        it "an empty list admits no retry (the single initial attempt only)" $ do
            delays <- simulatePolicy 0 (delayListPolicy [])
            map snd delays `shouldBe` [Nothing]

    describe "transientPolicy" $
        it "classifies every synchronous fault as transient, at the given pace" $ do
            let schedule = BackoffSchedule{bsBaseMicros = 100, bsCapMicros = 1_000}
                policy = transientPolicy "shell-loop" schedule
            spLabel policy `shouldBe` "shell-loop"
            spBackoff policy `shouldBe` schedule
            spClassify policy (toException (StepFault "residue")) `shouldBe` Transient

    describe "superviseLoop" $ do
        it "reruns the step after a transient fault (log, back off, continue)" $ do
            calls <- newIORef (0 :: Int)
            let step = do
                    atomicModifyIORef' calls (\n -> (n + 1, ()))
                    throwIO (StepFault "still down")
            _ <- timeout 200_000 (runQuietKatip (superviseLoop (fastPolicy (const Transient)) step))
            attempts <- readIORef calls
            attempts `shouldSatisfy` (>= 3)

        it "a completed step resets the backoff (alternating fault and success stays at the base delay)" $ do
            -- Without a reset on the successful steps, about 15 faults would pace at 1ms, 2ms, 4ms
            -- up to the 8ms cap and miss the window. With the reset every retry waits only the 1ms
            -- base.
            calls <- newIORef (0 :: Int)
            let step = do
                    n <- atomicModifyIORef' calls (\k -> (k + 1, k + 1))
                    when (odd n) (throwIO (StepFault "odd blip"))
            _ <- timeout 300_000 (runQuietKatip (superviseLoop (fastPolicy (const Transient)) step))
            attempts <- readIORef calls
            attempts `shouldSatisfy` (>= 30)

        it "rethrows a permanent fault after one attempt (fail up, no retry)" $ do
            calls <- newIORef (0 :: Int)
            let step = do
                    atomicModifyIORef' calls (\n -> (n + 1, ()))
                    throwIO (StepFault "wiring fault")
            outcome <- try (runQuietKatip (superviseLoop (fastPolicy (const Permanent)) step))
            case outcome of
                Left fault -> fromException fault `shouldBe` Just (StepFault "wiring fault")
                Right v -> absurd v
            readIORef calls `shouldReturn` 1

        it "classification decides per fault: transient faults are absorbed until the permanent one" $ do
            calls <- newIORef (0 :: Int)
            let step = do
                    n <- atomicModifyIORef' calls (\k -> (k + 1, k + 1))
                    if n < 3
                        then throwIO (StepFault "transient blip")
                        else throwIO (StepFault "wiring fault")
                classify fault = case fromException fault of
                    Just (StepFault "wiring fault") -> Permanent
                    _ -> Transient
            outcome <- try (runQuietKatip (superviseLoop (fastPolicy classify) step))
            case outcome of
                Left fault -> fromException fault `shouldBe` Just (StepFault "wiring fault")
                Right v -> absurd v
            readIORef calls `shouldReturn` 3

        -- The ERROR log contract: an operator alerts on the error level, so only the fault
        -- that takes the process down reaches it. A retry is the loop healing itself, and
        -- the stale heartbeat on /livez is what escalates a loop that never recovers.
        it "warns on a transient fault, so a self-healing retry never pages an operator" $ do
            let step = throwIO (StepFault "still down")
            logged <- captureStdout $ do
                logEnv <- jsonLogEnv
                void . timeout 200_000 $
                    runKatipContextT logEnv (mempty :: SimpleLogPayload) mempty (superviseLoop (fastPolicy (const Transient)) step)
                void (closeScribes logEnv)
            logged `shouldSatisfy` T.isInfixOf "\"sev\":\"Warning\""
            logged `shouldSatisfy` T.isInfixOf "iteration faulted"
            logged `shouldSatisfy` (not . T.isInfixOf "\"sev\":\"Error\"")

        it "errors on a permanent fault, the one that takes the process down" $ do
            let step = throwIO (StepFault "wiring fault")
            logged <- captureStdout $ do
                logEnv <- jsonLogEnv
                outcome <- try (runKatipContextT logEnv (mempty :: SimpleLogPayload) mempty (superviseLoop (fastPolicy (const Permanent)) step))
                case outcome of
                    Left fault -> fromException fault `shouldBe` Just (StepFault "wiring fault")
                    Right v -> absurd v
                void (closeScribes logEnv)
            logged `shouldSatisfy` T.isInfixOf "\"sev\":\"Error\""
            logged `shouldSatisfy` T.isInfixOf "permanent fault, failing up"

        it "never absorbs cancellation: a cancelled loop dies like any other thread" $ do
            entered <- newEmptyMVar
            loop <- asyncWithUnmask $ \unmask ->
                unmask . runQuietKatip . superviseLoop (fastPolicy (const Transient)) $ do
                    putMVar entered ()
                    threadDelay 10_000_000
            takeMVar entered
            cancel loop
            outcome <- waitCatch loop
            case outcome of
                Left _cancelled -> pass
                Right v -> absurd v
