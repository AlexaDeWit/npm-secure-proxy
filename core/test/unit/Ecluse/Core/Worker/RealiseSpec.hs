-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Cover for the realisation half of the worker ("Ecluse.Core.Worker.Realise"): which queue
operation each decided 'Ecluse.Core.Worker.JobOutcome' turns into, and the redelivery budget
that retires a message no dead-letter terminus captures. The decision half's cover lives in
"Ecluse.Core.Worker.JobSpec".
-}
module Ecluse.Core.Worker.RealiseSpec (spec) where

import Data.Text qualified as T
import Katip (closeScribes)
import Test.Hspec

import Ecluse.Core.Package (HashAlg (SRI))
import Ecluse.Core.Queue (DeliveryBudget (DeliveryBudget), MirrorQueue (deliveryBudget), QueueMessage (msgReceipt, msgReceiveCount))
import Ecluse.Core.Registry (PublishError (PublishError), PublishFault (PublishRejected))
import Ecluse.Core.Telemetry.Metrics (MirrorResult (Discarded, Failed, Published))
import Ecluse.Core.Worker (processBatch)
import Ecluse.Test.Log (captureStdout, jsonLogEnv)
import Ecluse.Test.Package (unsafeHash)
import Ecluse.Test.Port (noopWorkerMetricsPort, recordingWorkerMetricsPort)
import Ecluse.Test.Rules (denyRule)
import Ecluse.Worker.Support

spec :: Spec
spec = do
    describe "processBatch -- retiring a decided job at the queue handle" $ do
        it "acks a policy-denied job, retiring it from the queue" $ do
            -- A current-policy deny is non-retryable, so the worker acks the job rather than
            -- leaving it for the backend to redeliver. The ack is the retire decision, observed at
            -- the handle.
            (queue, ackedReceipts) <- recordingAckQueue
            withRuntimeQueue queue (`recordingPublish` Right ()) (npmPolicies presentResolver [denyRule]) noopWorkerMetricsPort $ \runtime logRef -> do
                enqueue_ queue (jobWith unreachableUrl)
                messages <- receive_ queue
                runWM runtime (processBatch messages)
                published <- plDocuments <$> readIORef logRef
                published `shouldBe` []
                acked <- ackedReceipts
                acked `shouldBe` map msgReceipt messages

        it "dead-letters an over-cap artifact on the memory backend: metered, never published, routed to deadLetter not ack (issue #846)" $
            -- A fetch cap below the served bytes makes the over-cap fault terminal, so the worker
            -- routes it to the dead-letter terminus and meters it. The memory backend drops it, its
            -- only terminus.
            withUpstream $ \url -> do
                (queue, deadReceipts) <- recordingDeadLetterQueue
                (metricsPort, recordedMetrics) <- recordingWorkerMetricsPort
                withRuntimeQueue queue (`recordingPublish` Right ()) (withArtifactCap 8 admitPolicies) metricsPort $ \runtime logRef -> do
                    enqueue_ queue (jobWith url)
                    messages <- receive_ queue
                    runWM runtime (processBatch messages)
                    published <- plDocuments <$> readIORef logRef
                    published `shouldBe` []
                    dead <- deadReceipts
                    dead `shouldBe` map msgReceipt messages
                    metered <- recordedMetrics
                    metered `shouldBe` [Failed]

        it "acks the skipped duplicate, retiring it from the queue" $ do
            (queue, ackedReceipts) <- recordingAckQueue
            withRuntimeQueue queue (\logRef -> mirrorListingPublish logRef (Right ()) [ver]) admitPolicies noopWorkerMetricsPort $ \runtime logRef -> do
                enqueue_ queue (jobWith unreachableUrl)
                messages <- receive_ queue
                runWM runtime (processBatch messages)
                published <- plDocuments <$> readIORef logRef
                published `shouldBe` []
                acked <- ackedReceipts
                acked `shouldBe` map msgReceipt messages

    describe "processBatch -- ack decisions at the queue handle" $ do
        -- The worker's retire-vs-retry decision is its ack call, recorded by 'recordingAckQueue'.
        -- The memory backend's ack is a no-op, so "Ecluse.Core.Worker.LoopIntegrationSpec" pins real redelivery against
        -- SQS.
        it "acks a successfully-mirrored job, retiring it from the queue" $
            withUpstream $ \url -> do
                (queue, ackedReceipts) <- recordingAckQueue
                withRuntimeQueue queue (`recordingPublish` Right ()) admitPolicies noopWorkerMetricsPort $ \runtime _logRef -> do
                    enqueue_ queue (jobWith url)
                    messages <- receive_ queue
                    runWM runtime (processBatch messages)
                    acked <- ackedReceipts
                    acked `shouldBe` map msgReceipt messages

        it "does not ack a transiently-failed job (left for the backend to redeliver)" $
            withUpstream $ \url -> do
                (queue, ackedReceipts) <- recordingAckQueue
                withRuntimeQueue queue (`recordingPublish` Left (PublishRejected (PublishError "503"))) admitPolicies noopWorkerMetricsPort $ \runtime _logRef -> do
                    enqueue_ queue (jobWith url)
                    messages <- receive_ queue
                    runWM runtime (processBatch messages)
                    -- The registry rejection is retryable, so the worker must not ack: over a
                    -- redelivering backend the un-acked message comes back ("retry is don't ack").
                    acked <- ackedReceipts
                    acked `shouldBe` []

        -- The ERROR log contract: an operator alerts on the error level, so a message the
        -- queue will simply hand back stays under it. The terminal outcomes beside this one
        -- (a dead-letter, a discard) are what keep the error level worth alerting on.
        it "warns rather than errors when a job is left for redelivery, the routine retry" $
            withUpstream $ \url -> do
                (queue, _ackedReceipts) <- recordingAckQueue
                withRuntimeQueue queue (`recordingPublish` Left (PublishRejected (PublishError "503"))) admitPolicies noopWorkerMetricsPort $ \runtime _logRef -> do
                    enqueue_ queue (jobWith url)
                    messages <- receive_ queue
                    logged <- captureStdout $ do
                        logEnv <- jsonLogEnv
                        runWMWith logEnv runtime (processBatch messages)
                        void (closeScribes logEnv)
                    logged `shouldSatisfy` T.isInfixOf "\"sev\":\"Warning\""
                    logged `shouldSatisfy` T.isInfixOf "leaving mirror job un-acked for retry"
                    logged `shouldSatisfy` (not . T.isInfixOf "\"sev\":\"Error\"")

        it "acks a DROPPED job, retiring a tampered artifact rather than retrying it" $
            -- An integrity mismatch is non-retryable, because redelivery could never make the bytes
            -- match, so the worker acks rather than leaving the job to redeliver indefinitely.
            withUpstream $ \url -> do
                (queue, ackedReceipts) <- recordingAckQueue
                withRuntimeQueue queue (`recordingPublish` Right ()) (admitPoliciesWithDigests [unsafeHash SRI falseSri]) noopWorkerMetricsPort $ \runtime logRef -> do
                    enqueue_ queue (jobWith url)
                    messages <- receive_ queue
                    runWM runtime (processBatch messages)
                    -- The worker published nothing (the mismatch refused the publish)...
                    published <- plDocuments <$> readIORef logRef
                    published `shouldBe` []
                    -- ...and it acked the job: retired at the handle.
                    acked <- ackedReceipts
                    acked `shouldBe` map msgReceipt messages
    describe "processBatch -- the redelivery budget, the terminus a queue without a DLQ has (issue #935)" $ do
        it "retires a delivery that has spent the budget, without ever running the job" $
            withUpstream $ \url -> do
                (metricsPort, readResults) <- recordingWorkerMetricsPort
                (base, ackedReceipts) <- recordingAckQueue
                let queue = base{deliveryBudget = DeliveryBudget 3}
                withRuntimeQueue queue (`recordingPublish` Right ()) admitPolicies metricsPort $ \runtime logRef -> do
                    enqueue_ queue (jobWith url)
                    [message] <- receive_ queue
                    runWM runtime (processBatch [message{msgReceiveCount = 3}])
                    -- The worker checks the budget before it runs the job, so it never
                    -- re-fetches the artifact and spares that repeated cost.
                    published <- plDocuments <$> readIORef logRef
                    published `shouldBe` []
                    -- The ack retires the delivery rather than let it cycle until the queue's
                    -- retention window drops it unseen...
                    acked <- ackedReceipts
                    acked `shouldBe` [msgReceipt message]
                    -- ...and it counts the delivery as a discard: the signal an operator
                    -- alerts on, distinct from an ordinary failure.
                    readResults >>= (`shouldBe` [Discarded])

        it "still runs the job on the delivery one below the budget" $
            withUpstream $ \url -> do
                (metricsPort, readResults) <- recordingWorkerMetricsPort
                (base, ackedReceipts) <- recordingAckQueue
                let queue = base{deliveryBudget = DeliveryBudget 3}
                withRuntimeQueue queue (`recordingPublish` Right ()) admitPolicies metricsPort $ \runtime logRef -> do
                    enqueue_ queue (jobWith url)
                    [message] <- receive_ queue
                    runWM runtime (processBatch [message{msgReceiveCount = 2}])
                    -- The worker mirrors the job and acks it on success.
                    published <- plDocuments <$> readIORef logRef
                    length published `shouldBe` 1
                    acked <- ackedReceipts
                    acked `shouldBe` [msgReceipt message]
                    readResults >>= (`shouldBe` [Published])

    describe "the worker metrics port" $ do
        it "records a Published result for a successfully-mirrored job, through the port" $
            -- Asserts the worker classified the terminal outcome and recorded it through the
            -- recording 'WorkerMetricsPort', which proves the port is wired.
            withUpstream $ \url -> do
                (metricsPort, readResults) <- recordingWorkerMetricsPort
                withRuntimeWith metricsPort (Right ()) $ \runtime queue _logRef -> do
                    enqueue_ queue (jobWith url)
                    messages <- receive_ queue
                    runWM runtime (processBatch messages)
                    readResults >>= (`shouldBe` [Published])

        it "records a Failed result for a tampered job, through the port" $
            withUpstream $ \url -> do
                (metricsPort, readResults) <- recordingWorkerMetricsPort
                withRuntimePolicies (admitPoliciesWithDigests [unsafeHash SRI falseSri]) metricsPort (Right ()) $ \runtime queue _logRef -> do
                    enqueue_ queue (jobWith url)
                    messages <- receive_ queue
                    runWM runtime (processBatch messages)
                    readResults >>= (`shouldBe` [Failed])
