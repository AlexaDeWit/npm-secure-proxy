-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The effectful doubles the worker unit specs run against: a recording publish capability,
the queues that fault or record, the stub upstream, and the builders that assemble a
'WorkerRuntime' over them.

Driving the core worker directly over these doubles, with no application @Env@ and no
OpenTelemetry SDK, is the partition's proof that the worker is genuinely core.
"Ecluse.Worker.Support.Fixtures" holds the values they carry.
-}
module Ecluse.Worker.Support.Runtime (
    -- * A recording publish capability
    PublishLog (..),
    recordingPublish,
    mirrorListingPublish,
    probeUnreachablePublish,

    -- * Building a worker runtime over doubles
    withRuntimeRegistry,
    withRuntimeQueue,
    withWiredRuntime,
    withWiredRuntimeHeartbeat,
    withRuntimePolicies,
    withRuntimeWith,
    withRuntime,
    withQueueRuntime,
    runWM,
    runWMWith,

    -- * Metadata-client doubles
    versionClient,
    throwingVersionClient,

    -- * Queues that fault, throw, or record
    faultingReceiveQueue,
    throwingReceiveQueue,
    recordingAckQueue,
    recordingDeadLetterQueue,
    enqueue_,
    receive_,
    enqueueAndReceive,

    -- * The stub upstream
    withUpstream,
) where

import Katip (LogEnv)
import Network.HTTP.Client (defaultManagerSettings, newManager)
import Network.HTTP.Types (status200)
import UnliftIO.Exception (throwIO)

import Ecluse.Core.Fault (TransportCause (TransportUnreachable), transportFault)
import Ecluse.Core.Package (PackageDetails)
import Ecluse.Core.Queue (
    MirrorJob,
    MirrorQueue (ack, deadLetter, receive),
    QueueMessage (msgReceipt),
    ReceiptHandle,
    enqueue,
 )
import Ecluse.Core.Registry (
    FetchFault (FetchTransport),
    MirrorArtifact,
    ParseError (ParseError),
    PublishFault,
    RegistryResponse (RegistryResponse),
 )
import Ecluse.Core.Registry.Metadata (
    MetadataClient (MetadataClient, fetchFullManifest, fetchVersionMetadata),
    MetadataError,
 )
import Ecluse.Core.Registry.Publish (MirrorPublish (..))
import Ecluse.Core.Telemetry.Record (WorkerMetricsPort)
import Ecluse.Core.Version (Version)
import Ecluse.Core.Worker (
    WorkerHeartbeat,
    WorkerM,
    WorkerPolicies,
    WorkerRuntime (WorkerRuntime, wrHeartbeat, wrInjectTraceContext, wrManager, wrMetrics, wrPolicies, wrQueue, wrTracing),
    newWorkerHeartbeat,
    runWorkerM,
 )
import Ecluse.Test.Log (newTestLogEnv)
import Ecluse.Test.Port (noopWorkerMetricsPort, passthroughWorkerTracingPort)
import Ecluse.Test.Queue (newTestMemoryQueue)
import Ecluse.Test.Stub (stubBaseUrl, withStub)
import Ecluse.Test.Support (TestContractEscape (TestContractEscape))
import Ecluse.Worker.Support.Fixtures (admitPolicies, tarballBytes, withPublish)

{- | What a publish captured: the raw verified bytes it received, and the artifact descriptor whose
digests the real codec assembles its publish document from.
-}
data PublishLog = PublishLog
    { plDocuments :: [ByteString]
    , plArtifacts :: [MirrorArtifact]
    }

{- | A publish double that records each call and returns the given fixed outcome. Its
mirror-presence probe answers absent, so a test drives the full pipeline.
-}
recordingPublish :: IORef PublishLog -> Either PublishFault () -> MirrorPublish
recordingPublish logRef outcome =
    MirrorPublish
        { mpProbeMetadata = const (pure (Right (RegistryResponse "")))
        , mpParseVersionList = const (Left (ParseError "absent: nothing mirrored yet"))
        , mpPublishArtifact = \_ _ artifact document -> do
            atomicModifyIORef' logRef (\l -> (l{plDocuments = document : plDocuments l, plArtifacts = artifact : plArtifacts l}, ()))
            pure outcome
        }

{- | 'recordingPublish' whose mirror-presence probe __confirms__ the given versions
present at the mirror target, for the dedup short-circuit tests.
-}
mirrorListingPublish :: IORef PublishLog -> Either PublishFault () -> [Version] -> MirrorPublish
mirrorListingPublish logRef outcome versions =
    (recordingPublish logRef outcome)
        { mpParseVersionList = const (Right versions)
        }

{- | 'recordingPublish' whose mirror-presence probe reports a mirror outage as the typed
'FetchTransport' value, for the probe-cannot-tell fall-through tests.
-}
probeUnreachablePublish :: IORef PublishLog -> Either PublishFault () -> MirrorPublish
probeUnreachablePublish logRef outcome =
    (recordingPublish logRef outcome)
        { mpProbeMetadata = const (pure (Left (FetchTransport (transportFault TransportUnreachable "simulated mirror outage"))))
        }

{- | Build a 'WorkerRuntime' over the caller's publish double and run the body against it. It hands
back the queue and the publish log, so a test can drive and inspect them.
-}
withRuntimeRegistry :: (IORef PublishLog -> MirrorPublish) -> WorkerPolicies -> WorkerMetricsPort -> (WorkerRuntime -> MirrorQueue -> IORef PublishLog -> IO a) -> IO a
withRuntimeRegistry mkPublish policies metricsPort body = do
    queue <- newTestMemoryQueue
    withRuntimeQueue queue mkPublish policies metricsPort (`body` queue)

{- | 'withRuntimeRegistry' over a __caller-supplied__ queue, so a test observes the worker's
queue-side decisions or drives the loop against a misbehaving queue.
-}
withRuntimeQueue :: MirrorQueue -> (IORef PublishLog -> MirrorPublish) -> WorkerPolicies -> WorkerMetricsPort -> (WorkerRuntime -> IORef PublishLog -> IO a) -> IO a
withRuntimeQueue queue mkPublish policies metricsPort body = do
    logRef <- newIORef (PublishLog [] [])
    withWiredRuntime queue (withPublish (mkPublish logRef) policies) metricsPort (`body` logRef)

{- | The base runtime builder over bundles that already carry their own publish capabilities, with
nothing injected, so a test observes exactly what it wired.
-}
withWiredRuntime :: MirrorQueue -> WorkerPolicies -> WorkerMetricsPort -> (WorkerRuntime -> IO a) -> IO a
withWiredRuntime queue policies metricsPort body = do
    heartbeat <- newWorkerHeartbeat
    withWiredRuntimeHeartbeat heartbeat queue policies metricsPort body

{- | 'withWiredRuntime' over a __caller-supplied__ heartbeat, so a test observes the heartbeat a
mid-batch step reads while the loop runs.
-}
withWiredRuntimeHeartbeat :: WorkerHeartbeat -> MirrorQueue -> WorkerPolicies -> WorkerMetricsPort -> (WorkerRuntime -> IO a) -> IO a
withWiredRuntimeHeartbeat heartbeat queue policies metricsPort body = do
    manager <- newManager defaultManagerSettings
    body
        WorkerRuntime
            { wrQueue = queue
            , wrManager = manager
            , wrHeartbeat = heartbeat
            , wrMetrics = metricsPort
            , wrTracing = passthroughWorkerTracingPort
            , wrInjectTraceContext = id
            , wrPolicies = policies
            }

-- | 'withRuntimeRegistry' with the recording publish double answering the given publish outcome.
withRuntimePolicies :: WorkerPolicies -> WorkerMetricsPort -> Either PublishFault () -> (WorkerRuntime -> MirrorQueue -> IORef PublishLog -> IO a) -> IO a
withRuntimePolicies policies metricsPort outcome =
    withRuntimeRegistry (`recordingPublish` outcome) policies metricsPort

{- | 'withRuntimePolicies' with the default admitting policy ('admitPolicies'), so ingest
re-evaluation always admits.
-}
withRuntimeWith :: WorkerMetricsPort -> Either PublishFault () -> (WorkerRuntime -> MirrorQueue -> IORef PublishLog -> IO a) -> IO a
withRuntimeWith = withRuntimePolicies admitPolicies

-- | 'withRuntimeWith' with the inert worker metrics port: the common case.
withRuntime :: Either PublishFault () -> (WorkerRuntime -> MirrorQueue -> IORef PublishLog -> IO a) -> IO a
withRuntime = withRuntimeWith noopWorkerMetricsPort

{- | Build a 'WorkerRuntime' over a caller-supplied queue, so a test drives the supervised loop
against a queue whose @receive@ misbehaves.
-}
withQueueRuntime :: MirrorQueue -> (WorkerRuntime -> IO a) -> IO a
withQueueRuntime queue body =
    withRuntimeQueue queue (`recordingPublish` Right ()) admitPolicies noopWorkerMetricsPort (\runtime _logRef -> body runtime)

{- | Discharge a 'WorkerM' to 'IO' over the worker runtime. The @katip@ environment has no
scribe, so log lines are discarded.
-}
runWM :: WorkerRuntime -> WorkerM a -> IO a
runWM runtime action = newTestLogEnv >>= \logEnv -> runWMWith logEnv runtime action

-- | 'runWM' over a caller-supplied 'LogEnv', so a spec reads back what the worker logged.
runWMWith :: LogEnv -> WorkerRuntime -> WorkerM a -> IO a
runWMWith logEnv = runWorkerM logEnv mempty

{- | A 'MetadataClient' double whose single-version op returns a fixed result (the
full-manifest op is unused here and refuses loudly).
-}
versionClient :: Either MetadataError (Maybe PackageDetails) -> MetadataClient
versionClient result =
    MetadataClient
        { fetchFullManifest = const (throwIO (TestContractEscape "versionClient: fetchFullManifest is unused"))
        , fetchVersionMetadata = \_ _ -> pure result
        }

{- | A 'MetadataClient' double whose single-version op __escapes its total contract__, so the
classification boundary must propagate the throw rather than absorb it.
-}
throwingVersionClient :: MetadataClient
throwingVersionClient =
    MetadataClient
        { fetchFullManifest = const (throwIO (TestContractEscape "throwingVersionClient: fetchFullManifest is unused"))
        , fetchVersionMetadata = \_ _ -> throwIO (TestContractEscape "simulated contract escape")
        }

{- | A queue whose @receive@ always reports the handle's typed fault, counting each call. The
loop must survive a faulted poll and poll again, not die.
-}
faultingReceiveQueue :: IORef Int -> IO MirrorQueue
faultingReceiveQueue calls = do
    base <- newTestMemoryQueue
    pure
        base
            { receive = do
                atomicModifyIORef' calls (\n -> (n + 1, ()))
                pure (Left (transportFault TransportUnreachable "receive: simulated queue outage"))
            }

{- | A queue whose @receive@ always throws, counting each call. The throw breaks the handle's
typed contract, so it drives the loop's residual catch-log-backoff arm.
-}
throwingReceiveQueue :: IORef Int -> IO MirrorQueue
throwingReceiveQueue calls = do
    base <- newTestMemoryQueue
    pure
        base
            { receive = do
                atomicModifyIORef' calls (\n -> (n + 1, ()))
                throwIO (TestContractEscape "receive: simulated queue outage")
            }

{- | The test queue with 'ack' wrapped to record each acked receipt. The memory backend never
redelivers, so its own state does not show the worker's retire-vs-retry decision.
-}
recordingAckQueue :: IO (MirrorQueue, IO [ReceiptHandle])
recordingAckQueue = do
    base <- newTestMemoryQueue
    acked <- newIORef []
    let recording = base{ack = \receipt -> atomicModifyIORef' acked (\rs -> (receipt : rs, ())) >> ack base receipt}
    pure (recording, reverse <$> readIORef acked)

{- | The test queue with 'deadLetter' wrapped to record each dead-lettered receipt. That record
is the only signal a terminal fault went to the terminus rather than 'ack'.
-}
recordingDeadLetterQueue :: IO (MirrorQueue, IO [ReceiptHandle])
recordingDeadLetterQueue = do
    base <- newTestMemoryQueue
    dead <- newIORef []
    let recording = base{deadLetter = \receipt -> atomicModifyIORef' dead (\rs -> (receipt : rs, ())) >> deadLetter base receipt}
    pure (recording, reverse <$> readIORef dead)

-- Enqueue a job on the test queue, unwrapping its never-faulting typed
-- channel: a 'Left' is a broken test premise, failed loudly.
enqueue_ :: MirrorQueue -> MirrorJob -> IO ()
enqueue_ queue job =
    enqueue queue job >>= \case
        Left fault -> fail ("enqueue faulted on the test queue: " <> show fault)
        Right () -> pass

-- Receive the currently-queued batch, unwrapping the never-faulting typed channel.
receive_ :: MirrorQueue -> IO [QueueMessage]
receive_ queue =
    receive queue >>= \case
        Left fault -> fail ("receive faulted on the test queue: " <> show fault)
        Right messages -> pure messages

-- Enqueue a job, receive it, and return its receipt handle, so a test drives the per-job
-- processing with a real handle.
enqueueAndReceive :: MirrorQueue -> MirrorJob -> IO (ReceiptHandle, MirrorJob)
enqueueAndReceive queue job = do
    enqueue_ queue job
    receive_ queue >>= \case
        [message] -> pure (msgReceipt message, job)
        other -> fail ("expected exactly one message, got " <> show other)

-- | Run a stub upstream that serves 'tarballBytes' and yields its base URL to the body.
withUpstream :: (Text -> IO a) -> IO a
withUpstream body = withStub status200 (toLazy tarballBytes) (body . stubBaseUrl)
