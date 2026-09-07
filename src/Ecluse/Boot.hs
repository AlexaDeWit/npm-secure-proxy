-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The shared boot environment owns the process logger and telemetry resources.
Role work ends before these resources drain and close.
-}
module Ecluse.Boot (
    BootEnv (..),
    applySecretFileIndirection,
    readConfigDocument,
    withBootEnv,
    BootAborted (..),
    orExit,
    refuseBoot,
    logBootWarning,
    logBootInfo,
    logRuleBootOrder,
    buildMirrorQueue,
    probeServerConfig,
) where

import Data.ByteString qualified as BS
import Data.List (lookup)
import Data.Text qualified as T
import Katip (Environment (Environment), LogEnv, Severity (InfoS, WarningS), closeScribes)
import System.Environment (getEnvironment)
import System.IO.Error (ioeGetErrorString, isDoesNotExistError)
import UnliftIO (bracket, throwIO, tryIO)

import Ecluse.Composition.BootError (renderBootErrors)
import Ecluse.Composition.MirrorQueue (
    MirrorQueuePlan (MemoryBackend, SqsBackend),
    deadLetterTerminusWarning,
    memoryQueueDropWarning,
 )
import Ecluse.Composition.Plan (
    BootInputs (BootInputs, biConfig, biDocument, biEnvVars, biFdLimit, biRuntimePlan),
    BootPlan (bpLines, bpWarnings),
    BootReport (brAdvisories, brOutcome, brProvenance),
    configDocumentPath,
    defaultConfigPath,
    explicitConfigPath,
    resolveBootPlan,
 )
import Ecluse.Composition.Sizing (openFileSoftLimit)
import Ecluse.Composition.Types (BootRole)
import Ecluse.Config (
    AppConfig (cfgObservability, cfgRuntime, cfgServer),
    Config (configApp),
    ObservabilitySettings (obsLogFormat, obsLogLevel, obsTelemetry),
    RuntimeSettings (rtCores, rtCoresCeiling, rtMaxHeapBytes),
    ServerSettings (srvPort),
    loadConfig,
    renderConfigError,
 )
import Ecluse.Config.Resolve (secretEnvSpellings)
import Ecluse.Core.Queue (MirrorQueue (deadLetterTerminus, deliveryBudget))
import Ecluse.Core.Queue.Memory (defaultMemoryQueueConfig, newBoundedInMemoryQueue)
import Ecluse.Core.Rules (renderBootOrder)
import Ecluse.Core.Security.Egress (mkRegistryUrl)
import Ecluse.Core.Server.Context (PackumentDeps (pdRules))
import Ecluse.Rts (RuntimeOverrides (RuntimeOverrides, roCores, roCoresCeiling, roMaxHeapBytes), applyRuntimePosture)
import Ecluse.Runtime.Log (moduleLog, newLogEnv)
import Ecluse.Runtime.Queue.Sqs (newSqsQueue)
import Ecluse.Runtime.Server (
    MountBinding (bindingPackumentDeps, bindingPrefix),
    ServerConfig (scPort),
    mkServerConfig,
 )
import Ecluse.Runtime.Telemetry (Telemetry, TelemetrySwitch (TelemetryOff, TelemetryOn), withTelemetry)
import Ecluse.Runtime.Telemetry.Correlation (ddIdentityFromEnvironment)
import Ecluse.Runtime.Telemetry.Resolve (prepareTelemetry)

-- | Configuration and process resources borrowed by a running role.
data BootEnv = BootEnv
    { beConfig :: Config
    -- ^ The complete loaded configuration, including its provenance.
    , beLogEnv :: LogEnv
    -- ^ The process structured-logging environment.
    , beTelemetry :: Telemetry
    -- ^ The telemetry handle, inert unless @ECLUSE_OBSERVABILITY__TELEMETRY@ enabled it.
    , beBootPlan :: BootPlan
    -- ^ The resolved plan, whose diagnostics were logged before role work starts.
    }

-- | Resolve secret files, strip trailing newlines, and refuse conflicting direct values.
applySecretFileIndirection :: [(String, String)] -> IO (Either Text [(String, String)])
applySecretFileIndirection envVars = do
    reads' <- traverse readOne fileVars
    let (readErrs, resolved) = partitionEithers reads'
    pure $ case conflicts <> readErrs of
        [] -> Right (filter (not . isSecretFileVar . fst) envVars <> resolved)
        errs -> Left (T.unlines errs)
  where
    fileVars = filter (isSecretFileVar . fst) envVars

    conflicts =
        [ T.pack base <> " and " <> T.pack name <> " are both set: supply the secret through exactly one of them"
        | (name, _) <- fileVars
        , let base = baseVarOf name
        , isJust (lookup base envVars)
        ]

    readOne (name, path) = do
        outcome <- tryIO (readFileBS path)
        pure $ case outcome of
            Left err ->
                Left (T.pack name <> " points at " <> T.pack path <> ", which cannot be read: " <> T.pack (displayException err))
            Right bytes ->
                Right (baseVarOf name, T.unpack (T.dropWhileEnd (== '\n') (decodeUtf8 bytes)))

    isSecretFileVar name =
        let spelling = T.pack name
         in "ECLUSE_" `T.isPrefixOf` spelling && any (`T.isSuffixOf` spelling) secretFileSuffixes

    -- Total even though the callers only pass matched names: an unmatched name
    -- passes through rather than inventing a partial strip.
    baseVarOf name = maybe name T.unpack (T.stripSuffix "_FILE" (T.pack name))

    -- The secret-typed keys, by their env-spelling tails. Anything else keeps the
    -- strict no-secrets-in-config posture, with no file-shaped side door.
    secretFileSuffixes :: [Text]
    secretFileSuffixes = map (<> "_FILE") secretEnvSpellings

-- | Accept a missing default document, but refuse an explicit path that does not exist.
readConfigDocument :: [(String, String)] -> IO (Either Text (Maybe ByteString))
readConfigDocument envVars = do
    let docPath = configDocumentPath envVars
    mDocBlob <- tryIO (BS.readFile docPath)
    pure $ case mDocBlob of
        Right bytes -> Right (Just bytes)
        Left err
            | isDoesNotExistError err ->
                case explicitConfigPath envVars of
                    Nothing -> Right Nothing
                    Just path ->
                        Left
                            ( "ECLUSE_CONFIG points at "
                                <> T.pack path
                                <> ", but no config document exists there; fix the path, or unset ECLUSE_CONFIG to use "
                                <> T.pack defaultConfigPath
                            )
            | otherwise ->
                Left
                    ( "config document at "
                        <> T.pack docPath
                        <> " cannot be read: "
                        <> T.pack (ioeGetErrorString err)
                    )

-- | Drain the process logger after role work and telemetry cleanup, on normal or exceptional exit.
withBootEnv :: BootRole -> (BootEnv -> IO a) -> IO a
withBootEnv role action = do
    rawEnvVars <- getEnvironment
    envVars <- applySecretFileIndirection rawEnvVars >>= orExit id
    docBlob <- readConfigDocument envVars >>= orExit id
    config <- orExit (T.unlines . map renderConfigError) (loadConfig envVars docBlob)
    let env = configApp config
        observability = cfgObservability env
        runtimeSettings = cfgRuntime env
        runtimeOverrides =
            RuntimeOverrides
                { roCores = rtCores runtimeSettings
                , roCoresCeiling = rtCoresCeiling runtimeSettings
                , roMaxHeapBytes = rtMaxHeapBytes runtimeSettings
                }
    -- Resolve the log identity from the table the SDK reads, before any OTEL_* projection
    -- applies, so a boot line carries the same identity as a served request.
    ddIdentity <- ddIdentityFromEnvironment
    bracket
        (newLogEnv (obsLogFormat observability) (obsLogLevel observability) ddIdentity (Environment "production"))
        (void . closeScribes)
        $ \logEnv -> do
            -- Apply the runtime posture before anything else spins up. It may exec the binary in
            -- place to enforce a heap ceiling (same PID, see Ecluse.Rts).
            runtimePlan <-
                applyRuntimePosture (logBootInfo logEnv) (logBootWarning logEnv) runtimeOverrides
            fdLimit <- openFileSoftLimit
            let report =
                    resolveBootPlan
                        role
                        BootInputs
                            { biEnvVars = envVars
                            , biDocument = docBlob
                            , biConfig = config
                            , biRuntimePlan = runtimePlan
                            , biFdLimit = fdLimit
                            }
            -- The provenance block logs ahead of every refusable phase, so a refusal that names a
            -- config key stays traceable to the layer that set it.
            traverse_ (logBootInfo logEnv) (brProvenance report)
            let logAdvisories = traverse_ (logBootWarning logEnv) (brAdvisories report)
            bootPlan <- case brOutcome report of
                -- An advisory about a configuration that will not start is still one its operator
                -- must act on, so a refusal reports beside it rather than instead of it.
                Left errs -> logAdvisories >> refuseBoot (renderBootErrors errs)
                Right plan -> pure plan
            -- @ecluse check-config@ prints the same lists in this order, so a transcript and a
            -- boot log agree line for line.
            traverse_ (logBootInfo logEnv) (bpLines bootPlan)
            traverse_ (logBootWarning logEnv) (bpWarnings bootPlan)
            logAdvisories
            prepareTelemetryBoot (obsTelemetry observability) logEnv
            withTelemetry (obsTelemetry observability) logEnv $ \telemetry ->
                action
                    BootEnv
                        { beConfig = config
                        , beLogEnv = logEnv
                        , beTelemetry = telemetry
                        , beBootPlan = bootPlan
                        }

-- | Build the planned queue and log its durability and delivery-limit warnings.
buildMirrorQueue :: LogEnv -> Int -> MirrorQueuePlan -> IO MirrorQueue
buildMirrorQueue logEnv memoryDepth plan = do
    queue <- case plan of
        SqsBackend sqsConfig -> newSqsQueue logEnv mkRegistryUrl sqsConfig
        MemoryBackend ->
            newBoundedInMemoryQueue (defaultMemoryQueueConfig memoryDepth) (logBootWarning logEnv . memoryQueueDropWarning)
    whenJust (deadLetterTerminusWarning plan (deliveryBudget queue) (deadLetterTerminus queue)) (logBootWarning logEnv)
    pure queue

-- | Serve health probes on the configured port, with no package mounts.
probeServerConfig :: AppConfig -> ServerConfig
probeServerConfig appConfig = (mkServerConfig []){scPort = srvPort (cfgServer appConfig)}

-- | Report a boot warning under the root module's logging context.
logBootWarning :: LogEnv -> Text -> IO ()
logBootWarning logEnv = moduleLog logEnv "Ecluse" WarningS

-- | Report a boot diagnostic under the root module's logging context.
logBootInfo :: LogEnv -> Text -> IO ()
logBootInfo logEnv = moduleLog logEnv "Ecluse" InfoS

-- | Report evaluation order for each wired mount.
logRuleBootOrder :: LogEnv -> [MountBinding] -> IO ()
logRuleBootOrder logEnv = traverse_ logMount
  where
    logMount binding = do
        let deps = bindingPackumentDeps binding
        let label = T.intercalate "/" (toList (bindingPrefix binding))
        logBootInfo logEnv ("rule boot order for mount " <> label <> ":")
        traverse_ (logBootInfo logEnv) (renderBootOrder (pdRules deps))

-- | A start-up refusal that the process perimeter reports before exiting.
newtype BootAborted = BootAborted Text
    deriving stock (Eq, Show)

instance Exception BootAborted

-- | Raise the complete refusal for the process perimeter to report.
refuseBoot :: Text -> IO a
refuseBoot = throwIO . BootAborted

-- | Abort on a rendered refusal, or return the successful result.
orExit :: (e -> Text) -> Either e a -> IO a
orExit render = either (refuseBoot . render) pure

{- Prepare the telemetry substrate before the SDK initialises. With
@ECLUSE_OBSERVABILITY__TELEMETRY@ off it is a no-op, reading no process environment. -}
prepareTelemetryBoot :: TelemetrySwitch -> LogEnv -> IO ()
prepareTelemetryBoot switch logEnv = case switch of
    TelemetryOff -> pass
    TelemetryOn -> do
        environment <- getEnvironment
        prepareTelemetry logEnv environment
