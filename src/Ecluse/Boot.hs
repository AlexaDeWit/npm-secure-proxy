-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The shared process-boot bracket for Écluse service roles. 'withBootEnv' applies the
@*_FILE@ secret indirection, loads the configuration under the @ECLUSE_CONFIG@ semantics,
applies the runtime posture, builds the process logger, resolves the 'BootPlan', and
brackets the telemetry substrate. It is the one place the plan's lines reach the boot log.
It then hands the 'BootEnv' to the role dispatch in "Ecluse", which plans that role's runtime
and starts the behaviour the plan names.
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
import Katip (Environment (Environment), LogEnv, Severity (InfoS, WarningS))
import System.Environment (getEnvironment)
import System.IO.Error (ioeGetErrorString, isDoesNotExistError)
import UnliftIO (throwIO, tryIO)

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

{- | The boot context 'withBootEnv' assembles once at start-up. Each subcommand builds the
heavier serve- and worker-side handles later (see "Ecluse.Service").
-}
data BootEnv = BootEnv
    { beConfig :: Config
    {- ^ The whole loaded configuration document. A subcommand that wants only the
    application slice projects it with 'configApp'.
    -}
    , beLogEnv :: LogEnv
    -- ^ The process structured-logging environment.
    , beTelemetry :: Telemetry
    -- ^ The telemetry handle, inert unless @ECLUSE_OBSERVABILITY__TELEMETRY@ enabled it.
    , beBootPlan :: BootPlan
    {- ^ Every decision the configuration settled, including the role this process boots.
    'withBootEnv' has already logged the plan's lines.
    -}
    }

{- | Apply the @*_FILE@ secret indirection: a secret-typed @\<VAR\>_FILE@ names a file whose
contents become its value, one trailing newline stripped. Both spellings at once refuse.
-}
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

{- | Read the config document per the @ECLUSE_CONFIG@ semantics. An absent default path
yields no bytes, and an explicit path that resolves to nothing refuses.
-}
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

{- | Assemble the 'BootEnv' for a role and run @action@ within it. A configuration error refuses
before the runtime posture applies, and the plan's own refusals follow it.
-}
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
    logEnv <- newLogEnv (obsLogFormat observability) (obsLogLevel observability) ddIdentity (Environment "production")
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

{- Build the config-selected mirror queue. Only the memory arm spends @memoryDepth@, and
'deadLetterTerminusWarning' is decided here because it needs the built handle. -}
buildMirrorQueue :: LogEnv -> Int -> MirrorQueuePlan -> IO MirrorQueue
buildMirrorQueue logEnv memoryDepth plan = do
    queue <- case plan of
        SqsBackend sqsConfig -> newSqsQueue logEnv mkRegistryUrl sqsConfig
        MemoryBackend ->
            newBoundedInMemoryQueue (defaultMemoryQueueConfig memoryDepth) (logBootWarning logEnv . memoryQueueDropWarning)
    whenJust (deadLetterTerminusWarning plan (deliveryBudget queue) (deadLetterTerminus queue)) (logBootWarning logEnv)
    pure queue

{- | The server configuration of a probe-only role: the configured port over no mounts, so
the process answers @\/livez@ and @\/readyz@ and gives every other path the neutral @404@.
-}
probeServerConfig :: AppConfig -> ServerConfig
probeServerConfig appConfig = (mkServerConfig []){scPort = srvPort (cfgServer appConfig)}

-- One boot line at 'WarningS', tagged with the root namespace rather than a submodule.
logBootWarning :: LogEnv -> Text -> IO ()
logBootWarning logEnv = moduleLog logEnv "Ecluse" WarningS

-- One boot line at 'InfoS', for a non-warning boot diagnostic.
logBootInfo :: LogEnv -> Text -> IO ()
logBootInfo logEnv = moduleLog logEnv "Ecluse" InfoS

{- Log every wired mount's resolved rule boot order, the same total order evaluation walks.
A mount with no packument deps (the unserved stub) contributes nothing. -}
logRuleBootOrder :: LogEnv -> [MountBinding] -> IO ()
logRuleBootOrder logEnv = traverse_ logMount
  where
    logMount binding = do
        let deps = bindingPackumentDeps binding
        let label = T.intercalate "/" (toList (bindingPrefix binding))
        logBootInfo logEnv ("rule boot order for mount " <> label <> ":")
        traverse_ (logBootInfo logEnv) (renderBootOrder (pdRules deps))

{- | Raised to abort start-up, carrying the rendered refusal the exit site reports. A typed
abort, rather than 'exitFailure', lets a test observe it without the process exiting.
-}
newtype BootAborted = BootAborted Text
    deriving stock (Eq, Show)

instance Exception BootAborted

{- | Abort start-up with a rendered refusal. The caller renders the whole aggregated block, so
one failed launch shows every problem.
-}
refuseBoot :: Text -> IO a
refuseBoot = throwIO . BootAborted

-- Refuse on a Left through 'refuseBoot', otherwise yield the value.
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
