-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The katip plumbing every tier's specs share.

A spec either wants no log output at all ('newTestLogEnv', 'runQuietKatip') or wants to
read back exactly what a scribe serialised ('jsonLogEnv' with 'captureStdout'), or what a
refusal reported ('captureStderr').
-}
module Ecluse.Test.Log (
    newTestLogEnv,
    runQuietKatip,
    jsonLogEnv,
    captureStdout,
    captureStderr,
    lineMessage,
) where

import Data.Aeson (Object, eitherDecodeStrict, (.:))
import Data.Aeson.Types (parseMaybe)
import GHC.IO.Handle (hClose, hDuplicate, hDuplicateTo)
import Katip (
    ColorStrategy (ColorLog),
    Environment (Environment),
    KatipContextT,
    LogEnv,
    Namespace (Namespace),
    Severity (DebugS),
    SimpleLogPayload,
    Verbosity (V2),
    defaultScribeSettings,
    initLogEnv,
    permitItem,
    registerScribe,
    runKatipContextT,
 )
import Katip.Scribes.Handle (jsonFormat, mkHandleScribeWithFormatter)
import UnliftIO (bracket)
import UnliftIO.Temporary (withSystemTempFile)

-- | A scribe-free 'LogEnv', so nothing a spec logs reaches the run's output.
newTestLogEnv :: IO LogEnv
newTestLogEnv = initLogEnv (Namespace ["ecluse"]) (Environment "test")

-- | Run a @katip@-constrained action against 'newTestLogEnv', at the empty context and namespace.
runQuietKatip :: KatipContextT IO a -> IO a
runQuietKatip action = do
    logEnv <- newTestLogEnv
    runKatipContextT logEnv (mempty :: SimpleLogPayload) mempty action

{- | A 'LogEnv' with one stdout scribe over @katip@'s own @jsonFormat@, every severity admitted.
The application's own scribe renders a different line shape, so assert on the payload, not the line.
-}
jsonLogEnv :: IO LogEnv
jsonLogEnv = do
    scribe <- mkHandleScribeWithFormatter jsonFormat (ColorLog False) stdout (permitItem DebugS) V2
    base <- newTestLogEnv
    registerScribe "stdout" scribe defaultScribeSettings base

{- | Run an action with 'stdout' redirected to a temporary file and return what it wrote.
'stdout' is restored on every exit path, so scribe output never leaks into the run.
-}
captureStdout :: IO () -> IO Text
captureStdout = captureHandle stdout

-- | 'captureStdout' over 'stderr', the stream a boot refusal reports on.
captureStderr :: IO () -> IO Text
captureStderr = captureHandle stderr

-- The stream is restored on every exit path, so output never leaks into the run.
captureHandle :: Handle -> IO () -> IO Text
captureHandle stream act =
    withSystemTempFile "ecluse-log-capture.txt" $ \path tmpHandle ->
        bracket (hDuplicate stream) restore $ \_saved -> do
            hFlush stream
            hDuplicateTo tmpHandle stream
            act
            hFlush stream
            hClose tmpHandle
            decodeUtf8 <$> readFileBS path
  where
    restore saved = do
        hFlush stream
        hDuplicateTo saved stream
        hClose saved

-- | Read a JSONL message, returning 'Nothing' for malformed JSON or a missing or non-text message.
lineMessage :: Text -> Maybe Text
lineMessage line = case eitherDecodeStrict (encodeUtf8 line) of
    Right o -> parseMaybe (.: "message") (o :: Object)
    Left _ -> Nothing
