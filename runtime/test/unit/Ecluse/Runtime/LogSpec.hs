-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

-- | Logging contracts for rendered fields, severity admission, and JSONL messages.
module Ecluse.Runtime.LogSpec (spec) where

import Data.Aeson (Object, Value (Object), decodeStrict, eitherDecodeStrict, object, (.:), (.=))
import Data.Aeson.Key qualified as Key
import Data.Aeson.KeyMap qualified as KeyMap
import Data.Aeson.Types (parseMaybe)
import Data.Text qualified as T
import Data.Text.Lazy.Builder qualified as TB
import Data.Time (UTCTime (..), fromGregorian)
import Katip (
    Environment (Environment),
    Item (..),
    Namespace (Namespace),
    Severity (AlertS, CriticalS, DebugS, EmergencyS, ErrorS, InfoS, NoticeS, WarningS),
    SimpleLogPayload,
    ThreadIdText (ThreadIdText),
    Verbosity (V2),
    closeScribes,
    logF,
    logStr,
    runKatipT,
    sl,
 )
import Test.Hspec
import UnliftIO (evaluate)

import Ecluse.Core.Credential (mkSecret)
import Ecluse.Runtime.Log (
    DdContext (..),
    DdSpan (..),
    LogFormat (..),
    LogLevel (..),
    ddField,
    ddObject,
    formatterFor,
    newLogEnv,
    newScribe,
    parseLogFormat,
    parseLogLevel,
    severityFloor,
    severityStatus,
 )
import Ecluse.Test.Log (captureStdout, lineMessage)
import Ecluse.Test.WireVocab (wireRoundTrips)

fixedTime :: UTCTime
fixedTime = UTCTime (fromGregorian 2026 6 22) 0

testIdentity :: DdContext
testIdentity = DdContext "ecluse" (Just "prod") (Just "1.4.2") Nothing

item :: SimpleLogPayload -> Text -> Item SimpleLogPayload
item = itemAt WarningS

itemAt :: Severity -> SimpleLogPayload -> Text -> Item SimpleLogPayload
itemAt severity payload message =
    Item
        { _itemApp = Namespace ["ecluse"]
        , _itemEnv = Environment "test"
        , _itemSeverity = severity
        , _itemThread = ThreadIdText "ThreadId 1"
        , _itemHost = "test-host"
        , _itemProcess = 1
        , _itemPayload = payload
        , _itemMessage = logStr message
        , _itemTime = fixedTime
        , _itemNamespace = Namespace ["ecluse"]
        , _itemLoc = Nothing
        }

renderLine :: DdContext -> Item SimpleLogPayload -> Text
renderLine logIdentity logItem =
    toText (TB.toLazyText (formatterFor JsonLog logIdentity False V2 logItem))

lineObject :: DdContext -> Item SimpleLogPayload -> Maybe Object
lineObject logIdentity = decodeStrict . encodeUtf8 . renderLine logIdentity

topField :: Text -> Item SimpleLogPayload -> Maybe Text
topField key logItem = lineObject testIdentity logItem >>= parseMaybe (\o -> o .: Key.fromText key)

dataField :: Text -> Item SimpleLogPayload -> Maybe Text
dataField key logItem = do
    o <- lineObject testIdentity logItem
    dat <- parseMaybe (.: "data") o
    parseMaybe (\d -> d .: Key.fromText key) dat

deniedContext :: SimpleLogPayload
deniedContext =
    sl "package" ("@evil/pkg" :: Text)
        <> sl "version" ("1.0.0" :: Text)
        <> sl "rule" ("DenyInstallTimeExecution" :: Text)

ddObjectOf :: DdContext -> Item SimpleLogPayload -> Maybe Object
ddObjectOf logIdentity logItem = lineObject logIdentity logItem >>= parseMaybe (.: "dd")

ddStr :: Text -> Object -> Maybe Text
ddStr key = parseMaybe (\ob -> ob .: Key.fromText key)

emitAt :: LogLevel -> Severity -> Text -> IO Text
emitAt level severity message =
    captureStdout $ do
        logEnv <- newLogEnv JsonLog level testIdentity (Environment "test")
        runKatipT logEnv $ logF (mempty :: SimpleLogPayload) (Namespace ["serve"]) severity (logStr message)
        void (closeScribes logEnv)

-- | Verify log fields, severity thresholds, and message preservation through real scribes.
spec :: Spec
spec = do
    wireRoundTrips @LogFormat
    wireRoundTrips @LogLevel

    describe "parseLogFormat" $ do
        it "parses the two accepted wire names" $ do
            parseLogFormat "json" `shouldBe` Right JsonLog
            parseLogFormat "console" `shouldBe` Right ConsoleLog

        it "rejects an unknown format, naming the accepted set" $
            parseLogFormat "yaml"
                `shouldBe` Left "unknown log format \"yaml\" (expected one of: json, console)"

    describe "parseLogLevel" $ do
        it "parses the four accepted wire names" $ do
            parseLogLevel "debug" `shouldBe` Right DebugLevel
            parseLogLevel "info" `shouldBe` Right InfoLevel
            parseLogLevel "warn" `shouldBe` Right WarnLevel
            parseLogLevel "error" `shouldBe` Right ErrorLevel

        it "rejects an unknown level, naming the accepted set" $
            parseLogLevel "trace"
                `shouldBe` Left "unknown log level \"trace\" (expected one of: debug, info, warn, error)"

        it "maps each level onto the katip severity floor it admits" $ do
            severityFloor DebugLevel `shouldBe` DebugS
            severityFloor InfoLevel `shouldBe` InfoS
            severityFloor WarnLevel `shouldBe` WarningS
            severityFloor ErrorLevel `shouldBe` ErrorS

    describe "severityStatus (the four statuses a backend facets on)" $
        it "folds the eight katip severities onto debug/info/warn/error" $ do
            severityStatus DebugS `shouldBe` "debug"
            severityStatus InfoS `shouldBe` "info"
            severityStatus NoticeS `shouldBe` "info"
            severityStatus WarningS `shouldBe` "warn"
            severityStatus ErrorS `shouldBe` "error"
            severityStatus CriticalS `shouldBe` "error"
            severityStatus AlertS `shouldBe` "error"
            severityStatus EmergencyS `shouldBe` "error"

    describe "the rendered JSON line" $ do
        it "carries exactly the contracted top-level keys" $ do
            let logItem = item deniedContext "denied"
            fmap (sort . map Key.toText . KeyMap.keys) (lineObject testIdentity logItem)
                `shouldBe` Just ["data", "env", "katip", "message", "service", "status", "timestamp", "version"]

        it "renders the timestamp as RFC 3339 UTC and the status from the severity" $ do
            let logItem = item deniedContext "denied"
            topField "timestamp" logItem `shouldBe` Just "2026-06-22T00:00:00Z"
            topField "status" logItem `shouldBe` Just "warn"
            topField "message" logItem `shouldBe` Just "denied"

        it "stamps the resolved service/env/version identity" $ do
            let logItem = item deniedContext "denied"
            topField "service" logItem `shouldBe` Just "ecluse"
            topField "env" logItem `shouldBe` Just "prod"
            topField "version" logItem `shouldBe` Just "1.4.2"

        it "falls the env back to the katip environment when none was configured" $ do
            -- A deployment that names no DD_ENV / deployment.environment still stamps
            -- an env, so the field is never absent from a line.
            let bare = DdContext "ecluse" Nothing Nothing Nothing
            (lineObject bare (item mempty "boot") >>= parseMaybe (.: "env"))
                `shouldBe` Just ("test" :: Text)

        it "carries every katip severity through as its mapped status" $
            for_ [DebugS, InfoS, NoticeS, WarningS, ErrorS, CriticalS, AlertS, EmergencyS] $ \severity ->
                topField "status" (itemAt severity mempty "event")
                    `shouldBe` Just (severityStatus severity)

        it "preserves the per-call structured payload under data" $ do
            let logItem = item deniedContext "denied"
            dataField "package" logItem `shouldBe` Just "@evil/pkg"
            dataField "version" logItem `shouldBe` Just "1.0.0"
            dataField "rule" logItem `shouldBe` Just "DenyInstallTimeExecution"

        it "keeps the katip emitter fields under one nested key" $ do
            let logItem = item deniedContext "denied"
                katip = lineObject testIdentity logItem >>= parseMaybe (.: "katip")
            (katip >>= parseMaybe (.: "host")) `shouldBe` Just ("test-host" :: Text)
            (katip >>= parseMaybe (.: "thread")) `shouldBe` Just ("ThreadId 1" :: Text)
            fmap (sort . map Key.toText . KeyMap.keys) katip
                `shouldBe` Just ["app", "host", "loc", "ns", "pid", "thread"]

    describe "dd trace correlation on the line" $ do
        it "lifts the log site's active-span ids to a top-level dd object" $ do
            let logItem =
                    item
                        (ddField (DdContext "ecluse" (Just "prod") (Just "1.4.2") (Just (DdSpan "42" "7"))))
                        "denied"
                dd = ddObjectOf testIdentity logItem
            (dd >>= ddStr "trace_id") `shouldBe` Just "42"
            (dd >>= ddStr "span_id") `shouldBe` Just "7"

        it "does not repeat the identity inside data.dd" $ do
            -- The identity is already top level. The line consumes the payload's dd
            -- object for its ids alone, so it never carries the same service twice.
            let logItem =
                    item
                        (ddField (DdContext "ecluse" (Just "prod") (Just "1.4.2") (Just (DdSpan "42" "7"))))
                        "denied"
                dat :: Maybe Object
                dat = lineObject testIdentity logItem >>= parseMaybe (.: "data")
            fmap KeyMap.toList dat `shouldBe` Just []

        it "omits dd entirely outside any span scope" $
            ddObjectOf testIdentity (item deniedContext "denied") `shouldBe` Nothing

        it "omits dd when the payload's dd object carries no ids" $
            -- A line raised under the identity context but outside a span: the context
            -- carries the object, not the ids, so no half-filled correlation pair renders.
            ddObjectOf testIdentity (item (ddField testIdentity) "denied") `shouldBe` Nothing

    describe "log level admission (the scribe's floor)" $ do
        it "suppresses a Debug event at the default info level" $ do
            captured <- emitAt InfoLevel DebugS "diagnostic"
            captured `shouldBe` ""

        it "admits a Debug event at the debug level" $ do
            captured <- emitAt DebugLevel DebugS "diagnostic"
            captured `shouldSatisfy` T.isInfixOf "\"status\":\"debug\""

        it "suppresses an Info event at the warn level" $ do
            captured <- emitAt WarnLevel InfoS "routine"
            captured `shouldBe` ""

        it "admits a Warning event at the warn level" $ do
            captured <- emitAt WarnLevel WarningS "trouble"
            captured `shouldSatisfy` T.isInfixOf "\"status\":\"warn\""

        it "admits an Error event at the error level and suppresses a Warning" $ do
            admitted <- emitAt ErrorLevel ErrorS "broken"
            admitted `shouldSatisfy` T.isInfixOf "\"status\":\"error\""
            suppressed <- emitAt ErrorLevel WarningS "trouble"
            suppressed `shouldBe` ""

    describe "JsonLog stays one physical line (embedded newlines escaped)" $
        for_ escapeCases $ \(label, raw) ->
            it ("keeps one physical line for: " <> toString label) $ do
                captured <- emitAt InfoLevel WarningS raw
                -- The scribe ends each event with one trailing newline, so a message with embedded
                -- newlines still emits as one physical JSONL line, its newline escaped to '\' 'n'.
                case filter (not . T.null) (T.lines captured) of
                    [line] -> line `shouldSatisfy` T.isInfixOf "\\n"
                    other -> expectationFailure ("expected exactly one JSON log line, got " <> show (length other))

    describe "secrets never reach a log field" $ do
        it "a Secret embedded in a payload renders only its redaction, never the token" $ do
            -- Token material must never reach a structured log field (observability.md).
            let token = "super-secret-token"
                leaky = sl "credential" (T.pack (show (mkSecret token)))
            captured <- captureStdout $ do
                logEnv <- newLogEnv JsonLog InfoLevel testIdentity (Environment "test")
                runKatipT logEnv $ logF leaky (Namespace ["serve"]) WarningS (logStr ("using credential" :: Text))
                void (closeScribes logEnv)
            captured `shouldSatisfy` (not . T.isInfixOf token)
            captured `shouldSatisfy` T.isInfixOf "REDACTED"

        it "holds for the console format too" $ do
            let token = "another-secret"
                leaky = sl "credential" (T.pack (show (mkSecret token)))
            captured <- captureStdout $ do
                logEnv <- newLogEnv ConsoleLog InfoLevel testIdentity (Environment "test")
                runKatipT logEnv $ logF leaky (Namespace ["serve"]) WarningS (logStr ("using credential" :: Text))
                void (closeScribes logEnv)
            captured `shouldSatisfy` (not . T.isInfixOf token)

    describe "newScribe" $
        it "constructs a scribe for each format without throwing" $ do
            -- A 'Scribe' is opaque. Forcing it to weak-head normal form is the assertion that the
            -- pipeline assembles for both shapes.
            _ <- newScribe JsonLog InfoLevel testIdentity >>= evaluate
            _ <- newScribe ConsoleLog InfoLevel testIdentity >>= evaluate
            pure () :: Expectation

    describe "newLogEnv (end-to-end through the real scribe)" $ do
        it "writes a JsonLog event as exactly one compact JSON line to stdout" $ do
            captured <- captureStdout $ do
                logEnv <- newLogEnv JsonLog InfoLevel testIdentity (Environment "test")
                runKatipT logEnv $
                    logF deniedContext (Namespace ["serve"]) WarningS (logStr ("denied" :: Text))
                void (closeScribes logEnv)
            -- The scribe ends each event with a newline, so one event is one non-empty physical
            -- line holding a complete JSON object.
            let physicalLines = filter (not . T.null) (T.lines captured)
            length physicalLines `shouldBe` 1
            case physicalLines of
                [line] -> do
                    eitherDecodeStrict (encodeUtf8 line) `shouldSatisfy` isObjectValue
                    line `shouldSatisfy` T.isInfixOf "DenyInstallTimeExecution"
                _ -> expectationFailure "expected exactly one JSON log line"

        it "round-trips a newline-bearing message: the decoded message equals the exact original" $ do
            let original = "denied\nfor cause" :: Text
            captured <- emitAt InfoLevel WarningS original
            -- The escaped newline decodes back to the exact message, so the JSON string escaping
            -- is lossless rather than merely one-line-safe.
            case filter (not . T.null) (T.lines captured) of
                [line] -> lineMessage line `shouldBe` Just original
                other -> expectationFailure ("expected exactly one JSON log line, got " <> show (length other))

        it "writes a ConsoleLog event in the human-readable bracketed form" $ do
            captured <- captureStdout $ do
                logEnv <- newLogEnv ConsoleLog InfoLevel testIdentity (Environment "test")
                runKatipT logEnv $
                    logF deniedContext (Namespace ["serve"]) WarningS (logStr ("denied" :: Text))
                void (closeScribes logEnv)
            captured `shouldSatisfy` T.isInfixOf "[Warning]"
            captured `shouldSatisfy` T.isInfixOf "denied"

    describe "the Datadog context object" $
        it "builds the dd context object: service always, env/version when set, ids only with a span" $ do
            ddObject (DdContext "ecluse" (Just "prod") (Just "1.4.2") (Just (DdSpan "42" "7")))
                `shouldBe` object
                    [ "service" .= ("ecluse" :: Text)
                    , "env" .= ("prod" :: Text)
                    , "version" .= ("1.4.2" :: Text)
                    , "trace_id" .= ("42" :: Text)
                    , "span_id" .= ("7" :: Text)
                    ]
            ddObject (DdContext "ecluse" Nothing Nothing Nothing)
                `shouldBe` object ["service" .= ("ecluse" :: Text)]
  where
    -- Whether a decoded JSON result is a single object (the JSONL contract).
    isObjectValue :: Either String Value -> Bool
    isObjectValue = \case
        Right (Object _) -> True
        _ -> False

    -- Newline-bearing messages whose escaping the JSONL line must preserve.
    escapeCases :: [(Text, Text)]
    escapeCases =
        [ ("a trailing newline", "denied\n")
        , ("an interior newline", "denied\nfor cause")
        , ("a multi-line message", "line one\nline two\nline three")
        , ("a carriage return and newline", "denied\r\nfor cause")
        ]
