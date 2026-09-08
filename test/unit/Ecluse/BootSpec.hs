-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

-- | Process exits, configuration refusal, and resource cleanup at the boot boundary.
module Ecluse.BootSpec (spec) where

import Prelude hiding (get)

import Control.Concurrent qualified as Conc
import Control.Exception (AsyncException (ThreadKilled))
import Data.Text qualified as T
import System.Environment (setEnv, unsetEnv, withArgs)
import System.Exit (ExitCode (ExitFailure, ExitSuccess))
import System.FilePath ((</>))
import System.IO.Temp (withSystemTempDirectory)
import Test.Hspec
import UnliftIO (bracket_, throwIO, timeout, try)
import UnliftIO.Concurrent (threadDelay)

import Ecluse (ProcessOutcome (..), exitCodeFor, run, superviseProcess)
import Ecluse.Boot (BootAborted (..), BootEnv (beLogEnv), applySecretFileIndirection, logBootInfo, orExit, readConfigDocument, withBootEnv)
import Ecluse.Composition.BootError (
    BootError (AwsEndpointMalformed, MirrorTargetOnMountEndpoint, PrivateUpstreamOnPublicUpstream, SplitRoleNeedsDurableQueue),
    renderBootError,
 )
import Ecluse.Composition.Support (malformedAwsEndpoint, noMaintenanceBackend, overrideEnv, withoutQueueUrl)
import Ecluse.Composition.Types (BootRole (BootWithoutPipeline))
import Ecluse.Config (AppConfig (cfgServer), Config (configApp), ServerSettings (srvAuthToken), loadConfig)
import Ecluse.Core.Credential (Secret, mkSecret, unSecret)
import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Test.Log (captureStderr, captureStdout)

runEnv :: [(String, String)]
runEnv =
    [ ("ECLUSE_SERVER__PUBLIC_URL", "https://registry.example.test")
    , ("ECLUSE_MOUNTS__NPM__PRIVATE_UPSTREAM__REGISTRY__URL", "https://private.example.test")
    , ("ECLUSE_MOUNTS__NPM__MIRROR_TARGET__REGISTRY__URL", "https://mirror.example.test")
    , ("ECLUSE_QUEUE__URL", "https://sqs.us-east-1.amazonaws.com/123456789012/mirror")
    , ("ECLUSE_MOUNTS__NPM__MIRROR_TARGET__REGISTRY__TOKEN", "mirror-write-token")
    , ("AWS_ACCESS_KEY_ID", "test")
    , ("AWS_SECRET_ACCESS_KEY", "test")
    , ("ECLUSE_SERVER__PORT", "0")
    ]

codeArtifactRepository :: String
codeArtifactRepository = "https://d-111122223333.d.codeartifact.us-east-1.amazonaws.com/npm/r/"

isRegistryMirrorKey :: String -> Bool
isRegistryMirrorKey name = "ECLUSE_MOUNTS__NPM__MIRROR_TARGET__REGISTRY__" `isPrefixOf` name

awsRunEnv :: [(String, String)]
awsRunEnv =
    [ ("AWS_REGION", "us-east-1")
    ]
        <> runEnv

-- | Verify role boot, process outcomes, and cleanup through the application entry points.
spec :: Spec
spec = do
    describe "process log cleanup" $
        forM_ [("normal return", Right ()), ("exceptional exit", Left (SimulatedServiceFault "role failed"))] $ \(label, expected) ->
            it ("drains queued final audit lines on " <> label) $
                bracket_ (traverse_ (uncurry setEnv) runEnv) (traverse_ (unsetEnv . fst) runEnv) $ do
                    output <- captureStdout $ do
                        result <- try $ withBootEnv BootWithoutPipeline $ \boot -> do
                            replicateM_ 100 (logBootInfo (beLogEnv boot) "final queued audit marker")
                            either throwIO pure expected
                        result `shouldBe` expected
                    length (filter (T.isInfixOf "final queued audit marker") (lines output)) `shouldBe` 100

    describe "run" $ do
        it "boots from the environment layer alone (no document, no AWS_REGION) and serves" $ do
            -- The queue URL's own host carries the region, so a real SQS
            -- deployment needs no AWS_REGION.
            unsetEnv "AWS_REGION"
            traverse_ (uncurry setEnv) runEnv
            outcome <- timeout 100000 (withArgs ["proxy"] run)
            traverse_ (unsetEnv . fst) runEnv
            outcome `shouldBe` Nothing

        it "boots the serve-only pure public gate on ENABLED alone (no queue or AWS variables)" $ do
            -- ECLUSE_MOUNTS__NPM__ENABLED and ECLUSE_SERVER__PUBLIC_URL are the whole start for a
            -- real install. No mount mirrors, so the shipped sqs default is never consulted.
            unsetEnv "AWS_REGION"
            unsetEnv "ECLUSE_QUEUE__URL"
            setEnv "ECLUSE_MOUNTS__NPM__ENABLED" "true"
            setEnv "ECLUSE_SERVER__PUBLIC_URL" "https://registry.example.test"
            setEnv "ECLUSE_SERVER__PORT" "0"
            outcome <- timeout 100000 (withArgs ["proxy"] run)
            unsetEnv "ECLUSE_MOUNTS__NPM__ENABLED"
            unsetEnv "ECLUSE_SERVER__PUBLIC_URL"
            unsetEnv "ECLUSE_SERVER__PORT"
            outcome `shouldBe` Nothing

        it "boots with a config document at the ECLUSE_CONFIG override path and serves" $ do
            withSystemTempDirectory "ecluse-bootspec" $ \dir -> do
                let path = dir </> "config.yaml"
                writeFileText path "server:\n  helpMessage: booted from the override document\n"
                traverse_ (uncurry setEnv) awsRunEnv
                setEnv "ECLUSE_CONFIG" path
                outcome <- timeout 100000 (withArgs ["proxy"] run)
                unsetEnv "ECLUSE_CONFIG"
                traverse_ (unsetEnv . fst) awsRunEnv
                outcome `shouldBe` Nothing

        it "aborts fast when the ECLUSE_CONFIG document carries an unknown key (the override is read and validated)" $ do
            withSystemTempDirectory "ecluse-bootspec" $ \dir -> do
                let path = dir </> "config.yaml"
                writeFileText path "bogusKey: 1\n"
                traverse_ (uncurry setEnv) awsRunEnv
                setEnv "ECLUSE_CONFIG" path
                outcome <- try (timeout 100000 (withArgs ["proxy"] run)) :: IO (Either ExitCode (Maybe ()))
                unsetEnv "ECLUSE_CONFIG"
                traverse_ (unsetEnv . fst) awsRunEnv
                outcome `shouldBe` Left (ExitFailure 2)

        it "aborts fast when ECLUSE_CONFIG points at a missing file (never a silent documentless boot)" $ do
            traverse_ (uncurry setEnv) awsRunEnv
            setEnv "ECLUSE_CONFIG" "/nonexistent/ecluse/config.yaml"
            outcome <- try (timeout 100000 (withArgs ["proxy"] run)) :: IO (Either ExitCode (Maybe ()))
            unsetEnv "ECLUSE_CONFIG"
            traverse_ (unsetEnv . fst) awsRunEnv
            outcome `shouldBe` Left (ExitFailure 2)

        it "aborts fast when ECLUSE_CONFIG points at an unreadable path (a typed refusal, not a raw exception)" $ do
            -- A directory is the portable unreadable-path shape, with no chmod games. The read
            -- failure must land on the same typed exit-2 path as every other config refusal.
            withSystemTempDirectory "ecluse-bootspec" $ \dir -> do
                traverse_ (uncurry setEnv) awsRunEnv
                setEnv "ECLUSE_CONFIG" dir
                outcome <- try (timeout 100000 (withArgs ["proxy"] run)) :: IO (Either ExitCode (Maybe ()))
                unsetEnv "ECLUSE_CONFIG"
                traverse_ (unsetEnv . fst) awsRunEnv
                outcome `shouldBe` Left (ExitFailure 2)

        it "names the path and the error for an unreadable document, never its contents" $
            withSystemTempDirectory "ecluse-bootspec" $ \dir -> do
                outcome <- readConfigDocument [("ECLUSE_CONFIG", dir)]
                case outcome of
                    Right r -> expectationFailure ("expected a typed refusal, got " <> show r)
                    Left message -> do
                        message `shouldSatisfy` T.isInfixOf (T.pack dir)
                        message `shouldSatisfy` T.isInfixOf "cannot be read"

        it "aborts fast at boot when the queue URL names the unbuilt pubsub backend" $ do
            -- The topic-shaped URL names the GCP backend, which has no
            -- implementation compiled in: a loud refusal, never a silent fallback.
            traverse_ (uncurry setEnv) runEnv
            setEnv "ECLUSE_QUEUE__URL" "projects/acme/topics/mirror"
            outcome <- try (timeout 100000 (withArgs ["proxy"] run)) :: IO (Either ExitCode (Maybe ()))
            traverse_ (unsetEnv . fst) runEnv
            -- The typed process supervisor maps the boot abort to exit 2.
            outcome `shouldBe` Left (ExitFailure 2)

        it "aborts fast at boot when the queue URL's shape names no backend" $ do
            traverse_ (uncurry setEnv) runEnv
            setEnv "ECLUSE_QUEUE__URL" "https://queue.example.test/q"
            outcome <- try (timeout 100000 (withArgs ["proxy"] run)) :: IO (Either ExitCode (Maybe ()))
            traverse_ (unsetEnv . fst) runEnv
            outcome `shouldBe` Left (ExitFailure 2)

        it "boots on the in-memory mirror queue when no ECLUSE_QUEUE__URL is set (graceful rollover) and serves" $ do
            unsetEnv "AWS_REGION"
            unsetEnv "ECLUSE_QUEUE__URL"
            traverse_ (uncurry setEnv) (filter ((/= "ECLUSE_QUEUE__URL") . fst) runEnv)
            outcome <- timeout 100000 (withArgs ["proxy"] run)
            traverse_ (unsetEnv . fst) runEnv
            outcome `shouldBe` Nothing

        it "refuses ecluse mirror over the in-memory queue, naming that command" $
            -- The proxy accepts this configuration, so the refusal identifies the dispatched role.
            splitRoleRefusal ["mirror"] `shouldReturn` refusalNaming "ecluse mirror"

        it "refuses ecluse proxy --no-worker over the in-memory queue, naming that command" $
            splitRoleRefusal ["proxy", "--no-worker"] `shouldReturn` refusalNaming "ecluse proxy --no-worker"

        it "refuses ecluse dredger where the mirror target is also the private upstream" $
            -- Only the Dredger refuses this collapsed target and its missing maintenance backend.
            bootRefusal ["dredger"] collapsedMirrorEnv
                `shouldReturn` (Left (ExitFailure 2), map renderBootError [collapsedMirrorRefusal, noMaintenanceBackend])

        it "aborts fast at boot when the SQS endpoint override is set with no AWS_REGION" $ do
            -- The override forces the SQS interpretation, and an emulator or VPC
            -- endpoint carries no region in its host, so AWS_REGION must scope it.
            unsetEnv "AWS_REGION"
            traverse_ (uncurry setEnv) runEnv
            setEnv "AWS_ENDPOINT_URL_SQS" "http://localhost:4566"
            outcome <- try (timeout 100000 (withArgs ["proxy"] run)) :: IO (Either ExitCode (Maybe ()))
            unsetEnv "AWS_ENDPOINT_URL_SQS"
            traverse_ (unsetEnv . fst) runEnv
            outcome `shouldBe` Left (ExitFailure 2)

        it "aborts fast at boot when a mirror target declares its write token and no url" $ do
            -- The write token lives under the target's own tag, so a token alone declares
            -- the target and the absent url is refused, never silently ignored.
            traverse_ (uncurry setEnv) (filter ((/= "ECLUSE_MOUNTS__NPM__MIRROR_TARGET__REGISTRY__URL") . fst) awsRunEnv)
            unsetEnv "ECLUSE_MOUNTS__NPM__MIRROR_TARGET__REGISTRY__URL"
            outcome <- try (timeout 100000 (withArgs ["proxy"] run)) :: IO (Either ExitCode (Maybe ()))
            traverse_ (unsetEnv . fst) awsRunEnv
            outcome `shouldBe` Left (ExitFailure 2)

        it "aborts fast at boot when a registry mirror target has no write token" $ do
            -- The registry tag mints nothing, so it requires the operator's static write
            -- token and a target without one fails at boot.
            traverse_ (uncurry setEnv) awsRunEnv
            unsetEnv "ECLUSE_MOUNTS__NPM__MIRROR_TARGET__REGISTRY__TOKEN"
            outcome <- try (timeout 100000 (withArgs ["proxy"] run)) :: IO (Either ExitCode (Maybe ()))
            traverse_ (unsetEnv . fst) awsRunEnv
            outcome `shouldBe` Left (ExitFailure 2)

        it "aborts fast at boot when a second tag lands on the declared mirror target" $ do
            -- A layer fills keys under a tag, it never switches one, so an endpoint left
            -- carrying two tags is a loud refusal caught before any AWS call.
            traverse_ (uncurry setEnv) awsRunEnv
            setEnv "ECLUSE_MOUNTS__NPM__MIRROR_TARGET__CODE_ARTIFACT__URL" codeArtifactRepository
            outcome <- try (timeout 100000 (withArgs ["proxy"] run)) :: IO (Either ExitCode (Maybe ()))
            unsetEnv "ECLUSE_MOUNTS__NPM__MIRROR_TARGET__CODE_ARTIFACT__URL"
            traverse_ (unsetEnv . fst) awsRunEnv
            outcome `shouldBe` Left (ExitFailure 2)

    describe "the *_FILE secret indirection" $ do
        it "resolves a secret through *_FILE and serves" $ do
            withSystemTempDirectory "ecluse-bootspec" $ \dir -> do
                let secretPath = dir </> "mirror-token"
                writeFileText secretPath "mirror-write-token\n"
                traverse_ (uncurry setEnv) (filter ((/= "ECLUSE_MOUNTS__NPM__MIRROR_TARGET__REGISTRY__TOKEN") . fst) runEnv)
                unsetEnv "ECLUSE_MOUNTS__NPM__MIRROR_TARGET__REGISTRY__TOKEN"
                setEnv "ECLUSE_MOUNTS__NPM__MIRROR_TARGET__REGISTRY__TOKEN_FILE" secretPath
                outcome <- timeout 100000 (withArgs ["proxy"] run)
                unsetEnv "ECLUSE_MOUNTS__NPM__MIRROR_TARGET__REGISTRY__TOKEN_FILE"
                traverse_ (unsetEnv . fst) runEnv
                outcome `shouldBe` Nothing

        it "refuses a secret supplied both directly and through *_FILE (no silent precedence)" $ do
            withSystemTempDirectory "ecluse-bootspec" $ \dir -> do
                let secretPath = dir </> "mirror-token"
                writeFileText secretPath "mirror-write-token\n"
                traverse_ (uncurry setEnv) runEnv
                setEnv "ECLUSE_MOUNTS__NPM__MIRROR_TARGET__REGISTRY__TOKEN_FILE" secretPath
                outcome <- try (timeout 100000 (withArgs ["proxy"] run)) :: IO (Either ExitCode (Maybe ()))
                unsetEnv "ECLUSE_MOUNTS__NPM__MIRROR_TARGET__REGISTRY__TOKEN_FILE"
                traverse_ (unsetEnv . fst) runEnv
                outcome `shouldBe` Left (ExitFailure 2)

        it "passes JSON-looking *_FILE contents through to the exact secret string" $
            withSystemTempDirectory "ecluse-bootspec" $ \dir -> do
                let secretPath = dir </> "token"
                for_ ["12345", "true", "null"] $ \(payload :: Text) -> do
                    writeFileText secretPath (payload <> "\n")
                    resolved <-
                        applySecretFileIndirection
                            [ ("ECLUSE_SERVER__AUTH_TOKEN_FILE", secretPath)
                            , ("ECLUSE_MOUNTS__NPM__MIRROR_TARGET__VERDACCIO__TOKEN_FILE", secretPath)
                            , ("ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__CODE_ARTIFACT__TOKEN_FILE", secretPath)
                            ]
                    case resolved of
                        Left e -> expectationFailure (toString e)
                        Right env -> do
                            -- The indirection resolves each *_FILE to its base variable...
                            map fst env
                                `shouldMatchList` [ "ECLUSE_SERVER__AUTH_TOKEN"
                                                  , "ECLUSE_MOUNTS__NPM__MIRROR_TARGET__VERDACCIO__TOKEN"
                                                  , "ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__CODE_ARTIFACT__TOKEN"
                                                  ]
                            -- JSON-looking secrets must retain their exact string value through loading.
                            case loadConfig (filter ((== "ECLUSE_SERVER__AUTH_TOKEN") . fst) env) Nothing of
                                Left e -> expectationFailure ("unexpected decode error for " <> toString payload <> ": " <> show e)
                                Right cfg ->
                                    (unSecret <$> srvAuthToken (cfgServer (configApp cfg)))
                                        `shouldBe` Just payload

        it "refuses a *_FILE secret whose file cannot be read" $ do
            traverse_ (uncurry setEnv) (filter ((/= "ECLUSE_MOUNTS__NPM__MIRROR_TARGET__REGISTRY__TOKEN") . fst) runEnv)
            unsetEnv "ECLUSE_MOUNTS__NPM__MIRROR_TARGET__REGISTRY__TOKEN"
            setEnv "ECLUSE_MOUNTS__NPM__MIRROR_TARGET__REGISTRY__TOKEN_FILE" "/nonexistent/ecluse/secret"
            outcome <- try (timeout 100000 (withArgs ["proxy"] run)) :: IO (Either ExitCode (Maybe ()))
            unsetEnv "ECLUSE_MOUNTS__NPM__MIRROR_TARGET__REGISTRY__TOKEN_FILE"
            traverse_ (unsetEnv . fst) runEnv
            outcome `shouldBe` Left (ExitFailure 2)

    describe "private/public repository collisions"
        $ forM_
            [ ["proxy"]
            , ["proxy", "--no-worker"]
            , ["mirror"]
            , ["dredger"]
            , ["pilot"]
            , ["pilot", "compile", "--out", "scratchpad/refused-compile"]
            , ["check-config"]
            ]
        $ \args -> it ("refuses " <> unwords args <> " before starting services") $ do
            let env = overrideEnv "ECLUSE_MOUNTS__NPM__PRIVATE_UPSTREAM__REGISTRY__URL" "https://registry.npmjs.org:443/" runEnv
                refusal = renderBootError (PrivateUpstreamOnPublicUpstream Npm "https://registry.npmjs.org:443/")
                expected = case args of
                    ["dredger"] -> [refusal, renderBootError noMaintenanceBackend]
                    ["check-config"] -> [refusal, "configuration: refused"]
                    _ -> [refusal]
            bootRefusal args env `shouldReturn` (Left (ExitFailure 2), expected)

    describe "check-config (validate and print, boot nothing)" $ do
        it "validates a bootable configuration and exits 0" $ do
            traverse_ (uncurry setEnv) runEnv
            outcome <- try (withArgs ["check-config"] run) :: IO (Either ExitCode ())
            traverse_ (unsetEnv . fst) runEnv
            outcome `shouldBe` Left ExitSuccess

        it "refuses an invalid configuration with exit 2" $ do
            -- An active mount with no server.publicUrl: the same refusal a boot
            -- would print, from the same loadConfig.
            traverse_ (uncurry setEnv) (filter ((/= "ECLUSE_SERVER__PUBLIC_URL") . fst) runEnv)
            unsetEnv "ECLUSE_SERVER__PUBLIC_URL"
            outcome <- try (withArgs ["check-config"] run) :: IO (Either ExitCode ())
            traverse_ (unsetEnv . fst) runEnv
            outcome `shouldBe` Left (ExitFailure 2)

        it "refuses an unrecognised queue URL with exit 2 (the queue plan is checked too)" $ do
            traverse_ (uncurry setEnv) runEnv
            setEnv "ECLUSE_QUEUE__URL" "https://queue.example.test/q"
            outcome <- try (withArgs ["check-config"] run) :: IO (Either ExitCode ())
            traverse_ (unsetEnv . fst) runEnv
            outcome `shouldBe` Left (ExitFailure 2)

        it "refuses a publication target without first-party namespaces with exit 2 (the boot's own refusal)" $ do
            traverse_ (uncurry setEnv) runEnv
            setEnv "ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__REGISTRY__URL" "https://publish.example.test"
            outcome <- try (withArgs ["check-config"] run) :: IO (Either ExitCode ())
            unsetEnv "ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__REGISTRY__URL"
            traverse_ (unsetEnv . fst) runEnv
            outcome `shouldBe` Left (ExitFailure 2)

        it "refuses a static publication token without an inbound edge with exit 2" $ do
            traverse_ (uncurry setEnv) runEnv
            setEnv "ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__REGISTRY__URL" "https://publish.example.test"
            setEnv "ECLUSE_MOUNTS__NPM__FIRST_PARTY" "@acme"
            setEnv "ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__REGISTRY__TOKEN" "publish-write-token"
            outcome <- try (withArgs ["check-config"] run) :: IO (Either ExitCode ())
            unsetEnv "ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__REGISTRY__URL"
            unsetEnv "ECLUSE_MOUNTS__NPM__FIRST_PARTY"
            unsetEnv "ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__REGISTRY__TOKEN"
            traverse_ (unsetEnv . fst) runEnv
            outcome `shouldBe` Left (ExitFailure 2)

        it "refuses an enabled ecosystem with no adapter with exit 2" $ do
            traverse_ (uncurry setEnv) runEnv
            setEnv "ECLUSE_MOUNTS__RUBYGEMS__ENABLED" "true"
            outcome <- try (withArgs ["check-config"] run) :: IO (Either ExitCode ())
            unsetEnv "ECLUSE_MOUNTS__RUBYGEMS__ENABLED"
            traverse_ (unsetEnv . fst) runEnv
            outcome `shouldBe` Left (ExitFailure 2)

        it "validates a CodeArtifact-shaped mirror target structurally and exits 0 (no mint, no cloud call)" $ do
            -- The derived-credential expectation is structural on the loaded config.
            -- check-config must never mint the token a boot would.
            traverse_ (uncurry setEnv) (filter (not . isRegistryMirrorKey . fst) runEnv)
            traverse_ unsetEnv (filter isRegistryMirrorKey (map fst runEnv))
            setEnv "ECLUSE_MOUNTS__NPM__MIRROR_TARGET__CODE_ARTIFACT__URL" codeArtifactRepository
            outcome <- try (withArgs ["check-config"] run) :: IO (Either ExitCode ())
            unsetEnv "ECLUSE_MOUNTS__NPM__MIRROR_TARGET__CODE_ARTIFACT__URL"
            traverse_ (unsetEnv . fst) runEnv
            outcome `shouldBe` Left ExitSuccess

    describe "the ambient AWS_ENDPOINT_URL refusal (one verdict for both entry points)" $ do
        it "refuses one malformed override in the boot and in check-config alike" $ do
            -- The pre-flight tool must never pass a value the real boot then refuses.
            traverse_ (uncurry setEnv) runEnv
            setEnv "AWS_ENDPOINT_URL" malformedAwsEndpoint
            -- Each outcome leaves its capture through a ref, so every assertion waits for
            -- the cleanup below and no failure strands the malformed override.
            bootOutcome <- newIORef (Nothing :: Maybe (Either ExitCode (Maybe ())))
            bootReport <- captureStderr $ do
                outcome <- try (timeout 100000 (withArgs ["proxy"] run))
                writeIORef bootOutcome (Just outcome)
            checkOutcome <- newIORef (Nothing :: Maybe (Either ExitCode ()))
            checkReport <- captureStderr $ do
                outcome <- try (withArgs ["check-config"] run)
                writeIORef checkOutcome (Just outcome)
            unsetEnv "AWS_ENDPOINT_URL"
            traverse_ (unsetEnv . fst) runEnv
            readIORef bootOutcome `shouldReturn` Just (Left (ExitFailure 2))
            readIORef checkOutcome `shouldReturn` Just (Left (ExitFailure 2))
            reportLines bootReport `shouldBe` [endpointRefusal]
            reportLines checkReport `shouldBe` [endpointRefusal, "configuration: refused"]
            -- The override can carry a credential, so no report may echo it.
            checkReport `shouldNotSatisfy` T.isInfixOf "s3cr3t"

    describe "superviseProcess (the typed process perimeter)" $ do
        it "classifies a graceful return as ShutdownRequested" $
            superviseProcess (pure ShutdownRequested) `shouldReturn` ShutdownRequested

        it "classifies a boot abort as BootFault carrying the refusal it was raised with" $
            superviseProcess (throwIO (BootAborted "mount npm has no adapter wired in this build"))
                `shouldReturn` BootFault "mount npm has no adapter wired in this build"

        it "classifies a synchronous service escape as ServiceExited with its rendered detail" $ do
            outcome <- superviseProcess (throwIO (SimulatedServiceFault "wiring broke"))
            case outcome of
                ServiceExited detail -> detail `shouldSatisfy` T.isInfixOf "wiring broke"
                other -> expectationFailure ("expected ServiceExited, got " <> show other)

        it "classifies a kill delivery (ThreadKilled) as RunCancelled" $
            -- Deliver a real asynchronous exception to exercise the process perimeter's cancellation path.
            superviseProcess (Conc.myThreadId >>= \tid -> Conc.throwTo tid ThreadKilled >> pure ShutdownRequested)
                `shouldReturn` RunCancelled

        it "rethrows a deliberate ExitCode so an intended status is preserved" $ do
            outcome <- try (superviseProcess (throwIO (ExitFailure 130))) :: IO (Either ExitCode ProcessOutcome)
            outcome `shouldBe` Left (ExitFailure 130)

        it "propagates an unrecognised asynchronous exception (not ours to interpret)" $ do
            -- A test's 'timeout' around 'run' must keep its semantics: the private
            -- timeout token passes through rather than reading as a cancellation.
            outcome <- timeout 50000 (superviseProcess (threadDelay 10_000_000 >> pure ShutdownRequested))
            outcome `shouldBe` Nothing

    describe "exitCodeFor (the operator-visible exit table)" $
        it "maps each outcome onto its documented status" $ do
            exitCodeFor ShutdownRequested `shouldBe` ExitSuccess
            exitCodeFor (ServiceExited "detail") `shouldBe` ExitFailure 1
            exitCodeFor (BootFault "refusal") `shouldBe` ExitFailure 2
            exitCodeFor RunCancelled `shouldBe` ExitFailure 3

    describe "orExit (boot fail-fast)" $ do
        it "yields the value on a Right (a passing boot phase)" $
            orExit (const "unused") (Right 7 :: Either () Int) `shouldReturn` 7

        it "reports the failure and aborts the boot on a Left" $ do
            -- The abort carries the rendered failure, and 'run' is what puts it on stderr, so a
            -- non-zero exit cannot leave without it.
            outcome <- try (orExit (const "boot rejected") (Left ()) :: IO ()) :: IO (Either BootAborted ())
            case outcome of
                Left (BootAborted rendered) -> rendered `shouldBe` "boot rejected"
                Right () -> expectationFailure "expected the boot to abort"

bootRefusal :: [String] -> [(String, String)] -> IO (Either ExitCode (Maybe ()), [Text])
bootRefusal args envVars = do
    unsetEnv "AWS_REGION"
    unsetEnv "ECLUSE_QUEUE__URL"
    traverse_ (uncurry setEnv) envVars
    outcome <- newIORef (Nothing :: Maybe (Either ExitCode (Maybe ())))
    report <- captureStderr $ do
        result <- try (timeout 100000 (withArgs args run))
        writeIORef outcome (Just result)
    traverse_ (unsetEnv . fst) runEnv
    readIORef outcome >>= \case
        Nothing -> fail "the boot left no outcome behind"
        Just result -> pure (result, reportLines report)

splitRoleRefusal :: [String] -> IO (Either ExitCode (Maybe ()), [Text])
splitRoleRefusal args = bootRefusal args (withoutQueueUrl runEnv)

collapsedMirrorEnv :: [(String, String)]
collapsedMirrorEnv = overrideEnv "ECLUSE_MOUNTS__NPM__MIRROR_TARGET__REGISTRY__URL" "https://private.example.test" runEnv

collapsedMirrorRefusal :: BootError
collapsedMirrorRefusal = MirrorTargetOnMountEndpoint Npm Npm "privateUpstream" "https://private.example.test"

refusalNaming :: Text -> (Either ExitCode (Maybe ()), [Text])
refusalNaming invocation =
    (Left (ExitFailure 2), [renderBootError (SplitRoleNeedsDurableQueue invocation)])

malformedSecret :: Secret
malformedSecret = mkSecret (toText malformedAwsEndpoint)

endpointRefusal :: Text
endpointRefusal = renderBootError (AwsEndpointMalformed malformedSecret)

reportLines :: Text -> [Text]
reportLines = filter (not . T.null) . lines

newtype SimulatedServiceFault = SimulatedServiceFault Text
    deriving stock (Eq, Show)

instance Exception SimulatedServiceFault
