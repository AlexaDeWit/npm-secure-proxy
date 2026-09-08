-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Advisory sync planning and lifecycle regressions.
Artifact paths follow the shared schema epoch.
-}
module Ecluse.Cve.SyncSpec (spec) where

import Control.Retry (simulatePolicy)
import Data.Map.Strict qualified as Map
import Data.Text qualified as T
import Katip (closeScribes)
import System.Directory (createDirectoryIfMissing, doesFileExist, removeFile)
import System.Environment (setEnv)
import System.FilePath ((</>))
import System.IO.Temp (withSystemTempDirectory)
import Test.Hspec
import UnliftIO.Exception (throwIO)

import Ecluse.Composition.Support (expectAppConfig)
import Ecluse.Core.Breaker (noBreakerReporter)
import Ecluse.Core.Cve (CveDb (..), DbEtag (..))
import Ecluse.Core.Cve.Slot (newCveSlot, swapIn, withSlotLookup)
import Ecluse.Core.Ecosystem (Ecosystem (..))
import Ecluse.Core.Rules (RuleDeps (rdWithCveLookup))
import Ecluse.Core.Supervision (delayListPolicy)
import Ecluse.Cve.Sync (CveSyncHandle (..), cveRuleDepsFor, cveSyncReady, cveSyncScheduleFor, planCveSync, sweepStaleTemps, sweepStep)
import Ecluse.Runtime.Cve.Sync (SyncEnv (..), SyncSchedule (..), bootBackoffDelays)
import Ecluse.Runtime.Test.Cve (refusingFetch)
import Ecluse.Test.Cve (fakeCveLookup)
import Ecluse.Test.Log (captureStdout, jsonLogEnv, newTestLogEnv)
import Ecluse.Test.Rules (noFaultReporter)

spec :: Spec
spec = do
    describe "planCveSync -- the per-ecosystem advisory-sync plan" $ do
        it "plans nothing without a configured advisory store" $ do
            cfg <- expectAppConfig [] Nothing
            logEnv <- newTestLogEnv
            plan <- planCveSync logEnv Nothing cfg []
            Map.keys plan `shouldBe` []

        it "plans one handle per configured mount ecosystem and prepares the data dir" $
            withSystemTempDirectory "ecluse-cve-sync-plan" $ \dir -> do
                setDummyAwsCredentials
                let dataDir = dir </> "osv"
                -- A stale in-progress download and a canonical artifact from a
                -- previous run: the sweep removes the former and keeps the latter.
                createDirectoryIfMissing True dataDir
                writeFileBS (dataDir </> "npm-osv-schema4.db.tmp") "stale partial download"
                writeFileBS (dataDir </> "npm-osv-schema4.db") "prior artifact"
                cfg <-
                    expectAppConfig
                        [ ("ECLUSE_ADVISORIES__URL", "s3://advisories")
                        , ("ECLUSE_ADVISORIES__DATA_DIR", dataDir)
                        ]
                        (Just mountedNpmDoc)
                logEnv <- newTestLogEnv
                plan <- planCveSync logEnv Nothing cfg [Npm]
                Map.keys plan `shouldBe` [Npm]
                for_ (Map.lookup Npm plan) $ \handle -> do
                    syncEcosystem (csEnv handle) `shouldBe` Npm
                    syncDbPath (csEnv handle) `shouldBe` dataDir </> "npm-osv-schema4.db"
                    -- Not ready and serving nothing until the first sync.
                    readTVarIO (csReady handle) `shouldReturn` False
                    withSlotLookup (syncSlot (csEnv handle)) (pure . isJust) `shouldReturn` False
                doesFileExist (dataDir </> "npm-osv-schema4.db.tmp") `shouldReturn` False
                doesFileExist (dataDir </> "npm-osv-schema4.db") `shouldReturn` True

    describe "sweepStep -- the sweep's best-effort filesystem boundary" $ do
        it "propagates a non-IO exception rather than swallowing it" $ do
            logEnv <- newTestLogEnv
            sweepStep logEnv "/srv/osv" (throwIO SweepBoom) `shouldThrow` (\SweepBoom -> True)

        it "swallows an IOError, logs it at Warning against the path, and returns so boot proceeds" $
            withSystemTempDirectory "ecluse-sweep-io" $ \dir -> do
                logEnv <- jsonLogEnv
                let missing = dir </> "npm-osv-schema4.db.tmp"
                logged <- captureStdout $ do
                    -- Removing a file that is not there raises an 'IOError': the step must
                    -- log it and return, not propagate it.
                    sweepStep logEnv missing (removeFile missing)
                    void (closeScribes logEnv)
                logged `shouldSatisfy` T.isInfixOf "\"sev\":\"Warning\""
                logged `shouldSatisfy` T.isInfixOf "\"module\":\"Ecluse.Cve.Sync\""
                logged `shouldSatisfy` T.isInfixOf "npm-osv-schema4.db.tmp"
                logged `shouldSatisfy` T.isInfixOf "could not sweep"

    describe "sweepStaleTemps -- the whole-directory sweep" $
        it "swallows a listing fault on a missing dir and returns, logging it at Warning" $
            withSystemTempDirectory "ecluse-sweep-missing" $ \dir -> do
                logEnv <- jsonLogEnv
                logged <- captureStdout $ do
                    sweepStaleTemps logEnv (dir </> "missing")
                    void (closeScribes logEnv)
                logged `shouldSatisfy` T.isInfixOf "\"sev\":\"Warning\""
                logged `shouldSatisfy` T.isInfixOf "\"module\":\"Ecluse.Cve.Sync\""

    describe "cveRuleDepsFor -- per-ecosystem capability dispatch" $ do
        it "borrows through the mount ecosystem's own slot" $ do
            handle <- stubSyncHandle
            swapIn (syncSlot (csEnv handle)) (DbEtag "e1") fakeDb
            let deps = cveRuleDepsFor (Map.singleton Npm handle) noBreakerReporter noFaultReporter
            rdWithCveLookup (deps Npm) (pure . isJust) `shouldReturn` True

        it "abstains for an ecosystem the plan does not carry" $ do
            handle <- stubSyncHandle
            swapIn (syncSlot (csEnv handle)) (DbEtag "e1") fakeDb
            let deps = cveRuleDepsFor (Map.singleton Npm handle) noBreakerReporter noFaultReporter
            rdWithCveLookup (deps PyPI) (pure . isJust) `shouldReturn` False

    describe "cveSyncReady -- the first-sync readiness gate" $ do
        it "is vacuously ready with no advisory store (an empty plan)" $
            cveSyncReady Map.empty `shouldReturn` True

        it "waits for every configured ecosystem, then reports ready" $ do
            npmHandle <- stubSyncHandle
            pypiHandle <- stubSyncHandle
            let plan = Map.fromList [(Npm, npmHandle), (PyPI, pypiHandle)]
            cveSyncReady plan `shouldReturn` False
            atomically (writeTVar (csReady npmHandle) True)
            cveSyncReady plan `shouldReturn` False
            atomically (writeTVar (csReady pypiHandle) True)
            cveSyncReady plan `shouldReturn` True

    describe "cveSyncScheduleFor" $
        it "converts the configured poll interval to microseconds over the shipped burst" $ do
            cfg <- expectAppConfig [("ECLUSE_ADVISORIES__POLL_INTERVAL", "90")] Nothing
            let schedule = cveSyncScheduleFor cfg
            schedPollDelay schedule `shouldBe` 90_000_000
            schedBootBackoff schedule `shouldBe` bootBackoffDelays

    describe "the boot burst compiled to a retry policy" $
        it "attempts immediately, backs off over the shipped schedule, then concedes" $ do
            -- 'simulatePolicy' walks the policy without sleeping, so this case pins the burst
            -- schedule directly. The length of 'bootBackoffDelays' is the retry budget.
            delays <- simulatePolicy (length bootBackoffDelays) (delayListPolicy bootBackoffDelays)
            map snd delays `shouldBe` map Just bootBackoffDelays <> [Nothing]

-- A handle as 'planCveSync' would build it, minus the transport (the tests
-- above never fetch): a fresh empty slot and a readiness flag at False.
stubSyncHandle :: IO CveSyncHandle
stubSyncHandle = do
    slot <- newCveSlot
    ready <- newTVarIO False
    pure
        CveSyncHandle
            { csReady = ready
            , csEnv =
                SyncEnv
                    { syncFetch = refusingFetch
                    , syncEcosystem = Npm
                    , syncDbPath = "unused.db"
                    , syncSlot = slot
                    }
            }

-- An owning handle over an in-memory lookup. Closing is a no-op.
fakeDb :: CveDb
fakeDb = CveDb{cveDbLookup = fakeCveLookup [], cveDbClose = pass, cveDbMeta = []}

-- The S3 env discovers credentials from the process environment. The plan only wires
-- the transport and makes no request, so dummies satisfy it.
setDummyAwsCredentials :: IO ()
setDummyAwsCredentials = do
    setEnv "AWS_ACCESS_KEY_ID" "test"
    setEnv "AWS_SECRET_ACCESS_KEY" "test"
    setEnv "AWS_REGION" "us-east-1"

mountedNpmDoc :: ByteString
mountedNpmDoc =
    "{\"server\":{\"publicUrl\":\"https://registry.example.test\"},\
    \\"mounts\":{\"npm\":{\
    \\"privateUpstream\":{\"registry\":{\"url\":\"https://private.example.test\"}},\
    \\"publicUpstream\":{\"registry\":{\"url\":\"https://registry.npmjs.org\"}},\
    \\"mirrorTarget\":{\"registry\":{\"url\":\"https://mirror.example.test\",\"token\":\"token\"}}}}}"

-- | A non-'IO' exception, to prove the sweep does not swallow every fault.
data SweepBoom = SweepBoom
    deriving stock (Show)

instance Exception SweepBoom
