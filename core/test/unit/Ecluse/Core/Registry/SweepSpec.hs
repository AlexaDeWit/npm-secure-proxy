-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Core.Registry.SweepSpec (spec) where

import Data.Map.Strict qualified as Map
import Data.Text qualified as T
import Test.Hspec

import Ecluse.Core.Cve (DbEtag (DbEtag))
import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.Fault (TransportCause (TransportTimeout), transportFault)
import Ecluse.Core.Package (PackageName, mkPackageName)
import Ecluse.Core.Registry.Maintenance (
    ConsentVerdict (ConsentGranted, ConsentWithheld),
    NamePrefix,
    RetryAdvice (RetryWorthwhile),
    StoreClass (StoreDestroyable, StorePreserved),
    StoreCursor (writeCursor),
    StoreFacts (factNameAlphabet),
    StoreFault (StoreFault, faultRetry, faultTransport),
    StoreMaintenance (classifyStore, storeCursor, verifyConsent),
    StoredVersion (StoredVersion),
    VersionPresence (VersionServed),
    mkNameAlphabet,
    protocolFault,
    renderNamePrefix,
 )
import Ecluse.Core.Registry.Sweep (sweepCycle, withStoreRetry)
import Ecluse.Core.Registry.Sweep.Types (
    CycleHalt (HaltConsentWithheld, HaltStoreFault, HaltStorePreserved),
    CycleOutcome (outcomeHalt, outcomeTally),
    SweepMode (SweepDeletes, SweepRehearses),
    SweepPacing (swpShape),
    SweepShape (SweepEverything),
    SweepTally (tallyDeleted, tallyExamined, tallyKept),
 )
import Ecluse.Core.Rules.Types (Rule (DenyByIdentity))
import Ecluse.Core.Version (Version, mkVersion)
import Ecluse.Test.Maintenance (
    FakeStore (fakeMaintenance, readFakeCursor),
    FakeStoreConfig (..),
    defaultFakeStoreConfig,
    newFakeStore,
 )
import Ecluse.Test.Package (sampleManifest)
import Ecluse.Test.Rules (denyRule)
import Ecluse.Test.Sweep (RecordedSweep (..), recordingPorts, testMount, testPacing)

spec :: Spec
spec = do
    permissionSpec
    retrySpec
    candidateCycleSpec
    fullWalkSpec

{- The two standing permissions a delete needs, read at every cycle start, because an operator
revokes either while the sweep runs. Both halts name the backend that raised them. -}
permissionSpec :: Spec
permissionSpec = describe "consent and classification" $ do
    it "halts the cycle when the store carries no consent marker, naming the backend" $ do
        store <- seededStore
        let withheld = withStore store (\h -> h{verifyConsent = pure (Right (ConsentWithheld "set permitDeletion to true"))})
        (rec', outcome) <- runCycle SweepDeletes testPacing withheld
        outcomeHalt outcome `shouldBe` Just (HaltConsentWithheld Npm "fake" "set permitDeletion to true")
        errors <- recErrors rec'
        errors `shouldSatisfy` any (T.isInfixOf "carries no deletion consent marker")

    it "halts the cycle when the store refills itself, so a delete would change nothing" $ do
        store <- seededStore
        let preserved = withStore store (\h -> h{classifyStore = pure (Right (StorePreserved "it has an upstream"))})
        (_, outcome) <- runCycle SweepDeletes testPacing preserved
        outcomeHalt outcome `shouldBe` Just (HaltStorePreserved Npm "fake" "it has an upstream")

    it "reads both at every cycle start, so nothing stale decides a delete" $ do
        store <- seededStore
        reads' <- newIORef (0 :: Int)
        let counting h =
                h
                    { verifyConsent = modifyIORef' reads' (+ 1) >> pure (Right ConsentGranted)
                    , classifyStore = modifyIORef' reads' (+ 1) >> pure (Right StoreDestroyable)
                    }
        void (runCycle SweepDeletes testPacing (withStore store counting))
        void (runCycle SweepDeletes testPacing (withStore store counting))
        readIORef reads' `shouldReturn` 4

{- One retry after the wait the fault itself advises. A fault that survives it halts the cycle,
and the next cycle re-attempts, so an outage reports once per interval and clears on its own. -}
retrySpec :: Spec
retrySpec = describe "withStoreRetry" $ do
    it "answers straight through when the call succeeds" $ do
        rec' <- recordingPorts generation
        outcome <- withStoreRetry testPacing (recPorts rec') Npm (pure (Right ('a' :: Char)))
        outcome `shouldBe` Right 'a'
        recDelays rec' `shouldReturn` 0

    it "retries once after a fault worth another attempt, then answers" $ do
        rec' <- recordingPorts generation
        attempts <- newIORef (0 :: Int)
        let flaky = do
                n <- atomicModifyIORef' attempts (\k -> (k + 1, k))
                pure (if n == 0 then Left retryable else Right 'a')
        withStoreRetry testPacing (recPorts rec') Npm flaky `shouldReturn` Right 'a'
        recDelays rec' `shouldReturn` 1

    it "halts the cycle on a fault that survives the retry" $ do
        rec' <- recordingPorts generation
        outcome <- withStoreRetry testPacing (recPorts rec') Npm (pure (Left retryable :: Either StoreFault Char))
        outcome `shouldSatisfy` isLeft
        recDelays rec' `shouldReturn` 1

    it "does not retry a fault whose own advice says another attempt is futile" $ do
        rec' <- recordingPorts generation
        attempts <- newIORef (0 :: Int)
        let futile = modifyIORef' attempts (+ 1) >> pure (Left (protocolFault "it never decodes") :: Either StoreFault Char)
        void (withStoreRetry testPacing (recPorts rec') Npm futile)
        readIORef attempts `shouldReturn` 1
        recDelays rec' `shouldReturn` 0
  where
    retryable = StoreFault{faultTransport = transportFault TransportTimeout "no answer", faultRetry = RetryWorthwhile}

{- The default shape carries only the names an advisory or an identity deny can have changed,
so the store's listing bounds the cycle and the candidate set bounds the metadata reads. -}
candidateCycleSpec :: Spec
candidateCycleSpec = describe "the candidate cycle" $ do
    it "decides only the names the candidate set carries" $ do
        store <- seededStore
        (_, outcome) <- runCycleWith store [DenyByIdentity "left-pad"]
        -- Two packages are in the store and one is a candidate, so only that one is examined.
        tallyExamined (outcomeTally outcome) `shouldBe` 1
        tallyDeleted (outcomeTally outcome) `shouldBe` 1

    it "examines nothing when no name in the store is a candidate" $ do
        store <- seededStore
        (_, outcome) <- runCycleWith store [DenyByIdentity "not-in-this-store"]
        outcomeTally outcome `shouldSatisfy` \t -> tallyExamined t == 0 && tallyKept t == 0
        outcomeHalt outcome `shouldBe` Nothing

    it "reports once that no advisory generation is loaded, and still sweeps the identity half" $ do
        store <- seededStore
        rec' <- recordingPorts Nothing
        outcome <- sweepCycle SweepDeletes testPacing (recPorts rec') [testMount (fakeMaintenance store) [denyRule] [DenyByIdentity "left-pad"]]
        tallyDeleted (outcomeTally outcome) `shouldBe` 1
        errors <- recErrors rec'
        length (filter (T.isInfixOf "no advisory database generation is loaded") errors) `shouldBe` 1

    it "closes a completed cycle with its counts on a routine line" $ do
        store <- seededStore
        (rec', _) <- runCycleWith store [DenyByIdentity "left-pad"]
        info <- recInfo rec'
        info `shouldSatisfy` any (T.isInfixOf "mirror sweep cycle complete: examined 1, deleted 1")

    it "reports a halted cycle on a line an operator must act on" $ do
        store <- seededStore
        let withheld = withStore store (\h -> h{verifyConsent = pure (Right (ConsentWithheld "attach it"))})
        (rec', _) <- runCycle SweepDeletes testPacing withheld
        errors <- recErrors rec'
        errors `shouldSatisfy` any (T.isInfixOf "mirror sweep cycle halted")

{- The opt-in shape carries every name instead, which is what covers a rule-configuration change,
and it records each completed bucket so a restart re-does at most one. -}
fullWalkSpec :: Spec
fullWalkSpec = describe "the full walk" $ do
    it "decides every name in the store, candidate or not" $ do
        store <- seededStore
        (_, outcome) <- runCycle SweepDeletes walkPacing (fakeMaintenance store)
        tallyExamined (outcomeTally outcome) `shouldBe` 2

    it "clears the marker when the walk completes, so the next cycle starts fresh" $ do
        store <- seededStore
        void (runCycle SweepDeletes walkPacing (fakeMaintenance store))
        readFakeCursor store `shouldReturn` Nothing

    it "records each completed bucket, so a restart re-does at most the one in flight" $ do
        store <- newFakeStore (bucketedBy "lx")
        (writes, handle) <- recordingCursor (fakeMaintenance store)
        void (runCycle SweepDeletes walkPacing handle)
        map renderNamePrefix <$> writes `shouldReturn` ["l", "x"]

    it "walks every bucket the alphabet gives, so no name falls outside the walk" $ do
        store <- newFakeStore (bucketedBy "lx")
        (_, outcome) <- runCycle SweepDeletes walkPacing (fakeMaintenance store)
        tallyExamined (outcomeTally outcome) `shouldBe` 2

    it "writes no marker under a dry run, because a rehearsal writes nothing to the store" $ do
        store <- seededStore
        void (runCycle SweepRehearses walkPacing (fakeMaintenance store))
        readFakeCursor store `shouldReturn` Nothing

    it "walks a store that keeps no marker whole, every cycle" $ do
        store <- newFakeStore seededConfig{fakeKeepsCursor = False}
        (_, outcome) <- runCycle SweepDeletes walkPacing (fakeMaintenance store)
        outcomeHalt outcome `shouldBe` Nothing
        tallyExamined (outcomeTally outcome) `shouldBe` 2

    it "halts the cycle when the store's listing stops on a fault" $ do
        store <- newFakeStore seededConfig{fakeFault = Just (protocolFault "the store stopped answering")}
        (_, outcome) <- runCycle SweepDeletes walkPacing (fakeMaintenance store)
        outcomeHalt outcome `shouldSatisfy` isStoreFault
  where
    walkPacing = testPacing{swpShape = SweepEverything}

    isStoreFault = \case
        Just (HaltStoreFault Npm _) -> True
        _ -> False

    -- Both seeded names lead with l, so one bucket holds them and the other is walked empty.
    bucketedBy chars = seededConfig{fakeFacts = (fakeFacts seededConfig){factNameAlphabet = mkNameAlphabet chars}}

{- The handle over a cursor that records what the walk wrote to it, so a case reads the buckets in
the order they completed rather than only the one left behind. -}
recordingCursor :: StoreMaintenance -> IO (IO [NamePrefix], StoreMaintenance)
recordingCursor handle = do
    written <- newIORef []
    let recorded cursor =
            cursor{writeCursor = \prefix -> modifyIORef' written (prefix :) >> writeCursor cursor prefix}
    pure (reverse <$> readIORef written, handle{storeCursor = recorded <$> storeCursor handle})

runCycle :: SweepMode -> SweepPacing -> StoreMaintenance -> IO (RecordedSweep, CycleOutcome)
runCycle mode pacing handle = do
    rec' <- recordingPorts generation
    outcome <- sweepCycle mode pacing (recPorts rec') [testMount handle [denyRule] []]
    pure (rec', outcome)

runCycleWith :: FakeStore -> [Rule] -> IO (RecordedSweep, CycleOutcome)
runCycleWith store configured = do
    rec' <- recordingPorts generation
    outcome <- sweepCycle SweepDeletes testPacing (recPorts rec') [testMount (fakeMaintenance store) [denyRule] configured]
    pure (rec', outcome)

withStore :: FakeStore -> (StoreMaintenance -> StoreMaintenance) -> StoreMaintenance
withStore store f = f (fakeMaintenance store)

seededStore :: IO FakeStore
seededStore = newFakeStore seededConfig

{- Two packages, each with one served version and a manifest that carries it, so a case chooses
which of them the candidate set names. -}
seededConfig :: FakeStoreConfig
seededConfig =
    defaultFakeStoreConfig
        { fakeContents = Map.fromList [(name, [StoredVersion (version "1.0.0") VersionServed]) | name <- names]
        , fakeManifests = Map.fromList [(name, sampleManifest name [version "1.0.0"]) | name <- names]
        }
  where
    names = [packageName "left-pad", packageName "lodash"]

generation :: Maybe DbEtag
generation = Just (DbEtag "etag-1")

packageName :: Text -> PackageName
packageName = mkPackageName Npm Nothing

version :: Text -> Version
version = mkVersion Npm
