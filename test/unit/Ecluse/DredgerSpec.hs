-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.DredgerSpec (spec) where

import Data.Map.Strict qualified as Map
import Data.Text qualified as T
import Test.Hspec

import Ecluse.Core.Cve (DbEtag (DbEtag))
import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.Package (PackageName, mkPackageName, renderPackageName)
import Ecluse.Core.Registry.Maintenance (
    StoreCursor (writeCursor),
    StoreMaintenance (deleteVersions, storeCursor),
    StoredVersion (StoredVersion),
    VersionPresence (VersionServed),
 )
import Ecluse.Core.Registry.Sweep.Types (
    CycleHalt,
    SweepPacing (swpDeletionCap),
    SweepReport (reportCapHalts, reportRemoval),
 )
import Ecluse.Core.Rules.Types (Rule (DenyByIdentity))
import Ecluse.Core.Telemetry.Metrics (SweepResult (SweepDeleted, SweepExamined, SweepWouldDelete))
import Ecluse.Core.Version (Version, mkVersion)
import Ecluse.Dredger (dredgerReady, latchedStep)
import Ecluse.Dredger.Plan (SweepMode (SweepRehearses), rehearsedStore, sweepReportFor)
import Ecluse.Test.Maintenance (
    FakeStore (fakeMaintenance, readFakeContents, readFakeCursor),
    FakeStoreConfig (..),
    defaultFakeStoreConfig,
    newFakeStore,
    withBucket,
 )
import Ecluse.Test.Package (sampleManifest)
import Ecluse.Test.Rules (denyRule)
import Ecluse.Test.Sweep (RecordedSweep (..), recordingPorts, testMount, testPacing)

spec :: Spec
spec = do
    latchSpec
    probeSpec
    rehearsalSpec

{- The cap is a breaker, so it stops the Dredger for the life of the process. Nothing clears it,
and the process stays up, because exiting would restart into the same poisoned generation. -}
latchSpec :: Spec
latchSpec = describe "a latched halt" $ do
    it "runs no further cycle, so the store it did not reach is untouched" $ do
        -- The first cycle fills a cap of one and latches. Two more steps then run nothing, so the
        -- second package is still served and was never even examined.
        (store, rec', _) <- stepped 3
        remaining <- held store
        length remaining `shouldBe` 1
        counted <- recResults rec'
        counted `shouldBe` [SweepExamined, SweepDeleted]

    it "repeats its own line at each cycle interval, so nothing halts in silence" $ do
        (_, rec', _) <- stepped 3
        errors <- recErrors rec'
        length (filter (T.isInfixOf "the mirror sweep is halted and runs no cycle") errors) `shouldBe` 2

    it "waits the cycle pause before repeating, rather than spinning on the halt" $ do
        (_, rec', _) <- stepped 3
        recDelays rec' `shouldReturn` 3

{- A latch closes readiness for good and leaves liveness alone: an orchestrator that restarted the
pod would start sweeping the same generation that filled the cap. -}
probeSpec :: Spec
probeSpec = describe "the health surface under a latch" $ do
    it "answers ready while the advisory sync has landed and nothing has latched" $
        dredgerReady (pure True) (pure Nothing) `shouldReturn` True

    it "stops answering ready once a halt latched" $ do
        (_, _, latched) <- stepped 1
        halt <- readIORef latched
        halt `shouldSatisfy` isJust
        dredgerReady (pure True) (readIORef latched) `shouldReturn` False

    it "answers unready before the advisory sync has landed, latch or no latch" $
        dredgerReady (pure False) (pure Nothing) `shouldReturn` False

{- The composition root hands the loop a store that cannot delete, so a dry run is not a branch
the loop takes but a capability it was never given. -}
rehearsalSpec :: Spec
rehearsalSpec = describe "rehearsedStore" $ do
    it "deletes nothing through the handle a dry run holds" $ do
        store <- newFakeStore seededConfig
        seeded <- held store
        outcomes <- deleteVersions (rehearsedStore (fakeMaintenance store)) (packageName "left-pad") [version "1.0.0"]
        length outcomes `shouldBe` 1
        held store `shouldReturn` seeded

    it "writes no walk marker, because a rehearsal writes nothing to the store" $ do
        store <- newFakeStore seededConfig
        let rehearsed = rehearsedStore (fakeMaintenance store)
        withBucket "l" $ \prefix ->
            traverse_ (\cursor -> void (writeCursor cursor prefix)) (storeCursor rehearsed)
        readFakeCursor store `shouldReturn` Nothing

    it "counts a removal as would-delete, and lets the cap only log" $ do
        let report = sweepReportFor SweepRehearses
        reportRemoval report `shouldBe` SweepWouldDelete
        reportCapHalts report `shouldBe` False

{- Drive the cycling Dredger's own step the given number of times over a seeded store whose cap is
one, and hand back what the store holds, what was reported, and what latched. -}
stepped :: Int -> IO (FakeStore, RecordedSweep, IORef (Maybe CycleHalt))
stepped steps = do
    store <- newFakeStore seededConfig
    rec' <- recordingPorts generation
    latched <- newIORef Nothing
    let mount = testMount (fakeMaintenance store) [denyRule] (map (DenyByIdentity . renderPackageName) seededNames)
    replicateM_ steps (latchedStep cappedPacing (recPorts rec') [mount] latched)
    pure (store, rec', latched)

seededConfig :: FakeStoreConfig
seededConfig =
    defaultFakeStoreConfig
        { fakeContents = Map.fromList [(name, [StoredVersion (version "1.0.0") VersionServed]) | name <- names]
        , fakeManifests = Map.fromList [(name, sampleManifest name [version "1.0.0"]) | name <- names]
        }
  where
    names = seededNames

seededNames :: [PackageName]
seededNames = [packageName "left-pad", packageName "lodash"]

-- A cap of one, so the first cycle fills it and latches with the second package untouched.
cappedPacing :: SweepPacing
cappedPacing = testPacing{swpDeletionCap = 1}

held :: FakeStore -> IO [Version]
held store = concatMap (map storedVersionOf) . Map.elems <$> readFakeContents store
  where
    storedVersionOf (StoredVersion v _) = v

generation :: Maybe DbEtag
generation = Just (DbEtag "etag-1")

packageName :: Text -> PackageName
packageName = mkPackageName Npm Nothing

version :: Text -> Version
version = mkVersion Npm
