-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Core.Registry.Sweep.PackageSpec (spec) where

import Data.Map.Strict qualified as Map
import Data.Text qualified as T
import Data.Time (UTCTime (UTCTime), fromGregorian)
import Test.Hspec

import Ecluse.Core.Cve (DbEtag (DbEtag))
import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.Package (PackageName, mkPackageName)
import Ecluse.Core.Registry.Maintenance (
    StoreMaintenance (deleteVersions, rehearseDelete),
    StoredVersion (StoredVersion, storedVersion),
    VersionOutcome (VersionRefused, VersionUnreached),
    VersionPresence (VersionServed, VersionWithdrawn),
    protocolFault,
    storeRefusal,
 )
import Ecluse.Core.Registry.Metadata (Manifest)
import Ecluse.Core.Registry.Sweep.Package (sweepPackage)
import Ecluse.Core.Registry.Sweep.Types (
    CycleHalt (HaltDeletionCap),
    SweepMount (smFirstParty, smStore),
    SweepPacing (swpDeletionCap),
    newSweepState,
 )
import Ecluse.Core.Rules (PreparedRule)
import Ecluse.Core.Rules.Types (EvalContext, mkEvalContext)
import Ecluse.Core.Telemetry.Metrics (SweepResult (..))
import Ecluse.Core.Version (Version, mkVersion)
import Ecluse.Test.Maintenance (FakeStore (fakeMaintenance, readFakeContents), FakeStoreConfig (..), defaultFakeStoreConfig, newFakeStore)
import Ecluse.Test.Package (sampleManifest)
import Ecluse.Test.Rules (admitRule, cannotVetRule, denyRule)
import Ecluse.Test.Sweep (RecordedSweep (..), recordingPorts, recordingPortsUnder, rehearsingReport, testMount, testPacing)

epoch :: UTCTime
epoch = UTCTime (fromGregorian 2026 1 1) 0

spec :: Spec
spec = do
    verdictSpec
    unvettableSpec
    beltSpec
    outcomeSpec
    capSpec
    dryRunSpec

{- Only a named decisive deny deletes. Deny by default and an unvettable version both keep,
because the store may hold the only surviving copy. -}
verdictSpec :: Spec
verdictSpec = describe "the delete verdict" $ do
    it "deletes a version a named decisive deny condemns" $ do
        (rec', store) <- sweepOne [denyRule] ["1.0.0"] ["1.0.0"]
        recResults rec' `shouldReturn` [SweepExamined, SweepDeleted]
        held store `shouldReturn` []

    it "keeps a version deny-by-default left undecided" $ do
        -- No rule was decisive, which the serve path refuses on. Here it keeps: nothing named
        -- this version, so nothing licenses destroying it.
        (rec', store) <- sweepOne [] ["1.0.0"] ["1.0.0"]
        recResults rec' `shouldReturn` [SweepExamined, SweepKept]
        held store `shouldReturn` [version "1.0.0"]

    it "keeps a version a rule admitted" $ do
        (rec', store) <- sweepOne [admitRule] ["1.0.0"] ["1.0.0"]
        recResults rec' `shouldReturn` [SweepExamined, SweepKept]
        held store `shouldReturn` [version "1.0.0"]

    it "keeps a version no rule could vet" $ do
        (rec', store) <- sweepOne [cannotVetRule] ["1.0.0"] ["1.0.0"]
        recResults rec' `shouldReturn` [SweepExamined, SweepKept]
        held store `shouldReturn` [version "1.0.0"]

    it "keeps a version the listing names but the manifest no longer carries" $ do
        -- The store lists it and its own metadata does not, so nothing about it can be decided.
        (rec', store) <- sweepOne [denyRule] ["1.0.0"] []
        recResults rec' `shouldReturn` [SweepExamined, SweepKept]
        held store `shouldReturn` [version "1.0.0"]

    it "never decides a version the store lists but no longer serves" $ do
        -- A backend keeps listing a deleted version, so a sweep blind to this would re-issue a
        -- destructive call for it every cycle.
        store <- storeWith [] (Just (sampleManifest packageName [version "1.0.0"]))
        rec' <- recordingPorts generation
        halt <- runStep rec' testPacing (mount store [denyRule]) [StoredVersion (version "1.0.0") VersionWithdrawn]
        halt `shouldBe` Nothing
        recResults rec' `shouldReturn` []

{- A read that produced no manifest keeps every version of the package for this cycle and says so.
The shared bounded fetch discards the response status, so a 404 and a 5xx arrive here alike. -}
unvettableSpec :: Spec
unvettableSpec = describe "a manifest the store did not serve" $ do
    it "keeps every version of the package and reports it" $ do
        store <- storeWith [] Nothing
        rec' <- recordingPorts generation
        halt <- runStep rec' testPacing (mount store [denyRule]) (served ["1.0.0", "2.0.0"])
        halt `shouldBe` Nothing
        recResults rec' `shouldReturn` [SweepExamined, SweepKept, SweepExamined, SweepKept]

    it "names the package and the fault on the line an operator acts on" $ do
        store <- storeWith [] Nothing
        rec' <- recordingPorts generation
        void (runStep rec' testPacing (mount store [denyRule]) (served ["1.0.0"]))
        errors <- recErrors rec'
        errors `shouldSatisfy` any (T.isInfixOf "cannot be vetted and are kept")

beltSpec :: Spec
beltSpec = describe "the first-party belt" $ do
    it "skips a name the deployment owns without reading its metadata at all" $ do
        -- The belt shields the whole name, so the store is never even asked about it.
        store <- storeWith [version "1.0.0"] (Just (sampleManifest packageName [version "1.0.0"]))
        rec' <- recordingPorts generation
        let shielded = (mount store [denyRule]){smFirstParty = const True}
        halt <- runStep rec' testPacing shielded (served ["1.0.0"])
        halt `shouldBe` Nothing
        recResults rec' `shouldReturn` [SweepGuardSkipped]
        held store `shouldReturn` [version "1.0.0"]

{- A refused or unreached delete leaves the version in the store, so it counts as kept and reports
the backend's own code for an operator to follow up. -}
outcomeSpec :: Spec
outcomeSpec = describe "what the backend reported" $ do
    it "counts a refused delete as kept, with the backend's code on an error line" $ do
        rec' <- recordingPorts generation
        store <- refusingStore (VersionRefused (storeRefusal "ACCESS_DENIED" "the identity may not delete"))
        halt <- runStep rec' testPacing (mount store [denyRule]) (served ["1.0.0"])
        halt `shouldBe` Nothing
        recResults rec' `shouldReturn` [SweepExamined, SweepKept]
        errors <- recErrors rec'
        errors `shouldSatisfy` any (T.isInfixOf "ACCESS_DENIED")

    it "counts a delete that never reached the backend as kept, with the fault" $ do
        rec' <- recordingPorts generation
        store <- refusingStore (VersionUnreached (protocolFault "the store never answered"))
        void (runStep rec' testPacing (mount store [denyRule]) (served ["1.0.0"]))
        recResults rec' `shouldReturn` [SweepExamined, SweepKept]
        errors <- recErrors rec'
        errors `shouldSatisfy` any (T.isInfixOf "did not reach the backend")

    it "counts a delete the backend is still doing as deleted, and never awaits it" $ do
        -- The fake reports a late-finishing delete, which is the arm no backend takes today.
        -- The next cycle's listing shows whether it finished, and a repeat delete is idempotent.
        (rec', _) <- sweepOne [denyRule] ["1.0.0"] ["1.0.0"]
        recResults rec' `shouldReturn` [SweepExamined, SweepDeleted]
        info <- recInfo rec'
        info `shouldSatisfy` any (T.isInfixOf "the backend is removing it under")

capSpec :: Spec
capSpec = describe "the per-cycle deletion cap" $ do
    it "hands over what the cap allows, holds the rest back, and halts" $ do
        store <- storeWith (map version ["1.0.0", "2.0.0"]) (Just (sampleManifest packageName (map version ["1.0.0", "2.0.0"])))
        rec' <- recordingPorts generation
        halt <- runStep rec' testPacing{swpDeletionCap = 1} (mount store [denyRule]) (served ["1.0.0", "2.0.0"])
        case halt of
            Just (HaltDeletionCap cap issued etag) -> (cap, issued, etag) `shouldBe` (1, 1, generation)
            other -> expectationFailure ("expected the cap halt, got: " <> show other)
        recResults rec'
            `shouldReturn` [SweepExamined, SweepExamined, SweepGuardSkipped, SweepDeleted]
        held store `shouldReturn` [version "2.0.0"]

    it "latches on reaching the cap even when nothing was held back" $ do
        -- The breaker is the count handed over, not whether this package had more to give, so a
        -- cycle that fills the cap exactly still stops.
        store <- storeWith [version "1.0.0"] (Just (sampleManifest packageName [version "1.0.0"]))
        rec' <- recordingPorts generation
        halt <- runStep rec' testPacing{swpDeletionCap = 1} (mount store [denyRule]) (served ["1.0.0"])
        case halt of
            Just (HaltDeletionCap cap issued _) -> (cap, issued) `shouldBe` (1, 1)
            other -> expectationFailure ("expected the cap halt, got: " <> show other)

    it "does not halt a package that left the cap unreached" $ do
        (rec', _) <- sweepOne [denyRule] ["1.0.0"] ["1.0.0"]
        recErrors rec' `shouldReturn` []

{- A dry run holds a handle with no real delete in it, so this module cannot delete because
nothing it is given can. It counts under its own arm and the cap only logs. -}
dryRunSpec :: Spec
dryRunSpec = describe "a dry run" $ do
    it "counts what it would delete under its own arm and deletes nothing" $ do
        (rec', store) <- rehearseOne testPacing ["1.0.0"]
        recResults rec' `shouldReturn` [SweepExamined, SweepWouldDelete]
        held store `shouldReturn` [version "1.0.0"]

    it "says it would delete rather than that it is deleting" $ do
        (rec', _) <- rehearseOne testPacing ["1.0.0"]
        info <- recInfo rec'
        info `shouldSatisfy` any (T.isInfixOf "dry run, would delete")

    it "counts the full reach past the cap and never halts on it" $ do
        -- The cap is the breaker on real deletions, so under a rehearsal it only logs: an operator
        -- reads the whole count a real run would reach rather than a count that stopped at one.
        (rec', store) <- rehearseOne testPacing{swpDeletionCap = 1} ["1.0.0", "2.0.0"]
        recResults rec'
            `shouldReturn` [SweepExamined, SweepExamined, SweepWouldDelete, SweepWouldDelete]
        held store `shouldReturn` map version ["1.0.0", "2.0.0"]

{- One package's step under a rehearsal's report, over a store whose delete is the backend's own
rehearsal. Nothing here knows which run it is in; the report is what differs. -}
rehearseOne :: SweepPacing -> [Text] -> IO (RecordedSweep, FakeStore)
rehearseOne pacing stored = do
    store <- storeWith (map version stored) (Just (sampleManifest packageName (map version stored)))
    rec' <- recordingPortsUnder rehearsingReport generation
    let handle = fakeMaintenance store
        rehearsed = (mount store [denyRule]){smStore = handle{deleteVersions = fromMaybe (deleteVersions handle) (rehearseDelete handle)}}
    void (runStep rec' pacing rehearsed (served stored))
    pure (rec', store)

-- One package's step over a store seeded with those versions and a manifest carrying those.
sweepOne :: [PreparedRule] -> [Text] -> [Text] -> IO (RecordedSweep, FakeStore)
sweepOne rules stored inManifest = do
    store <- storeWith (map version stored) (Just (sampleManifest packageName (map version inManifest)))
    rec' <- recordingPorts generation
    void (runStep rec' testPacing (mount store rules) (served stored))
    pure (rec', store)

runStep :: RecordedSweep -> SweepPacing -> SweepMount -> [StoredVersion] -> IO (Maybe CycleHalt)
runStep rec' pacing mount' stored = do
    counters <- newSweepState
    ctx <- evalContext
    sweepPackage pacing (recPorts rec') counters mount' (smStore mount') ctx generation packageName stored

-- A store holding those versions, serving that manifest, or serving none at all.
storeWith :: [Version] -> Maybe Manifest -> IO FakeStore
storeWith stored manifest =
    newFakeStore
        defaultFakeStoreConfig
            { fakeContents = Map.singleton packageName [StoredVersion v VersionServed | v <- stored]
            , fakeManifests = maybe Map.empty (Map.singleton packageName) manifest
            }

{- A store whose delete reports the given outcome and changes nothing, so the refusal and the
unreached arms are both drivable without a fault that would stop the whole cycle. -}
refusingStore :: VersionOutcome -> IO FakeStore
refusingStore outcome = do
    store <- storeWith [version "1.0.0"] (Just (sampleManifest packageName [version "1.0.0"]))
    let handle = fakeMaintenance store
    pure store{fakeMaintenance = handle{deleteVersions = \_ versions -> pure [(v, outcome) | v <- versions]}}

mount :: FakeStore -> [PreparedRule] -> SweepMount
mount store rules = testMount (fakeMaintenance store) rules []

held :: FakeStore -> IO [Version]
held store = maybe [] (map storedVersion) . Map.lookup packageName <$> readFakeContents store

served :: [Text] -> [StoredVersion]
served = map (\raw -> StoredVersion (version raw) VersionServed)

evalContext :: IO EvalContext
evalContext = mkEvalContext (pure epoch) (pure generation)

generation :: Maybe DbEtag
generation = Just (DbEtag "etag-1")

packageName :: PackageName
packageName = mkPackageName Npm Nothing "left-pad"

version :: Text -> Version
version = mkVersion Npm
