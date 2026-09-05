-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Core.Registry.Sweep.TypesSpec (spec) where

import Data.Text qualified as T
import Test.Hspec

import Ecluse.Core.Cve (DbEtag (DbEtag))
import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.Registry.Sweep.Types (
    CycleHalt (HaltConsentWithheld, HaltDeletionCap, HaltStoreFault, HaltStorePreserved),
    SweepTally (SweepTally, tallyDeleted, tallyExamined, tallyGuardSkipped, tallyKept),
    latches,
    renderCycleHalt,
    renderTally,
    sweepDelayMicros,
 )

spec :: Spec
spec = do
    latchSpec
    haltLineSpec
    tallySpec

{- Only the cap latches. Everything else is a condition an operator clears without a restart, so
the next cycle re-reads it and resumes on its own. -}
latchSpec :: Spec
latchSpec = describe "latches" $ do
    it "latches the deletion cap, because a breaker that re-closes itself is not a breaker" $
        latches (HaltDeletionCap 10 10 Nothing) `shouldBe` True

    it "does not latch withheld consent, so restoring the marker resumes the next cycle" $
        latches (HaltConsentWithheld Npm "verdaccio" "set permitDeletion") `shouldBe` False

    it "does not latch a preserved store, so reclassifying it resumes the next cycle" $
        latches (HaltStorePreserved Npm "codeArtifact" "it has an upstream") `shouldBe` False

    it "does not latch a store fault, so the sweep resumes when the store answers" $
        latches (HaltStoreFault Npm "TransportTimeout: no answer") `shouldBe` False

{- An operator running two backends reads which one refused, so the vendor word comes off the
handle's own fact while the surrounding text stays vendor-neutral. -}
haltLineSpec :: Spec
haltLineSpec = describe "renderCycleHalt" $ do
    it "names the backend that withheld consent, beside how to attach it" $ do
        let line = renderCycleHalt (HaltConsentWithheld Npm "verdaccio" "set permitDeletion to true")
        line `shouldSatisfy` T.isInfixOf "verdaccio"
        line `shouldSatisfy` T.isInfixOf "set permitDeletion to true"

    it "names the backend whose store refills itself" $
        renderCycleHalt (HaltStorePreserved Npm "codeArtifact" "it has an upstream")
            `shouldSatisfy` T.isInfixOf "codeArtifact"

    it "names the generation and the count a cap halt reached, and that it needs a restart" $ do
        let line = renderCycleHalt (HaltDeletionCap 100 100 (Just (DbEtag "etag-7")))
        line `shouldSatisfy` T.isInfixOf "etag-7"
        line `shouldSatisfy` T.isInfixOf "100"
        line `shouldSatisfy` T.isInfixOf "restarted deliberately"

    it "reads the generation as none when a cap halt was reached without a database" $
        renderCycleHalt (HaltDeletionCap 5 5 Nothing) `shouldSatisfy` T.isInfixOf "generation none"

    it "carries the store fault through verbatim" $
        renderCycleHalt (HaltStoreFault Npm "TransportTimeout: no answer")
            `shouldSatisfy` T.isInfixOf "TransportTimeout: no answer"

tallySpec :: Spec
tallySpec = describe "the cycle tally" $ do
    it "adds each column of two tallies" $
        renderTally (counted <> counted) `shouldBe` "examined 2, deleted 2, kept 2, guard-skipped 2"

    it "starts at zero in every column" $
        renderTally mempty `shouldBe` "examined 0, deleted 0, kept 0, guard-skipped 0"

    it "converts a pause in seconds to the microseconds a delay primitive takes" $
        sweepDelayMicros 3 `shouldBe` 3_000_000
  where
    counted = SweepTally{tallyExamined = 1, tallyDeleted = 1, tallyKept = 1, tallyGuardSkipped = 1}
