-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Core.Registry.Sweep.TypesSpec (spec) where

import Data.Text qualified as T
import Test.Hspec

import Ecluse.Core.Cve (DbEtag (DbEtag))
import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.Registry.Sweep.Types (
    CycleHalt (HaltBucketUnsplittable, HaltConsentWithheld, HaltDeletionCap, HaltStoreFault, HaltStorePreserved),
    SweepTally (SweepTally, tallyDeleted, tallyExamined, tallyGuardSkipped, tallyKept),
    latches,
    renderCycleHalt,
    renderGeneration,
    renderTally,
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
        latches (HaltStoreFault Npm "verdaccio" "the peer did not answer in time") `shouldBe` False

    it "does not latch an unsplittable bucket, so a store that shrank walks again next cycle" $
        latches (HaltBucketUnsplittable Npm "verdaccio" "abcd") `shouldBe` False

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

    it "names the backend a store fault came from, beside the fault" $ do
        let line = renderCycleHalt (HaltStoreFault Npm "codeArtifact" "the peer did not answer in time")
        line `shouldSatisfy` T.isInfixOf "codeArtifact"
        line `shouldSatisfy` T.isInfixOf "the peer did not answer in time"

    it "names the bucket a walk could not read, and why narrowing did not help" $ do
        let line = renderCycleHalt (HaltBucketUnsplittable Npm "codeArtifact" "abcd")
        line `shouldSatisfy` T.isInfixOf "abcd"
        line `shouldSatisfy` T.isInfixOf "no narrower bucket divides them"

tallySpec :: Spec
tallySpec = describe "the cycle tally" $ do
    it "adds each column of two tallies" $
        renderTally (counted <> counted) `shouldBe` "examined 2, deleted 2, kept 2, guard-skipped 2"

    it "starts at zero in every column" $
        renderTally mempty `shouldBe` "examined 0, deleted 0, kept 0, guard-skipped 0"

    it "reads a generation as none when none was loaded" $
        renderGeneration Nothing `shouldBe` "none"

    it "reads a loaded generation as its own marker" $
        renderGeneration (Just (DbEtag "etag-7")) `shouldBe` "etag-7"
  where
    counted = SweepTally{tallyExamined = 1, tallyDeleted = 1, tallyKept = 1, tallyGuardSkipped = 1}
