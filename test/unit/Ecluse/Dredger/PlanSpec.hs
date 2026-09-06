-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Dredger.PlanSpec (spec) where

import Data.Text qualified as T
import Test.Hspec

import Ecluse.Composition.Support (expectConfig, staticEnvVars)
import Ecluse.Config (Config (configApp))
import Ecluse.Core.Registry.Sweep.Types (
    CycleHalt (HaltDeletionCap),
    SweepPacing (swpChunkPause, swpChunkSize, swpCyclePause, swpDeletionCap, swpShape),
    SweepShape (SweepCandidates, SweepEverything),
    deletionCapPerStore,
 )
import Ecluse.Dredger.Plan (haltDetail, sweepPacingFor)

spec :: Spec
spec = do
    pacingSpec
    capSpec
    shapeSpec
    haltSpec

pacingSpec :: Spec
pacingSpec = describe "sweepPacingFor" $ do
    it "carries every shipped default off the dredger group" $ do
        pacing <- pacingUnder []
        (swpChunkSize pacing, swpChunkPause pacing, swpCyclePause pacing) `shouldBe` (50, 2, 3600)

    it "carries an operator's own pacing" $ do
        pacing <- pacingUnder [("ECLUSE_DREDGER__CHUNK_SIZE", "25")]
        swpChunkSize pacing `shouldBe` 25

{- The cap bounds one cycle, and one cycle covers every store in turn, so an unset key is computed
per store rather than pinned to a total the later mounts would never reach. -}
capSpec :: Spec
capSpec = describe "the per-cycle deletion cap" $ do
    it "computes its default from the stores one cycle sweeps" $ do
        (pacing, line) <- resolvedOver 3 []
        swpDeletionCap pacing `shouldBe` 3 * deletionCapPerStore
        line `shouldSatisfy` T.isInfixOf "computed as"

    it "takes an operator's own cap over the computed one" $ do
        (pacing, line) <- resolvedOver 3 [("ECLUSE_DREDGER__DELETION_CAP", "10")]
        swpDeletionCap pacing `shouldBe` 10
        line `shouldSatisfy` T.isInfixOf "from config"

{- The full walk is opt-in, and while it is on it replaces the candidate cycle rather than running
beside it, because a walk is a superset of a candidate cycle. -}
shapeSpec :: Spec
shapeSpec = describe "the cycle's shape" $ do
    it "runs the candidate cycle by default" $ do
        pacing <- pacingUnder []
        swpShape pacing `shouldBe` SweepCandidates

    it "runs the full walk when the operator turns it on" $ do
        pacing <- pacingUnder [("ECLUSE_DREDGER__FULL_WALK", "true")]
        swpShape pacing `shouldBe` SweepEverything

{- A one-shot run reports why it halted on the ending itself, so a scheduler reads the outcome from
the exit status and the reason from the same line. -}
haltSpec :: Spec
haltSpec = describe "haltDetail" $ do
    it "carries the halt's own text onto the ending a one-shot run exits with" $ do
        let detail = haltDetail (HaltDeletionCap 10 10 Nothing)
        detail `shouldSatisfy` T.isInfixOf "the mirror sweep cycle halted"
        detail `shouldSatisfy` T.isInfixOf "deletion cap of 10"

-- The shipped defaults over one sweepable store, plus whatever the case layers over them.
pacingUnder :: [(String, String)] -> IO SweepPacing
pacingUnder = fmap fst . resolvedOver 1

-- The pacing and the boot line naming where the cap came from, over a chosen store count.
resolvedOver :: Int -> [(String, String)] -> IO (SweepPacing, Text)
resolvedOver stores overrides =
    flip sweepPacingFor stores . configApp <$> expectConfig (staticEnvVars <> overrides) Nothing
