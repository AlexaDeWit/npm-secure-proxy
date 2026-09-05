-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The Dredger's pure decisions over its resolved configuration and its invocation, so
"Ecluse.Dredger" dispatches on their results instead of branching inside 'IO'.
-}
module Ecluse.Dredger.Plan (
    DredgerOptions (..),
    SweepRepetition (..),
    sweepPacingFor,
    haltDetail,
) where

import Ecluse.Config (
    AppConfig (cfgDredger),
    DredgerSettings (drgChunkPause, drgChunkSize, drgCyclePause, drgDeletionCap, drgFullWalk),
 )
import Ecluse.Core.Registry.Sweep.Types (
    CycleHalt,
    SweepMode,
    SweepPacing (SweepPacing, swpChunkPause, swpChunkSize, swpCyclePause, swpDeletionCap, swpShape),
    SweepShape (SweepCandidates, SweepEverything),
    renderCycleHalt,
 )

-- | Whether the role cycles for the life of the process, or runs one cycle and exits.
data SweepRepetition
    = -- | Cycle, pause, cycle again, under supervision. The shipped invocation.
      SweepContinuously
    | -- | One cycle, then exit with what that cycle did. @--once@, which the harness drives.
      SweepOnce
    deriving stock (Eq, Show)

-- | What @ecluse dredger@'s own flags settled, carried from the command line to the sweep.
data DredgerOptions = DredgerOptions
    { doMode :: SweepMode
    -- ^ Whether the sweep deletes (@--dry-run@ rehearses instead).
    , doRepetition :: SweepRepetition
    -- ^ Whether it cycles for the life of the process (@--once@ runs one cycle).
    }
    deriving stock (Eq, Show)

-- | The pacing, the per-cycle cap, and the shape the @dredger@ configuration group settled.
sweepPacingFor :: AppConfig -> SweepPacing
sweepPacingFor appConfig =
    SweepPacing
        { swpChunkSize = drgChunkSize dredger
        , swpChunkPause = drgChunkPause dredger
        , swpCyclePause = drgCyclePause dredger
        , swpDeletionCap = drgDeletionCap dredger
        , swpShape = if drgFullWalk dredger then SweepEverything else SweepCandidates
        }
  where
    dredger = cfgDredger appConfig

{- | The detail a halted one-shot run reports as its own non-zero ending, so a scheduler reads
the outcome from the status and the reason from the same line.
-}
haltDetail :: CycleHalt -> Text
haltDetail halt = "the mirror sweep cycle halted: " <> renderCycleHalt halt
