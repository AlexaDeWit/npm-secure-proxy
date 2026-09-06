-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The Dredger's pure decisions over its resolved configuration and its invocation, so
"Ecluse.Dredger" dispatches on their results instead of branching inside 'IO'.
-}
module Ecluse.Dredger.Plan (
    DredgerOptions (..),
    SweepMode (..),
    SweepRepetition (..),
    sweepPacingFor,
    sweepReportFor,
    rehearsedStore,
    waitsForAdvisories,
    advisoryWaitAttempts,
    advisoryPollMicros,
    haltDetail,
) where

import Ecluse.Config (
    AppConfig (cfgDredger),
    DredgerSettings (drgChunkPause, drgChunkSize, drgCyclePause, drgDeletionCap, drgFullWalk),
 )
import Ecluse.Core.Registry.Maintenance (
    StoreCursor (clearCursor, writeCursor),
    StoreMaintenance (deleteVersions, rehearseDelete, storeCursor),
    VersionOutcome (VersionRemoved),
 )
import Ecluse.Core.Registry.Sweep.Types (
    CycleHalt,
    SweepMount (smConfigured),
    SweepPacing (SweepPacing, swpChunkPause, swpChunkSize, swpCyclePause, swpDeletionCap, swpShape),
    SweepReport (SweepReport, reportCapHalts, reportOpening, reportRemoval),
    SweepShape (SweepCandidates, SweepEverything),
    renderCycleHalt,
 )
import Ecluse.Core.Rules.Types (readsAdvisories)
import Ecluse.Core.Supervision (secondsToMicros)
import Ecluse.Core.Telemetry.Metrics (SweepResult (SweepDeleted, SweepWouldDelete))

-- | Whether the run deletes, or rehearses and deletes nothing.
data SweepMode
    = -- | Versions a named decisive deny condemns are deleted.
      SweepDeletes
    | -- | Nothing is deleted, because the store handle carries no real delete.
      SweepRehearses
    deriving stock (Eq, Show)

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

{- | How a run reports what it removed. A rehearsal counts under its own arm and past the cap, so
it reports the full reach a real run would have rather than stopping at the breaker.
-}
sweepReportFor :: SweepMode -> SweepReport
sweepReportFor = \case
    SweepDeletes -> SweepReport{reportRemoval = SweepDeleted, reportOpening = "deleting ", reportCapHalts = True}
    SweepRehearses ->
        SweepReport{reportRemoval = SweepWouldDelete, reportOpening = "dry run, would delete ", reportCapHalts = False}

{- | A store handle with no real delete and no real marker write in it, so the loop cannot delete
because nothing it holds can. The backend's own rehearsal answers where it has one.
-}
rehearsedStore :: StoreMaintenance -> StoreMaintenance
rehearsedStore store =
    store
        { deleteVersions = fromMaybe reportsRemoved (rehearseDelete store)
        , storeCursor = readOnly <$> storeCursor store
        }
  where
    -- A backend with no rehearsal of its own reports what it was handed, which is what the
    -- would-delete count reads and the audit line has already put on record.
    reportsRemoved _ versions = pure [(version, VersionRemoved) | version <- versions]

    readOnly cursor = cursor{writeCursor = const (pure (Right ())), clearCursor = pure (Right ())}

{- | Whether a first cycle waits for the first advisory sync. A rule set with no advisory rule
never needs one, so it starts at once.
-}
waitsForAdvisories :: [SweepMount] -> Bool
waitsForAdvisories = any (any readsAdvisories . smConfigured)

{- | How many times a first cycle checks for the advisory sync before it starts anyway. The bound
is the cycle pause, so waiting never costs more than one cycle's worth of time.
-}
advisoryWaitAttempts :: SweepPacing -> Int
advisoryWaitAttempts pacing = max 1 (secondsToMicros (swpCyclePause pacing) `div` advisoryPollMicros)

-- | How long the first cycle waits between checks for the advisory sync.
advisoryPollMicros :: Int
advisoryPollMicros = 500_000
