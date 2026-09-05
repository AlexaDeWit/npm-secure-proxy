-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Driving the mirror sweep from a spec: recording ports, a mount over a fake store, and the
pacing a case varies one field of. Nothing here decides anything, so a case reads as the store
it seeded and the lines and counts that came back.
-}
module Ecluse.Test.Sweep (
    -- * Recording ports
    RecordedSweep (..),
    recordingPorts,
    recordingPortsUnder,
    deletingReport,
    rehearsingReport,

    -- * What a cycle runs over
    testPacing,
    testMount,
) where

import Data.Time (UTCTime (UTCTime), fromGregorian)

import Ecluse.Core.Cve (DbEtag)
import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.Registry.Adapter (adapterProjectName)
import Ecluse.Core.Registry.Maintenance (StoreMaintenance)
import Ecluse.Core.Registry.Npm.Adapter (npmAdapter)
import Ecluse.Core.Registry.Sweep.Types (
    SweepAudit (SweepAudit, auditError, auditInfo, auditWarn),
    SweepMount (..),
    SweepPacing (SweepPacing, swpChunkPause, swpChunkSize, swpCyclePause, swpDeletionCap, swpShape),
    SweepPorts (SweepPorts, sweepAdvisoryEtag, sweepAudit, sweepDelay, sweepMetrics, sweepNow, sweepReport),
    SweepReport (SweepReport, reportCapHalts, reportOpening, reportRemoval),
    SweepShape (SweepCandidates),
 )
import Ecluse.Core.Rules (PreparedRule)
import Ecluse.Core.Rules.Types (Rule)
import Ecluse.Core.Telemetry.Metrics (SweepResult (SweepDeleted, SweepWouldDelete))
import Ecluse.Core.Telemetry.Record (DredgerMetricsPort (DredgerMetricsPort, dmpSweptVersion))
import Ecluse.Test.Rules (inertRuleDeps)

-- | The ports a case drives the sweep through, beside the readers for what they recorded.
data RecordedSweep = RecordedSweep
    { recPorts :: SweepPorts
    , recInfo :: IO [Text]
    -- ^ The routine lines, oldest first.
    , recErrors :: IO [Text]
    -- ^ The lines an operator must act on, oldest first.
    , recResults :: IO [SweepResult]
    -- ^ Every disposition the sweep counted, in the order it counted them.
    , recWarnings :: IO [Text]
    -- ^ The lines that may clear on their own, oldest first.
    , recDelays :: IO Int
    -- ^ How many times the sweep paused. The pause itself returns at once.
    }

{- | Ports that record instead of waiting: the delay returns immediately, the clock stands still,
and the advisory generation is whatever the case names.
-}
recordingPorts :: Maybe DbEtag -> IO RecordedSweep
recordingPorts = recordingPortsUnder deletingReport

-- | 'recordingPorts' over a chosen report, for a case about a rehearsal's own counters.
recordingPortsUnder :: SweepReport -> Maybe DbEtag -> IO RecordedSweep
recordingPortsUnder report etag = do
    info <- newIORef []
    warnings <- newIORef []
    errors <- newIORef []
    results <- newIORef []
    delays <- newIORef (0 :: Int)
    let push ref line = modifyIORef' ref (line :)
    pure
        RecordedSweep
            { recPorts =
                SweepPorts
                    { sweepNow = pure epoch
                    , sweepAdvisoryEtag = const (pure etag)
                    , sweepDelay = const (modifyIORef' delays (+ 1))
                    , sweepMetrics = DredgerMetricsPort{dmpSweptVersion = push results}
                    , sweepAudit =
                        SweepAudit{auditInfo = push info, auditWarn = push warnings, auditError = push errors}
                    , sweepReport = report
                    }
            , recInfo = reverse <$> readIORef info
            , recWarnings = reverse <$> readIORef warnings
            , recErrors = reverse <$> readIORef errors
            , recResults = reverse <$> readIORef results
            , recDelays = readIORef delays
            }
  where
    -- A fixed instant: no rule a sweep case runs reads the clock for its verdict.
    epoch = UTCTime (fromGregorian 2026 1 1) 0

{- | Pacing wide enough that no case hits a limit it did not set: one chunk, no cap in practice,
and the candidate shape. A case overrides the one field it is about.
-}
testPacing :: SweepPacing
testPacing =
    SweepPacing
        { swpChunkSize = 100
        , swpChunkPause = 1
        , swpCyclePause = 60
        , swpDeletionCap = 1000
        , swpShape = SweepCandidates
        }

{- | An npm mount over a fake store: the rules a case prepared, the configured rules its candidate
set reads, and a belt that shields nothing. Override 'smFirstParty' for a case about the belt.
-}
testMount :: StoreMaintenance -> [PreparedRule] -> [Rule] -> SweepMount
testMount store rules configured =
    SweepMount
        { smEcosystem = Npm
        , smStore = store
        , smRules = rules
        , smConfigured = configured
        , smRuleDeps = inertRuleDeps
        , smProjectName = adapterProjectName npmAdapter
        , smFirstParty = const False
        }

{- | The report a real run carries: a removal counts as a deletion, and reaching the cap stops the
cycle. A case about a rehearsal builds its own through 'Ecluse.Dredger.Plan.sweepReportFor'.
-}
deletingReport :: SweepReport
deletingReport = SweepReport{reportRemoval = SweepDeleted, reportOpening = "deleting ", reportCapHalts = True}

{- | The report a rehearsal carries: a removal counts under its own arm, and the cap only logs, so
the run reports the full reach a real one would have.
-}
rehearsingReport :: SweepReport
rehearsingReport =
    SweepReport{reportRemoval = SweepWouldDelete, reportOpening = "dry run, would delete ", reportCapHalts = False}
