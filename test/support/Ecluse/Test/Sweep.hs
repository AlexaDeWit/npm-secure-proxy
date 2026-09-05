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
    SweepAudit (SweepAudit, auditError, auditInfo),
    SweepMount (..),
    SweepPacing (SweepPacing, swpChunkPause, swpChunkSize, swpCyclePause, swpDeletionCap, swpShape),
    SweepPorts (SweepPorts, sweepAdvisoryEtag, sweepAudit, sweepDelay, sweepMetrics, sweepNow),
    SweepShape (SweepCandidates),
 )
import Ecluse.Core.Rules (PreparedRule)
import Ecluse.Core.Rules.Types (Rule)
import Ecluse.Core.Telemetry.Metrics (SweepResult)
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
    , recDelays :: IO Int
    -- ^ How many times the sweep paused. The pause itself returns at once.
    }

{- | Ports that record instead of waiting: the delay returns immediately, the clock stands still,
and the advisory generation is whatever the case names.
-}
recordingPorts :: Maybe DbEtag -> IO RecordedSweep
recordingPorts etag = do
    info <- newIORef []
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
                    , sweepAudit = SweepAudit{auditInfo = push info, auditError = push errors}
                    }
            , recInfo = reverse <$> readIORef info
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
