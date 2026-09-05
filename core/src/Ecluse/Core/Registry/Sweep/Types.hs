-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | What one mirror sweep is made of, and how it reports. Every effect the cycle reaches the
running system through arrives here as a value, so the cycle holds no backend branch and a
second backend is one more handle.
-}
module Ecluse.Core.Registry.Sweep.Types (
    -- * What a sweep runs over
    SweepMount (..),
    SweepPacing (..),
    SweepMode (..),
    SweepShape (..),
    SweepPorts (..),
    SweepAudit (..),

    -- * What one cycle did
    SweepTally (..),
    CycleHalt (..),
    CycleOutcome (..),
    latches,
    renderCycleHalt,
    renderTally,
    renderStoreFault,

    -- * The cycle's running state
    SweepState (..),
    newSweepState,
    record,

    -- * Pacing arithmetic
    sweepDelayMicros,
) where

import Data.Time (NominalDiffTime, UTCTime)

import Ecluse.Core.Cve (DbEtag (DbEtag))
import Ecluse.Core.Ecosystem (Ecosystem, ecosystemName)
import Ecluse.Core.Fault (TransportFault (tfCause, tfDetail))
import Ecluse.Core.Package (PackageName)
import Ecluse.Core.Registry.Adapter.Capability (ProjectName)
import Ecluse.Core.Registry.Maintenance (StoreFault (faultTransport), StoreMaintenance)
import Ecluse.Core.Rules (PreparedRule, RuleDeps)
import Ecluse.Core.Rules.Types (Rule)
import Ecluse.Core.Telemetry.Metrics (SweepResult (..))
import Ecluse.Core.Telemetry.Record (DredgerMetricsPort (dmpSweptVersion))

-- | One mount's sweepable store, and everything that decides for it.
data SweepMount = SweepMount
    { smEcosystem :: Ecosystem
    -- ^ The mount's ecosystem, which names it in an audit line.
    , smStore :: StoreMaintenance
    -- ^ The store's maintenance handle. Every backend-varying fact is a value on it.
    , smRules :: [PreparedRule]
    -- ^ The mount's own prepared rule set, the one the serve and ingest gates evaluate.
    , smConfigured :: [Rule]
    {- ^ The same rules as configured values, which a prepared rule no longer carries. The
    candidate set reads the names an identity deny pins out of these.
    -}
    , smRuleDeps :: RuleDeps
    {- ^ The mount's rule dependencies, which the candidate set reads the advisory generation's
    covered names through, under the same bracket a verdict is taken in.
    -}
    , smProjectName :: ProjectName
    -- ^ The ecosystem's own name parser, which both halves of the candidate set are read through.
    , smFirstParty :: PackageName -> Bool
    {- ^ Whether a name belongs to a namespace this deployment owns, the shared predicate
    derived once at the composition root.
    -}
    }

-- | How a sweep paces itself, how much one cycle may delete, and which shape it runs.
data SweepPacing = SweepPacing
    { swpChunkSize :: Int
    -- ^ Candidate packages one chunk examines before the sweep pauses.
    , swpChunkPause :: NominalDiffTime
    -- ^ The wait between chunks, and the wait a fault whose advice names no delay takes.
    , swpCyclePause :: NominalDiffTime
    {- ^ The wait between the end of one cycle and the start of the next, a halted one
    included. The role's own loop applies it, so a cycle is one supervised step.
    -}
    , swpDeletionCap :: Int
    -- ^ Versions one cycle may hand over for deletion before it halts for good.
    , swpShape :: SweepShape
    -- ^ Which names the cycle carries to the rules.
    }
    deriving stock (Eq, Show)

{- | Which names one cycle decides. A full walk is a superset of a candidate cycle, so the
two never run beside each other.
-}
data SweepShape
    = {- | Every store name the advisory database covers or an identity deny pins. It is
      bounded by the listing for store size and by advisory hits for reads.
      -}
      SweepCandidates
    | {- | Every name in the store, bucket by bucket, resuming from the store's own cursor.
      It covers a rule-configuration change, which no candidate set can see.
      -}
      SweepEverything
    deriving stock (Eq, Show)

-- | Whether the sweep deletes, or rehearses and deletes nothing.
data SweepMode
    = -- | Versions a named decisive deny condemns are deleted.
      SweepDeletes
    | -- | Nothing is deleted, and no cursor is written.
      SweepRehearses
    deriving stock (Eq, Show)

{- | Where the sweep reports. The two severities are separate fields rather than a level
argument, so a caller cannot log a halt as routine.
-}
data SweepAudit = SweepAudit
    { auditInfo :: Text -> IO ()
    -- ^ One routine line: a deletion, a rehearsal, a completed cycle.
    , auditError :: Text -> IO ()
    -- ^ One line an operator must act on: a halt, a refused deletion, a store fault.
    }

-- | The effects the sweep reaches the running system through.
data SweepPorts = SweepPorts
    { sweepNow :: IO UTCTime
    -- ^ The clock the rules' evaluation context reads.
    , sweepAdvisoryEtag :: Ecosystem -> IO (Maybe DbEtag)
    -- ^ The active advisory generation for one ecosystem, for the audit line alone.
    , sweepDelay :: NominalDiffTime -> IO ()
    -- ^ The pause, injected so a spec observes pacing without waiting for it.
    , sweepMetrics :: DredgerMetricsPort
    -- ^ Where each version's disposition is counted.
    , sweepAudit :: SweepAudit
    -- ^ Where the sweep's own lines go.
    }

-- | What one cycle did with the versions it examined.
data SweepTally = SweepTally
    { tallyExamined :: Int
    , tallyDeleted :: Int
    , tallyKept :: Int
    , tallyGuardSkipped :: Int
    }
    deriving stock (Eq, Show)

instance Semigroup SweepTally where
    left <> right =
        SweepTally
            { tallyExamined = tallyExamined left + tallyExamined right
            , tallyDeleted = tallyDeleted left + tallyDeleted right
            , tallyKept = tallyKept left + tallyKept right
            , tallyGuardSkipped = tallyGuardSkipped left + tallyGuardSkipped right
            }

instance Monoid SweepTally where
    mempty = SweepTally 0 0 0 0

-- | Why a cycle stopped before it finished.
data CycleHalt
    = -- | The store carries no consent marker, with the backend and its how-to-attach text.
      HaltConsentWithheld Ecosystem Text Text
    | -- | The store refills itself from elsewhere, so deleting from it changes nothing.
      HaltStorePreserved Ecosystem Text Text
    | {- | The cycle reached its deletion cap, carrying the cap, what it handed over, and the
      advisory generation it decided under. It latches: no later cycle runs.
      -}
      HaltDeletionCap Int Int (Maybe DbEtag)
    | -- | A store call produced no answer and its retry advice ran out, carrying the fault.
      HaltStoreFault Ecosystem Text
    deriving stock (Eq, Show)

-- | One cycle's result: what it did, and why it stopped early if it did.
data CycleOutcome = CycleOutcome
    { outcomeHalt :: Maybe CycleHalt
    , outcomeTally :: SweepTally
    }
    deriving stock (Eq, Show)

{- | Whether a halt stops the Dredger for the life of the process. Only the cap does: a
breaker that re-closes itself is not a breaker, and every other halt is a condition an
operator clears without a restart, so the next cycle re-reads it.
-}
latches :: CycleHalt -> Bool
latches = \case
    HaltDeletionCap{} -> True
    HaltConsentWithheld{} -> False
    HaltStorePreserved{} -> False
    HaltStoreFault{} -> False

-- | The operator-facing text of a halt, naming the backend that raised it and what to fix.
renderCycleHalt :: CycleHalt -> Text
renderCycleHalt = \case
    HaltConsentWithheld eco backend descriptor ->
        storeSubject eco backend <> " carries no deletion consent marker: " <> descriptor
    HaltStorePreserved eco backend why ->
        storeSubject eco backend <> " refills itself, so a delete changes nothing: " <> why
    HaltDeletionCap cap issued etag ->
        "the cycle handed over "
            <> show issued
            <> " versions and reached its deletion cap of "
            <> show cap
            <> " under advisory generation "
            <> renderGeneration etag
            <> ", so the Dredger runs no further cycle until it is restarted deliberately"
    HaltStoreFault eco fault ->
        "a call against the " <> ecosystemName eco <> " mirror store produced no answer: " <> fault

-- | The advisory generation an audit line names, or that none was loaded.
renderGeneration :: Maybe DbEtag -> Text
renderGeneration = maybe "none" (\(DbEtag etag) -> etag)

storeSubject :: Ecosystem -> Text -> Text
storeSubject eco backend = "the " <> ecosystemName eco <> " mirror store on " <> backend

-- | One cycle's counts, as its closing line reports them.
renderTally :: SweepTally -> Text
renderTally tally =
    "examined "
        <> show (tallyExamined tally)
        <> ", deleted "
        <> show (tallyDeleted tally)
        <> ", kept "
        <> show (tallyKept tally)
        <> ", guard-skipped "
        <> show (tallyGuardSkipped tally)

-- | A store fault as an operator reads it: the transport's own cause and its bounded detail.
renderStoreFault :: StoreFault -> Text
renderStoreFault fault = show (tfCause transport) <> ": " <> tfDetail transport
  where
    transport = faultTransport fault

{- | The running totals of one cycle. The issued count is what the cycle handed over for
deletion, which is what the cap bounds, and the tally is what the backend then reported.
-}
data SweepState = SweepState
    { stTally :: IORef SweepTally
    , stIssued :: IORef Int
    }

newSweepState :: IO SweepState
newSweepState = SweepState <$> newIORef mempty <*> newIORef 0

-- | Count one version's disposition, in the cycle tally and at the metrics port together.
record :: SweepPorts -> SweepState -> SweepResult -> IO ()
record ports counters result = do
    dmpSweptVersion (sweepMetrics ports) result
    modifyIORef' (stTally counters) (<> tallyOf result)

{- A rehearsed deletion counts under its own metric arm and in the cycle's deleted column, so
one dry run reports the reach a real run would have. -}
tallyOf :: SweepResult -> SweepTally
tallyOf = \case
    SweepExamined -> mempty{tallyExamined = 1}
    SweepDeleted -> mempty{tallyDeleted = 1}
    SweepWouldDelete -> mempty{tallyDeleted = 1}
    SweepKept -> mempty{tallyKept = 1}
    SweepGuardSkipped -> mempty{tallyGuardSkipped = 1}

{- | The pause in microseconds, which is what a delay primitive takes. The config decoder bounds
every pause to a positive number of seconds, so the conversion cannot wrap.
-}
sweepDelayMicros :: NominalDiffTime -> Int
sweepDelayMicros pause = round pause * 1_000_000
