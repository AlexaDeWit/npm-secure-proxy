-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The mirror sweep: the Dredger's cycle over every mount's mirror store.

A cycle reads each store's consent and classification, then carries names to the rules, one
package at a time. The default shape carries only the candidates a new advisory or an operator
identity deny can have changed, so a cycle is bounded by the listing for store size and by
advisory hits for metadata reads. The opt-in full walk carries every name instead, which is what
covers a rule-configuration change, and it resumes from the store's own cursor.

Deletion is permanent, so the first-party belt, the per-cycle cap, and the consent and
classification read at every cycle start bound what one cycle can do.
-}
module Ecluse.Core.Registry.Sweep (
    sweepCycle,
    withStoreRetry,
) where

import Data.Conduit (ConduitT, await, fuseBothMaybe, runConduit)

import Ecluse.Core.Cve (DbEtag)
import Ecluse.Core.Ecosystem (Ecosystem, ecosystemName)
import Ecluse.Core.Fault (RetryAfter (RetryAfter))
import Ecluse.Core.Package (PackageName)
import Ecluse.Core.Registry.Maintenance (
    ConsentVerdict (ConsentGranted, ConsentWithheld),
    DeleteCeiling (AtMost),
    NameAlphabet,
    NamePrefix,
    RetryAdvice (RetryDelayed, RetryFutile, RetryWorthwhile),
    StoreClass (StoreDestroyable, StorePreserved),
    StoreCursor (clearCursor, readCursor, writeCursor),
    StoreFacts (factBackend, factNameAlphabet),
    StoreFault (faultRetry),
    StoreMaintenance (classifyStore, enumerateVersions, listPackagesIn, storeCursor, storeFacts, verifyConsent),
    chunksOfCeiling,
 )
import Ecluse.Core.Registry.Sweep.Candidates (CandidateSet, candidateSet, inCandidates)
import Ecluse.Core.Registry.Sweep.Package (sweepPackage)
import Ecluse.Core.Registry.Sweep.Types (
    CycleHalt (HaltConsentWithheld, HaltStoreFault, HaltStorePreserved),
    CycleOutcome (CycleOutcome, outcomeHalt, outcomeTally),
    SweepAudit (auditError, auditInfo),
    SweepMode (SweepDeletes, SweepRehearses),
    SweepMount (smConfigured, smEcosystem, smProjectName, smRuleDeps, smStore),
    SweepPacing (swpChunkPause, swpChunkSize, swpShape),
    SweepPorts (sweepAdvisoryEtag, sweepAudit, sweepDelay, sweepNow),
    SweepShape (SweepCandidates, SweepEverything),
    SweepState,
    SweepTally,
    newSweepState,
    renderCycleHalt,
    renderStoreFault,
    renderTally,
    stTally,
 )
import Ecluse.Core.Registry.Sweep.Walk (
    BucketNames (BucketFaulted, BucketOverflowed, BucketRead),
    collectBucket,
    resumeAfter,
    walkBuckets,
 )
import Ecluse.Core.Rules (RuleDeps (rdWithCveLookup))
import Ecluse.Core.Rules.Types (EvalContext, mkEvalContext)

{- | Run one cycle: every mount's store in turn. A halt ends the whole cycle, because every
reason for one is a fact about the deployment rather than about one package.
-}
sweepCycle :: SweepMode -> SweepPacing -> SweepPorts -> [SweepMount] -> IO CycleOutcome
sweepCycle mode pacing ports mounts = do
    counters <- newSweepState
    halt <- stepUntilHalt (sweepMount mode pacing ports counters) mounts
    tally <- readIORef (stTally counters)
    reportCycle ports halt tally
    pure CycleOutcome{outcomeHalt = halt, outcomeTally = tally}

-- The closing line of one cycle. A halt is the operator's to act on, a completion is not.
reportCycle :: SweepPorts -> Maybe CycleHalt -> SweepTally -> IO ()
reportCycle ports halt tally = case halt of
    Nothing -> auditInfo (sweepAudit ports) ("mirror sweep cycle complete: " <> renderTally tally)
    Just reason ->
        auditError
            (sweepAudit ports)
            ("mirror sweep cycle halted: " <> renderCycleHalt reason <> "; " <> renderTally tally)

{- Walk the steps until one halts. The mounts, the buckets, and the packages of a chunk all fold
this way, so a halt ends the cycle from wherever it is raised. -}
stepUntilHalt :: (a -> IO (Maybe CycleHalt)) -> [a] -> IO (Maybe CycleHalt)
stepUntilHalt step = go
  where
    go [] = pure Nothing
    go (x : xs) = step x >>= maybe (go xs) (pure . Just)

-- Run the checks in order and stop at the first halt one raises.
firstHalt :: [IO (Maybe CycleHalt)] -> IO (Maybe CycleHalt)
firstHalt = stepUntilHalt id

{- One mount: read the consent and the classification, then walk it. Both reads happen at every
cycle start, because an operator revokes either while the sweep runs, and a store can be
recreated under the same name as a different kind. -}
sweepMount :: SweepMode -> SweepPacing -> SweepPorts -> SweepState -> SweepMount -> IO (Maybe CycleHalt)
sweepMount mode pacing ports counters mount =
    firstHalt
        [ clearedToDelete pacing ports mount
        , walkStore mode pacing ports counters mount
        ]

{- The two standing permissions a delete needs. Consent is the operator's marker on the store,
and the classification is whether deleting from it destroys anything. Both halts name the
backend that raised them, so an operator reads which store refused. -}
clearedToDelete :: SweepPacing -> SweepPorts -> SweepMount -> IO (Maybe CycleHalt)
clearedToDelete pacing ports mount = do
    consent <- withStoreRetry pacing ports eco (verifyConsent store)
    classified <- withStoreRetry pacing ports eco (classifyStore store)
    pure $ case (consent, classified) of
        (Left halt, _) -> Just halt
        (_, Left halt) -> Just halt
        (Right (ConsentWithheld descriptor), _) -> Just (HaltConsentWithheld eco backend descriptor)
        (_, Right (StorePreserved why)) -> Just (HaltStorePreserved eco backend why)
        (Right ConsentGranted, Right StoreDestroyable) -> Nothing
  where
    eco = smEcosystem mount
    store = smStore mount
    backend = factBackend (storeFacts store)

{- Walk this mount's store in the shape the configuration selected. A full walk is a superset of
a candidate cycle, so nothing runs beside it. -}
walkStore :: SweepMode -> SweepPacing -> SweepPorts -> SweepState -> SweepMount -> IO (Maybe CycleHalt)
walkStore mode pacing ports counters mount = case swpShape pacing of
    SweepCandidates -> candidateCycle mode pacing ports counters mount
    SweepEverything -> fullWalk mode pacing ports counters mount

{- The default shape: every bucket, carrying only the names the advisory database covers or an
identity deny pins. The listing is consumed a page at a time and never held whole. -}
candidateCycle :: SweepMode -> SweepPacing -> SweepPorts -> SweepState -> SweepMount -> IO (Maybe CycleHalt)
candidateCycle mode pacing ports counters mount = do
    reportAdvisoryHalf ports mount
    stepUntilHalt candidateBucket (walkBuckets (alphabetOf mount))
  where
    candidateBucket prefix =
        withCandidates ports mount $ \candidates etag ctx ->
            streamCandidates mode pacing ports counters mount ctx etag (inCandidates candidates) prefix

{- One bucket's candidate names and the generation they came from, read in one bracket so the set
and the verdicts taken against it come from the same advisory database. A generation that swaps
mid-bucket defers a name it newly covers to the next cycle. -}
withCandidates :: SweepPorts -> SweepMount -> (CandidateSet -> Maybe DbEtag -> EvalContext -> IO a) -> IO a
withCandidates ports mount act =
    rdWithCveLookup (smRuleDeps mount) $ \mLookup -> do
        candidates <- candidateSet (smProjectName mount) (smConfigured mount) mLookup
        etag <- sweepAdvisoryEtag ports (smEcosystem mount)
        ctx <- mkEvalContext (sweepNow ports) (pure etag)
        act candidates etag ctx

{- Say once per cycle when no advisory generation is loaded. The advisory half of the candidate
set is then empty and only the identity half sweeps; every advisory rule yields cannot-vet under
its own alignment, which keeps the version. -}
reportAdvisoryHalf :: SweepPorts -> SweepMount -> IO ()
reportAdvisoryHalf ports mount =
    rdWithCveLookup (smRuleDeps mount) $ \mLookup ->
        whenNothing_ mLookup $
            auditError
                (sweepAudit ports)
                ( "no advisory database generation is loaded for the "
                    <> ecosystemName (smEcosystem mount)
                    <> " mount, so this cycle sweeps only the names an identity deny pins"
                )

{- The opt-in shape: every name in the store, bucket by bucket, resuming where the last run
stopped. Each completed bucket is recorded, and a completed walk clears the record so the next
cycle starts a fresh one. -}
fullWalk :: SweepMode -> SweepPacing -> SweepPorts -> SweepState -> SweepMount -> IO (Maybe CycleHalt)
fullWalk mode pacing ports counters mount =
    readWalkCursor pacing ports mount >>= \case
        Left halt -> pure (Just halt)
        Right resume ->
            walkFrom (resumeAfter resume (walkBuckets alphabet)) >>= \case
                Just halt -> pure (Just halt)
                Nothing -> onCursor mode pacing ports mount clearCursor
  where
    alphabet = alphabetOf mount

    -- A bucket that outgrew the memory budget is replaced in place by the narrower buckets
    -- covering it, so the sequence stays ordered and the cursor keeps its meaning.
    walkFrom [] = pure Nothing
    walkFrom (prefix : rest) =
        collectBucket alphabet prefix (listPackagesIn (smStore mount) prefix) >>= \case
            BucketFaulted fault -> pure (Just (storeHalt mount fault))
            BucketOverflowed narrower -> walkFrom (narrower <> rest)
            BucketRead names -> sweepBucket names >>= maybe (walkFrom rest) (pure . Just)
      where
        sweepBucket names = do
            etag <- sweepAdvisoryEtag ports (smEcosystem mount)
            ctx <- mkEvalContext (sweepNow ports) (pure etag)
            sweepChunks mode pacing ports counters mount ctx etag names
                >>= maybe (onCursor mode pacing ports mount (`writeCursor` prefix)) (pure . Just)

{- One bucket's listing, consumed page by page so nothing holds it whole. This cycle's own halt
abandons the stream, and a listing that stopped on a fault halts too. -}
streamCandidates ::
    SweepMode ->
    SweepPacing ->
    SweepPorts ->
    SweepState ->
    SweepMount ->
    EvalContext ->
    Maybe DbEtag ->
    (PackageName -> Bool) ->
    NamePrefix ->
    IO (Maybe CycleHalt)
streamCandidates mode pacing ports counters mount ctx etag keep prefix =
    outcome <$> runConduit (fuseBothMaybe (listPackagesIn (smStore mount) prefix) foldPages)
  where
    -- The sweep's own halt is read first: it is the arm that abandoned the stream.
    outcome = \case
        (_, Just halt) -> Just halt
        (Just (Just fault), _) -> Just (storeHalt mount fault)
        _ -> Nothing

    foldPages :: ConduitT [PackageName] o IO (Maybe CycleHalt)
    foldPages =
        await >>= \case
            Nothing -> pure Nothing
            Just page ->
                lift (sweepChunks mode pacing ports counters mount ctx etag (filter keep page))
                    >>= maybe foldPages (pure . Just)

{- A run of names in chunks, with the pause ahead of every chunk but the first, so the pause falls
between chunks and never after the last one. -}
sweepChunks ::
    SweepMode ->
    SweepPacing ->
    SweepPorts ->
    SweepState ->
    SweepMount ->
    EvalContext ->
    Maybe DbEtag ->
    [PackageName] ->
    IO (Maybe CycleHalt)
sweepChunks mode pacing ports counters mount ctx etag names =
    stepUntilHalt paced (zip [0 :: Int ..] (chunksOfCeiling (AtMost (swpChunkSize pacing)) names))
  where
    paced (index, chunk) = do
        when (index > 0) (sweepDelay ports (swpChunkPause pacing))
        stepUntilHalt (sweepOne mode pacing ports counters mount ctx etag) chunk

-- One package: what the store serves for it, then the shared decision step over those versions.
sweepOne ::
    SweepMode ->
    SweepPacing ->
    SweepPorts ->
    SweepState ->
    SweepMount ->
    EvalContext ->
    Maybe DbEtag ->
    PackageName ->
    IO (Maybe CycleHalt)
sweepOne mode pacing ports counters mount ctx etag name =
    withStoreRetry pacing ports (smEcosystem mount) (enumerateVersions store name) >>= \case
        Left halt -> pure (Just halt)
        Right stored -> sweepPackage mode pacing ports counters mount store ctx etag name stored
  where
    store = smStore mount

{- The bucket the last run of this walk completed. A store with nowhere to keep one resumes from
the first bucket every cycle, which is a value here rather than a branch. -}
readWalkCursor :: SweepPacing -> SweepPorts -> SweepMount -> IO (Either CycleHalt (Maybe NamePrefix))
readWalkCursor pacing ports mount = case storeCursor (smStore mount) of
    Nothing -> pure (Right Nothing)
    Just cursor -> withStoreRetry pacing ports (smEcosystem mount) (readCursor cursor)

{- Run one cursor write, where the store keeps a cursor and the run is a real one. A dry run
writes nothing to the store, this included. -}
onCursor :: SweepMode -> SweepPacing -> SweepPorts -> SweepMount -> (StoreCursor -> IO (Either StoreFault ())) -> IO (Maybe CycleHalt)
onCursor mode pacing ports mount write = case (mode, storeCursor (smStore mount)) of
    (SweepRehearses, _) -> pure Nothing
    (_, Nothing) -> pure Nothing
    (SweepDeletes, Just cursor) ->
        leftToMaybe <$> withStoreRetry pacing ports (smEcosystem mount) (write cursor)

storeHalt :: SweepMount -> StoreFault -> CycleHalt
storeHalt mount fault = HaltStoreFault (smEcosystem mount) (renderStoreFault fault)

alphabetOf :: SweepMount -> NameAlphabet
alphabetOf = factNameAlphabet . storeFacts . smStore

{- One store call, retried once after the wait its own fault advises. A fault that survives that
wait halts the cycle, and the cycle pause is the outer backoff a halted cycle waits. -}
withStoreRetry :: SweepPacing -> SweepPorts -> Ecosystem -> IO (Either StoreFault a) -> IO (Either CycleHalt a)
withStoreRetry pacing ports eco call =
    call >>= \case
        Right answered -> pure (Right answered)
        Left fault -> case faultRetry fault of
            RetryFutile -> pure (Left (halted fault))
            RetryWorthwhile -> again (swpChunkPause pacing) fault
            RetryDelayed (RetryAfter seconds) -> again (fromIntegral seconds) fault
  where
    again delay fault = do
        auditError
            (sweepAudit ports)
            ("retrying a " <> ecosystemName eco <> " mirror store call after " <> renderStoreFault fault)
        sweepDelay ports delay
        first halted <$> call

    halted fault = HaltStoreFault eco (renderStoreFault fault)
