-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The mirror sweep: the Dredger's cycle over every mount's mirror store.

A cycle reads each store's consent and classification, then carries names to the rules one package
at a time. The default shape carries only the candidates a new advisory or an operator identity
deny can have changed. The opt-in full walk carries every name instead, which is what covers a
rule-configuration change, and it resumes from the store's own cursor.

Deletion is permanent, so the belt, the per-cycle cap, and those two reads bound one cycle.
-}
module Ecluse.Core.Registry.Sweep (
    sweepCycle,
    withStoreRetry,
) where

import Data.Conduit (ConduitT, await, fuseBothMaybe, runConduit)

import Ecluse.Core.Cve (DbEtag)
import Ecluse.Core.Ecosystem (ecosystemName)
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
    renderNamePrefix,
 )
import Ecluse.Core.Registry.Sweep.Candidates (CandidateSet, candidateSet, inCandidates)
import Ecluse.Core.Registry.Sweep.Package (sweepPackage)
import Ecluse.Core.Registry.Sweep.Types (
    CycleHalt (HaltBucketUnsplittable, HaltConsentWithheld, HaltStoreFault, HaltStorePreserved),
    CycleOutcome (CycleOutcome, outcomeHalt, outcomeTally),
    SweepAudit (auditError, auditInfo, auditWarn),
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
    BucketNames (BucketFaulted, BucketOverflowed, BucketRead, BucketUnsplittable),
    collectBucket,
    resumeAfter,
    walkBuckets,
 )
import Ecluse.Core.Rules (RuleDeps (rdWithCveLookup))
import Ecluse.Core.Rules.Types (EvalContext, mkEvalContext)

{- | Run one cycle: every mount's store in turn. A halt ends the whole cycle, because every reason
for one is a fact about the deployment rather than about one package.
-}
sweepCycle :: SweepPacing -> SweepPorts -> [SweepMount] -> IO CycleOutcome
sweepCycle pacing ports mounts = do
    counters <- newSweepState
    halt <- stepUntilHalt (sweepMount pacing ports counters) mounts
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

{- One mount: read the consent and the classification, then walk it. Both are read at every cycle
start, because an operator revokes either, and a store can be recreated as a different kind. -}
sweepMount :: SweepPacing -> SweepPorts -> SweepState -> SweepMount -> IO (Maybe CycleHalt)
sweepMount pacing ports counters mount =
    firstHalt
        [ clearedToDelete pacing ports mount
        , walkStore pacing ports counters mount
        ]

{- The two standing permissions a delete needs: the operator's own marker, and whether deleting
from this store destroys anything. Both halts name the backend that raised them. -}
clearedToDelete :: SweepPacing -> SweepPorts -> SweepMount -> IO (Maybe CycleHalt)
clearedToDelete pacing ports mount = do
    consent <- withStoreRetry pacing ports mount (verifyConsent store)
    classified <- withStoreRetry pacing ports mount (classifyStore store)
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
walkStore :: SweepPacing -> SweepPorts -> SweepState -> SweepMount -> IO (Maybe CycleHalt)
walkStore pacing ports counters mount = case swpShape pacing of
    SweepCandidates -> candidateCycle pacing ports counters mount
    SweepEverything -> fullWalk pacing ports counters mount

{- The default shape: every bucket, carrying only the names the advisory database covers or an
identity deny pins. The listing is consumed a page at a time and never held whole. -}
candidateCycle :: SweepPacing -> SweepPorts -> SweepState -> SweepMount -> IO (Maybe CycleHalt)
candidateCycle pacing ports counters mount = do
    reportAdvisoryHalf ports mount
    stepUntilHalt candidateBucket (walkBuckets (alphabetOf mount))
  where
    candidateBucket prefix =
        withCandidates ports mount $ \candidates etag ctx ->
            streamCandidates pacing ports counters mount ctx etag (inCandidates candidates) prefix

{- One bucket's candidates and the generation they came from, in one bracket so both come from the
same database. A generation swapped mid-bucket defers a name it newly covers by one cycle. -}
withCandidates :: SweepPorts -> SweepMount -> (CandidateSet -> Maybe DbEtag -> EvalContext -> IO a) -> IO a
withCandidates ports mount act =
    rdWithCveLookup (smRuleDeps mount) $ \mLookup -> do
        candidates <- candidateSet (smProjectName mount) (smConfigured mount) mLookup
        etag <- sweepAdvisoryEtag ports (smEcosystem mount)
        ctx <- mkEvalContext (sweepNow ports) (pure etag)
        act candidates etag ctx

{- Say once per cycle when no generation is loaded. Only the identity half then sweeps, and every
advisory rule yields cannot-vet under its own alignment, which keeps the version. -}
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

-- The opt-in shape: every name in the store, bucket by bucket, resuming where the last run
-- stopped, and clearing the record when a walk completes so the next cycle starts a fresh one.
fullWalk :: SweepPacing -> SweepPorts -> SweepState -> SweepMount -> IO (Maybe CycleHalt)
fullWalk pacing ports counters mount =
    readWalkCursor pacing ports mount >>= \case
        Left halt -> pure (Just halt)
        Right resume ->
            walkFrom pacing ports counters mount resume (resumeAfter resume (walkBuckets (alphabetOf mount))) >>= \case
                Just halt -> pure (Just halt)
                Nothing -> onCursor pacing ports mount clearCursor

{- Walk the buckets in turn. A split replaces a bucket in place with the narrower ones covering it,
and the record is applied to those too, since the walk may have stopped inside that very split. -}
walkFrom :: SweepPacing -> SweepPorts -> SweepState -> SweepMount -> Maybe NamePrefix -> [NamePrefix] -> IO (Maybe CycleHalt)
walkFrom pacing ports counters mount resume = go
  where
    go [] = pure Nothing
    go (prefix : rest) =
        collectBucket (alphabetOf mount) prefix (listPackagesIn (smStore mount) prefix) >>= \case
            BucketFaulted fault -> pure (Just (storeHalt mount fault))
            BucketUnsplittable -> pure (Just (unsplittableHalt mount prefix))
            BucketOverflowed narrower -> go (resumeAfter resume (toList narrower) <> rest)
            BucketRead names -> sweepBucket prefix names >>= maybe (go rest) (pure . Just)

    -- A completed bucket is recorded before the next one starts, so a restart re-does one bucket.
    sweepBucket prefix names = do
        etag <- sweepAdvisoryEtag ports (smEcosystem mount)
        ctx <- mkEvalContext (sweepNow ports) (pure etag)
        sweepChunks pacing ports counters mount ctx etag names
            >>= maybe (onCursor pacing ports mount (`writeCursor` prefix)) (pure . Just)

{- One bucket's listing, consumed page by page so nothing holds it whole. This cycle's own halt
abandons the stream, and a listing that stopped on a fault halts too. -}
streamCandidates ::
    SweepPacing ->
    SweepPorts ->
    SweepState ->
    SweepMount ->
    EvalContext ->
    Maybe DbEtag ->
    (PackageName -> Bool) ->
    NamePrefix ->
    IO (Maybe CycleHalt)
streamCandidates pacing ports counters mount ctx etag keep prefix =
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
                lift (sweepChunks pacing ports counters mount ctx etag (filter keep page))
                    >>= maybe foldPages (pure . Just)

{- A run of names in chunks, with the pause ahead of every chunk but the first, so the pause falls
between chunks and never after the last one. -}
sweepChunks ::
    SweepPacing ->
    SweepPorts ->
    SweepState ->
    SweepMount ->
    EvalContext ->
    Maybe DbEtag ->
    [PackageName] ->
    IO (Maybe CycleHalt)
sweepChunks pacing ports counters mount ctx etag names =
    stepUntilHalt paced (zip [0 :: Int ..] (chunksOfCeiling (AtMost (swpChunkSize pacing)) names))
  where
    paced (index, chunk) = do
        when (index > 0) (sweepDelay ports (swpChunkPause pacing))
        stepUntilHalt (sweepOne pacing ports counters mount ctx etag) chunk

-- One package: what the store serves for it, then the shared decision step over those versions.
sweepOne ::
    SweepPacing ->
    SweepPorts ->
    SweepState ->
    SweepMount ->
    EvalContext ->
    Maybe DbEtag ->
    PackageName ->
    IO (Maybe CycleHalt)
sweepOne pacing ports counters mount ctx etag name =
    withStoreRetry pacing ports mount (enumerateVersions store name) >>= \case
        Left halt -> pure (Just halt)
        Right stored -> sweepPackage pacing ports counters mount store ctx etag name stored
  where
    store = smStore mount

{- The bucket the last run of this walk completed. A store with nowhere to keep one resumes from
the first bucket every cycle, which is a value here rather than a branch. -}
readWalkCursor :: SweepPacing -> SweepPorts -> SweepMount -> IO (Either CycleHalt (Maybe NamePrefix))
readWalkCursor pacing ports mount = case storeCursor (smStore mount) of
    Nothing -> pure (Right Nothing)
    Just cursor -> withStoreRetry pacing ports mount (readCursor cursor)

-- Run one cursor write, where the store keeps a cursor. A store with nowhere to keep one records
-- nothing, and a dry run holds a cursor whose writes reach no store.
onCursor :: SweepPacing -> SweepPorts -> SweepMount -> (StoreCursor -> IO (Either StoreFault ())) -> IO (Maybe CycleHalt)
onCursor pacing ports mount write =
    maybe (pure Nothing) recorded (storeCursor (smStore mount))
  where
    recorded cursor = leftToMaybe <$> withStoreRetry pacing ports mount (write cursor)

storeHalt :: SweepMount -> StoreFault -> CycleHalt
storeHalt mount fault = HaltStoreFault (smEcosystem mount) (backendOf mount) (renderStoreFault fault)

unsplittableHalt :: SweepMount -> NamePrefix -> CycleHalt
unsplittableHalt mount prefix =
    HaltBucketUnsplittable (smEcosystem mount) (backendOf mount) (renderNamePrefix prefix)

backendOf :: SweepMount -> Text
backendOf = factBackend . storeFacts . smStore

alphabetOf :: SweepMount -> NameAlphabet
alphabetOf = factNameAlphabet . storeFacts . smStore

{- | One store call, retried once after the wait its own fault advises. A fault that survives that
wait halts the cycle, which the next cycle re-attempts after the cycle pause.
-}
withStoreRetry :: SweepPacing -> SweepPorts -> SweepMount -> IO (Either StoreFault a) -> IO (Either CycleHalt a)
withStoreRetry pacing ports mount call =
    call >>= \case
        Right answered -> pure (Right answered)
        Left fault -> case faultRetry fault of
            RetryFutile -> pure (Left (storeHalt mount fault))
            RetryWorthwhile -> again (swpChunkPause pacing) fault
            RetryDelayed (RetryAfter seconds) -> again (fromIntegral seconds) fault
  where
    -- A retry that clears leaves the cycle running, so it warns rather than reporting a fault the
    -- operator has to act on. Only the halt after a failed retry is an error.
    again delay fault = do
        auditWarn
            (sweepAudit ports)
            ( "retrying a call against the "
                <> ecosystemName (smEcosystem mount)
                <> " mirror store on "
                <> backendOf mount
                <> " after "
                <> renderStoreFault fault
            )
        sweepDelay ports delay
        first (storeHalt mount) <$> call
