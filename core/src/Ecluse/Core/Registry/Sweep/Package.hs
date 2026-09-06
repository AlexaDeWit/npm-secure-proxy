-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | One package, the sweep's work unit. Both cycle shapes decide a version the same way here.

The metadata comes from the store being dredged, never the public upstream: one manifest read per
package, with every stored version projected out of it. A version is deleted only on a named
decisive deny, because deletion is permanent and the store may hold the only surviving copy.

Nothing here knows whether the run deletes: a dry run holds a handle whose delete is a rehearsal.
-}
module Ecluse.Core.Registry.Sweep.Package (
    sweepPackage,
) where

import Ecluse.Core.Cve (DbEtag)
import Ecluse.Core.Package (PackageName, renderPackageName)
import Ecluse.Core.Registry.Maintenance (
    StoreFacts (factDeleteCeiling),
    StoreFault,
    StoreMaintenance (deleteVersions, readStoreManifest, storeFacts),
    StoredVersion (storedPresence, storedVersion),
    VersionOutcome (VersionRefused, VersionRemoved, VersionRemoving, VersionUnreached),
    VersionPresence (VersionServed),
    chunksOfCeiling,
    deleteAll,
    refusalCode,
    refusalDetail,
 )
import Ecluse.Core.Registry.Metadata (Manifest (manifestInfo))
import Ecluse.Core.Registry.Sweep.Types (
    CycleHalt (HaltDeletionCap),
    SweepAudit (auditError, auditInfo),
    SweepMount (smFirstParty, smRules),
    SweepPacing (swpDeletionCap),
    SweepPorts (sweepAudit, sweepReport),
    SweepReport (reportCapHalts, reportOpening, reportRemoval),
    SweepState (stIssued),
    record,
    renderGeneration,
    renderStoreFault,
 )
import Ecluse.Core.Rules (evalRules)
import Ecluse.Core.Rules.Types (Decision (Blocked), EvalContext, Reason)
import Ecluse.Core.Server.Metadata (selectVersion)
import Ecluse.Core.Telemetry.Metrics (SweepResult (SweepExamined, SweepGuardSkipped, SweepKept))
import Ecluse.Core.Version (Version, renderVersion)

{- | Decide one package's stored versions and hand the condemned ones over, yielding the halt the
deletion cap raised. A manifest read that faulted keeps the package rather than halting.
-}
sweepPackage ::
    SweepPacing ->
    SweepPorts ->
    SweepState ->
    SweepMount ->
    StoreMaintenance ->
    EvalContext ->
    Maybe DbEtag ->
    PackageName ->
    [StoredVersion] ->
    IO (Maybe CycleHalt)
sweepPackage pacing ports counters mount store ctx etag name stored
    | smFirstParty mount name = Nothing <$ traverse_ (const (record ports counters SweepGuardSkipped)) served
    | otherwise =
        readStoreManifest store name >>= \case
            Left fault -> Nothing <$ keepUnvettable ports counters name served fault
            Right manifest -> do
                condemned <- catMaybes <$> traverse (decideVersion ports counters mount ctx manifest) served
                disposeOf pacing ports counters store etag name condemned
  where
    served = [storedVersion s | s <- stored, storedPresence s == VersionServed]

{- Nothing about these versions is known, so every one stays. The shared fetch discards the response
status, so a package the store no longer serves arrives here too. -}
keepUnvettable :: SweepPorts -> SweepState -> PackageName -> [Version] -> StoreFault -> IO ()
keepUnvettable ports counters name served fault = do
    auditError
        (sweepAudit ports)
        ( renderPackageName name
            <> ": the store served no metadata this cycle, so its "
            <> show (length served)
            <> " versions cannot be vetted and are kept: "
            <> renderStoreFault fault
        )
    for_ served $ \_ -> record ports counters SweepExamined >> record ports counters SweepKept

{- | One version a named decisive deny condemned, with the rule that named it. Its audit line
and its deletion both read this, so neither can credit a rule the other did not.
-}
data Condemned = Condemned
    { cdVersion :: Version
    , cdRule :: Text
    , cdReason :: Reason
    }

{- Decide one version out of the one manifest and count it. Only a named decisive deny condemns, so
this runs 'evalRules' rather than the wrapper that folds it together with deny-by-default. -}
decideVersion ::
    SweepPorts ->
    SweepState ->
    SweepMount ->
    EvalContext ->
    Manifest ->
    Version ->
    IO (Maybe Condemned)
decideVersion ports counters mount ctx manifest version = do
    record ports counters SweepExamined
    maybe keep condemnation (selectVersion version (manifestInfo manifest))
  where
    keep = record ports counters SweepKept $> Nothing

    condemnation details =
        evalRules ctx (smRules mount) details >>= \case
            Blocked rule reason -> pure (Just Condemned{cdVersion = version, cdRule = rule, cdReason = reason})
            _ -> keep

{- Hand the condemned versions over, up to what the cycle's cap still allows. The cap counts
what was handed over rather than what came back, because the cap bounds destructive calls. -}
disposeOf ::
    SweepPacing ->
    SweepPorts ->
    SweepState ->
    StoreMaintenance ->
    Maybe DbEtag ->
    PackageName ->
    [Condemned] ->
    IO (Maybe CycleHalt)
disposeOf pacing ports counters store etag name condemned
    | null condemned = pure Nothing
    | otherwise = do
        issued <- readIORef (stIssued counters)
        let allowance = max 0 (swpDeletionCap pacing - issued)
            (taken, held) = splitAt (if reportCapHalts (sweepReport ports) then allowance else length condemned) condemned
            reached = issued + length taken
        traverse_ (const (record ports counters SweepGuardSkipped)) held
        unless (null taken) $ do
            traverse_ (announce ports etag name) taken
            writeIORef (stIssued counters) reached
            outcomes <- sendDeletes store name (map cdVersion taken)
            traverse_ (recordOutcome ports counters name) outcomes
        pure (cappedHalt pacing reached etag <$ guard (halts reached))
  where
    -- Reaching the cap latches, whether or not this package had more to hand over.
    halts reached = reportCapHalts (sweepReport ports) && reached >= swpDeletionCap pacing

-- The halt the cap raises, carrying what an operator needs to judge the generation that filled it.
cappedHalt :: SweepPacing -> Int -> Maybe DbEtag -> CycleHalt
cappedHalt pacing = HaltDeletionCap (swpDeletionCap pacing)

{- Every deletion's audit line: the package, the version, the rule that denied it, and the
advisory generation pinned when it was decided. -}
announce :: SweepPorts -> Maybe DbEtag -> PackageName -> Condemned -> IO ()
announce ports etag name condemned =
    auditInfo (sweepAudit ports) $
        reportOpening (sweepReport ports)
            <> renderPackageName name
            <> "@"
            <> renderVersion (cdVersion condemned)
            <> ": blocked by "
            <> cdRule condemned
            <> " ("
            <> cdReason condemned
            <> "); advisory generation "
            <> renderGeneration etag

{- Send the batch through the handle's own splitter. What that handle's delete does is the root's
choice, so a dry run reaches a rehearsal here without this knowing which run it is in. -}
sendDeletes :: StoreMaintenance -> PackageName -> [Version] -> IO [(Version, VersionOutcome)]
sendDeletes store name versions =
    deleteAll (fmap Right . deleteVersions store name) (chunksOfCeiling ceiling' versions)
  where
    ceiling' = factDeleteCeiling (storeFacts store)

{- What the backend reported for one version. A refusal or an unreached call leaves the version
in the store, so it counts as kept and reports for an operator to follow up. -}
recordOutcome :: SweepPorts -> SweepState -> PackageName -> (Version, VersionOutcome) -> IO ()
recordOutcome ports counters name (version, outcome) = case outcome of
    VersionRemoved -> record ports counters removal
    VersionRemoving reference -> do
        -- No backend completes later today. The next cycle's listing shows whether it finished,
        -- and a version still served is decided and deleted again, which is idempotent.
        auditInfo (sweepAudit ports) (subject <> ": the backend is removing it under " <> reference)
        record ports counters removal
    VersionRefused refusal -> do
        auditError
            (sweepAudit ports)
            (subject <> ": the backend refused the delete, " <> refusalCode refusal <> ": " <> refusalDetail refusal)
        record ports counters SweepKept
    VersionUnreached fault -> do
        auditError (sweepAudit ports) (subject <> ": the delete did not reach the backend: " <> renderStoreFault fault)
        record ports counters SweepKept
  where
    subject = renderPackageName name <> "@" <> renderVersion version
    removal = reportRemoval (sweepReport ports)
