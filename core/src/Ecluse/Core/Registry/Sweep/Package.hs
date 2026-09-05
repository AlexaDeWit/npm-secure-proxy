-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | One package, the sweep's work unit. Both cycle shapes reach the rules through here, so a
candidate cycle and a full walk decide a version the same way.

The metadata comes from the store being dredged, never the public upstream: one manifest read
per package, through the ecosystem's own codec, with every stored version projected out of that
one read. A version is deleted only on a named decisive deny. Deny by default, a version the
manifest no longer carries, and a version that could not be vetted all keep, because deletion
is permanent and the store may hold the only surviving copy.
-}
module Ecluse.Core.Registry.Sweep.Package (
    sweepPackage,
) where

import Ecluse.Core.Cve (DbEtag (DbEtag))
import Ecluse.Core.Package (PackageName, renderPackageName)
import Ecluse.Core.Registry.Maintenance (
    StoreFacts (factDeleteCeiling),
    StoreFault,
    StoreMaintenance (deleteVersions, readStoreManifest, rehearseDelete, storeFacts),
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
    SweepMode (SweepDeletes, SweepRehearses),
    SweepMount (smFirstParty, smRules),
    SweepPacing (swpDeletionCap),
    SweepPorts (sweepAudit),
    SweepState (stIssued),
    record,
    renderStoreFault,
 )
import Ecluse.Core.Rules (evalRules)
import Ecluse.Core.Rules.Types (Decision (Blocked), EvalContext, Reason)
import Ecluse.Core.Server.Metadata (selectVersion)
import Ecluse.Core.Telemetry.Metrics (SweepResult (SweepDeleted, SweepExamined, SweepGuardSkipped, SweepKept, SweepWouldDelete))
import Ecluse.Core.Version (Version, renderVersion)

{- | Decide one package's stored versions and hand the condemned ones over. It yields the halt
the deletion cap raised, or nothing. A store fault on the manifest read keeps every version of
the package for this cycle rather than halting, because the next cycle re-reads it.
-}
sweepPackage ::
    SweepMode ->
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
sweepPackage mode pacing ports counters mount store ctx etag name stored
    | smFirstParty mount name = Nothing <$ traverse_ (const (record ports counters SweepGuardSkipped)) served
    | otherwise =
        readStoreManifest store name >>= \case
            Left fault -> Nothing <$ keepUnvettable ports counters name served fault
            Right manifest -> do
                condemned <- catMaybes <$> traverse (decideVersion ports counters mount ctx manifest) served
                disposeOf mode pacing ports counters store etag name condemned
  where
    served = [storedVersion s | s <- stored, storedPresence s == VersionServed]

{- The store answered nothing a manifest could be read from, so nothing about these versions is
known and every one of them stays. The shared fetch discards the response status, so a package
the store no longer serves arrives here too, which keeps it for the same reason. -}
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

{- Decide one version out of the one manifest and count it. A version the manifest no longer
carries keeps, and only a named decisive deny condemns: 'evalRules' rather than the admission
wrapper, because that wrapper folds a decisive deny and deny-by-default into one constructor. -}
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
    SweepMode ->
    SweepPacing ->
    SweepPorts ->
    SweepState ->
    StoreMaintenance ->
    Maybe DbEtag ->
    PackageName ->
    [Condemned] ->
    IO (Maybe CycleHalt)
disposeOf mode pacing ports counters store etag name condemned
    | null condemned = pure Nothing
    | otherwise = do
        issued <- readIORef (stIssued counters)
        let allowance = max 0 (swpDeletionCap pacing - issued)
            (taken, held) = splitAt allowance condemned
        traverse_ (const (record ports counters SweepGuardSkipped)) held
        unless (null taken) $ do
            traverse_ (announce mode ports etag name) taken
            writeIORef (stIssued counters) (issued + length taken)
            outcomes <- sendDeletes mode store name (map cdVersion taken)
            traverse_ (recordOutcome mode ports counters name) outcomes
        pure (cappedHalt pacing (issued + length taken) etag <$ guard (not (null held)))

-- The halt the cap raises, carrying what an operator needs to judge the generation that filled it.
cappedHalt :: SweepPacing -> Int -> Maybe DbEtag -> CycleHalt
cappedHalt pacing = HaltDeletionCap (swpDeletionCap pacing)

{- Every deletion's audit line: the package, the version, the rule that denied it, and the
advisory generation pinned when it was decided. -}
announce :: SweepMode -> SweepPorts -> Maybe DbEtag -> PackageName -> Condemned -> IO ()
announce mode ports etag name condemned =
    auditInfo (sweepAudit ports) $
        opening
            <> renderPackageName name
            <> "@"
            <> renderVersion (cdVersion condemned)
            <> ": blocked by "
            <> cdRule condemned
            <> " ("
            <> cdReason condemned
            <> "); advisory generation "
            <> maybe "none" (\(DbEtag raw) -> raw) etag
  where
    opening = case mode of
        SweepDeletes -> "deleting "
        SweepRehearses -> "dry run, would delete "

{- Send the batch through the handle's own splitter. Under a dry run the handle carries no real
delete at all, so this reaches the backend's rehearsal where it has one and nothing where it
does not, and the announcement above has already put the whole batch on record. -}
sendDeletes :: SweepMode -> StoreMaintenance -> PackageName -> [Version] -> IO [(Version, VersionOutcome)]
sendDeletes mode store name versions = case mode of
    SweepDeletes -> send (deleteVersions store)
    SweepRehearses -> maybe (pure [(version, VersionRemoved) | version <- versions]) send (rehearseDelete store)
  where
    send call = deleteAll (fmap Right . call name) (chunksOfCeiling ceiling' versions)
    ceiling' = factDeleteCeiling (storeFacts store)

{- What the backend reported for one version. A refusal or an unreached call leaves the version
in the store, so it counts as kept and reports for an operator to follow up. -}
recordOutcome :: SweepMode -> SweepPorts -> SweepState -> PackageName -> (Version, VersionOutcome) -> IO ()
recordOutcome mode ports counters name (version, outcome) = case outcome of
    VersionRemoved -> record ports counters (removalResult mode)
    VersionRemoving reference -> do
        -- No backend completes later today. The next cycle's listing shows whether it finished,
        -- and a version still served is decided and deleted again, which is idempotent.
        auditInfo (sweepAudit ports) (subject <> ": the backend is removing it under " <> reference)
        record ports counters (removalResult mode)
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

-- A rehearsal never reports a deletion, so its reach is counted under its own arm.
removalResult :: SweepMode -> SweepResult
removalResult = \case
    SweepDeletes -> SweepDeleted
    SweepRehearses -> SweepWouldDelete
