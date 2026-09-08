-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Read one synced advisory artifact through a pinned lookup capability.
Package keys are canonical per ecosystem. Fix versions match raw text exactly.
-}
module Ecluse.Core.Cve (
    -- * The owning resource
    CveDb (..),
    openCveDb,

    -- * The consumer view
    CveLookup (..),

    -- * What a lookup returns
    AdvisoryRange (..),

    -- * Rejection
    CveDbRejected (..),

    -- * Query faults
    CveQueryFault (..),

    -- * Artifact identity
    DbEtag (..),

    -- * Pure range matching
    insideAffectedRange,
    scoreAtLeast,
) where

import UnliftIO.Exception (catch, catchAny, onException, throwIO)

import Ecluse.Core.Cve.Internal (AdvisoryRange (..), CveDbRejected (..), advisoriesQuery, coveredNamesQuery, openHardenedConnection, probeQuery, provenanceQuery)
import Ecluse.Core.Ecosystem (Ecosystem)
import Ecluse.Core.Osv.Types (UpperBound (..))
import Ecluse.Core.Version (compareVersions, mkVersion, parseVersionKey)

import Database.SQLite.Simple (Connection, SQLError, close)

{- | An artifact version marker: S3's ETag, opaque text compared for equality only.
Two objects with equal ETags carry equal bytes, so an unchanged ETag means nothing to do.
-}
newtype DbEtag = DbEtag Text
    deriving stock (Eq, Show)

{- | Query canonical package keys, with npm scopes inline, and raw version strings.
Display names must not be used as query keys.
-}
data CveLookup = CveLookup
    { cveRemediationProbe :: Text -> Text -> IO Bool
    {- ^ Does any advisory for this package name carry this exact version string as a fixed
    bound? Throws the confined 'CveQueryFault' on a query fault.
    -}
    , cveAdvisoriesFor :: Text -> IO [AdvisoryRange]
    {- ^ Every advisory range recorded against a package name. Rule predicates
    interpret them. A query fault throws the confined 'CveQueryFault'.
    -}
    , cveCoveredNames :: IO [Text]
    {- ^ Every package name this generation records an advisory against. A store sweep
    intersects it with the store's listing. Throws the confined 'CveQueryFault' on a fault.
    -}
    }

-- | A database query fault for the rule's resilience policy to classify.
data CveQueryFault = CveQueryFault
    { cqfQuery :: Text
    -- ^ Which handle field was asked (@remediation-probe@ or @advisories-for@).
    , cqfDetail :: Text
    -- ^ The rendered 'SQLError', for the harness's log line. Never parsed.
    }
    deriving stock (Eq, Show)

instance Exception CveQueryFault

{- | One opened artifact: the consumer view plus the owner's close. Whoever holds
this owns the connection's lifetime. Hand a consumer 'cveDbLookup' only.
-}
data CveDb = CveDb
    { cveDbLookup :: CveLookup
    -- ^ The view consumers query through.
    , cveDbClose :: IO ()
    {- ^ Release the artifact's connection. Owner-only: nothing may read through this
    handle's view afterwards. __Never throws__, since the connection is going away either way.
    -}
    , cveDbMeta :: [(Text, Text)]
    {- ^ The artifact's @meta@ provenance rows (Pilot version, ecosystem, build timestamp,
    source URL, row count), snapshotted at open and key-sorted for the audit trail.
    -}
    }

-- | Reject incompatible artifacts as values. Opening faults leave no connection behind.
openCveDb :: Ecosystem -> FilePath -> IO (Either CveDbRejected CveDb)
openCveDb eco dbFile =
    openHardenedConnection eco dbFile >>= \case
        Left rejection -> pure (Left rejection)
        Right conn -> do
            -- No-leak backstop for a fault below the artifact contract. Acceptance already made the
            -- provenance decode itself total.
            meta <- provenanceQuery conn `onException` close conn
            pure (Right (mkCveDb conn meta))

mkCveDb :: Connection -> [(Text, Text)] -> CveDb
mkCveDb conn meta =
    CveDb
        { cveDbLookup =
            CveLookup
                { cveRemediationProbe = \name version -> taggedQuery "remediation-probe" (probeQuery conn name version)
                , cveAdvisoriesFor = taggedQuery "advisories-for" . advisoriesQuery conn
                , cveCoveredNames = taggedQuery "covered-names" (coveredNamesQuery conn)
                }
        , -- Total by construction: the connection is going away either way (see
          -- 'cveDbClose').
          cveDbClose = close conn `catchAny` const pass
        , cveDbMeta = meta
        }

-- The SQLite edge: the driver's 'SQLError' never escapes the handle, only this module's
-- confined 'CveQueryFault'.
taggedQuery :: Text -> IO a -> IO a
taggedQuery tag act = act `catch` \(err :: SQLError) -> throwIO (CveQueryFault tag (show err))

{- | Is this version inside the advisory segment's affected interval, under the ecosystem's
ordering? __Fail-closed:__ an unprovable comparison counts as __inside__, bar an 'unorderablePoint'.
-}
insideAffectedRange :: Ecosystem -> Text -> AdvisoryRange -> Bool
insideAffectedRange eco versionText ar = case unorderablePoint eco ar of
    Just only -> versionText == only
    Nothing -> atOrAboveIntroduced && withinUpperBound
  where
    v = mkVersion eco versionText

    atOrAboveIntroduced = case arIntroduced ar of
        -- No introduced bound: the range starts at the beginning.
        Nothing -> True
        Just i -> case compareVersions v (mkVersion eco i) of
            Just LT -> False
            Just _ -> True
            Nothing -> True

    withinUpperBound = case arUpperBound ar of
        -- A fix is an exclusive upper bound: affected while v < fixed.
        FixedBefore f -> case compareVersions v (mkVersion eco f) of
            Just LT -> True
            Just _ -> False
            Nothing -> True
        -- last_affected is an inclusive upper bound: affected while v <= it.
        LastAffected la -> case compareVersions v (mkVersion eco la) of
            Just GT -> False
            Just _ -> True
            Nothing -> True
        -- No upper bound: the range never ends.
        Unbounded -> True

-- OSV writes an enumerated version as introduced == last_affected. When the grammar rejects that
-- string, the segment names it literally, since nothing can order it against anything.
unorderablePoint :: Ecosystem -> AdvisoryRange -> Maybe Text
unorderablePoint eco ar = case (arIntroduced ar, arUpperBound ar) of
    (Just introduced, LastAffected lastAffected)
        | introduced == lastAffected
        , isLeft (parseVersionKey eco introduced) ->
            Just introduced
    _ -> Nothing

-- | Missing scores satisfy every deny threshold, so absent evidence cannot open the gate.
scoreAtLeast :: Double -> Maybe Double -> Bool
scoreAtLeast threshold = maybe True (>= threshold)
