-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The advisory lookup capability: answer CVE questions about a package version
from a local, already-synced @osv.db@ artifact, never from the network.

The handle is deliberately dumb data access over one artifact file. Rule semantics
live in pure predicates over what it returns ('insideAffectedRange'), because
SQLite's text collation cannot order versions. Only
'Ecluse.Core.Version.compareVersions' can. The one deliberate exception is
'cveRemediationProbe'. A fixed bound in the artifact is a single canonical version
string. Exact-fix matching is therefore plain string equality, and it rides the
@(package_name, fixed_version)@ index in one traversal. A fix published under a
non-canonical version string misses the probe and waits out the ordinary quarantine.
The operator workaround is an explicit 'Ecluse.Core.Rules.Types.AllowByIdentity'
rule.

'openCveDb' accepts or rejects an artifact on its epoch stamp, integrity,
strict-schema conformance, and ecosystem. Rejection is a value: the caller keeps its
last known-good handle and alarms. See "Ecluse.Core.Cve.Internal" for the hardening
detail.

__Ownership is split at the type level__: 'openCveDb' yields a 'CveDb', the owning
resource whose holder alone may 'cveDbClose'. A consumer gets only its 'CveLookup'
view, so nothing that evaluates rules can release a shared connection. The owner
holds the 'CveDb' and closes it explicitly. That owner is the background sync's
shadow-swap, which retires an artifact only when no evaluation still reads it.
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

{- | The read-only advisory view a rule evaluation gets, keyed by the OSV wire
vocabulary: package name with scope inline (@\@scope\/name@) and verbatim version text.
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

{- | A query the accepted advisory database could not answer. Acceptance made every row
decode total, so it marks an infrastructural fault. Only 'Ecluse.Core.Rules.runEffectfulRule'
catches it, resolving it to an @Unavailable@ evaluation that advances the rule's breaker.
-}
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

{- | Open an @osv.db@ artifact and build the owning handle over it, or reject it
('CveDbRejected'). Nothing an artifact carries can make this throw, and a rejection or a
throw below the artifact contract, such as an unopenable file, leaves the connection closed.
-}
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
version ordering? __Fail-closed:__ an unprovable comparison, from an unparseable bound or
version, counts as __inside__, so a range with an endpoint the grammar rejects covers every
version of its package. The one exception is a segment naming a single unorderable version
('unorderablePoint'), which nothing can order and which therefore matches only itself.
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

{- | The single version a segment names, when it names one that no ordering can place: both
bounds are the same text and the grammar rejects it. OSV writes an exactly enumerated version
this way, so the affected set is that literal string. A parseable point keeps the comparison,
which admits the equal version through the ordinary inclusive bounds.
-}
unorderablePoint :: Ecosystem -> AdvisoryRange -> Maybe Text
unorderablePoint eco ar = case (arIntroduced ar, arUpperBound ar) of
    (Just introduced, LastAffected lastAffected)
        | introduced == lastAffected
        , isLeft (parseVersionKey eco introduced) ->
            Just introduced
    _ -> Nothing

{- | Does this segment's score, a CVSS base score or an EPSS probability, meet the deny
threshold? __Fail-closed:__ an absent score ('Nothing') meets every threshold, because an
unprovable score must not open a deny gate.
-}
scoreAtLeast :: Double -> Maybe Double -> Bool
scoreAtLeast threshold = maybe True (>= threshold)
