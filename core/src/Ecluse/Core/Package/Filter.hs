-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The ecosystem-agnostic filtering /decision/ for a single public-upstream
packument. It says which versions survive a rule set, which version @dist-tags.latest@
resolves to, and the per-version decisions a no-survivors outcome must report.

This mirrors "Ecluse.Core.Package.Merge": the pure fold above the registry handle that
emits a __plan__ rather than a finished document. It reasons over the typed
'Ecluse.Core.Package.PackageInfo' domain model only, and never touches a registry's wire
format. The per-ecosystem adapter __replays__ this plan onto the raw upstream
document, so unmodeled wire keys survive. The typed model is lossy, so re-encoding it
would drop them. See @docs\/architecture\/registry-model.md@ → "Decision surface vs
served surface".

__Decision, not served surface.__ A 'FilterPlan' carries exactly the decisions the
filter owns:

* __Survivors.__ A version key survives iff the rules engine 'Admitted' it. Every
  other verdict drops it: a denial, deny-by-default, or an undecidable outcome.
  Presence in the served packument /is/ availability, so the filter removes a
  non-approved version rather than flagging it.

* __Resolved @latest@.__ The surviving @dist-tags.latest@ under the shared
  __keep-unless-denied, stable-preferring__ rule ('Ecluse.Core.Version.selectLatest').
  The upstream @latest@ stays untouched while it survives. The filter repoints it to
  the highest /stable/ survivor only when the tagged version was itself denied. This is
  the @latest@ /within the public set/, which the cross-upstream merge then re-resolves
  over the union. It is not the final served @latest@.

* __Decisions.__ Every version's 'Decision', in version-key order, so a
  no-survivors outcome can render each denial and choose a status.

The plan deliberately omits any "dropped tags" list. A stale tag is one whose target
did not survive. The survivor set alone drops it __structurally__: a tag survives iff
its target is in 'fpSurvivors'. The replay therefore needs no extra field to find
one. The plan stays minimal: the decisions the filter owns, nothing the replay
can recompute.

This filters a __single public packument__ (the gated set). Combining it with the
trusted /private/ set is the cross-upstream merge ("Ecluse.Core.Package.Merge").

== Served-location enforcement

The module also owns the other ecosystem-agnostic reduction a fetched document needs before
serve: which of a version's artifacts a client may be sent to. It reasons over the domain
model and the agnostic egress and host policies alone, with no wire format in sight, so it is
the projection post-step every ecosystem shares rather than copies. A divergent copy of an
egress-policy application is exactly the drift the policy's correct-by-construction design
exists to prevent.

Two predicates decide one artifact. The __scheme__ normalises against the https-only egress
policy ('Ecluse.Core.Security.Egress.resolveTarballUrl'): an https URL is kept, a same-host
@http@ URL is upgraded, and anything else is dropped. The __authority__ must be honoured for
the origin that served the document ('Ecluse.Core.Security.artifactAuthorityHonoured'), the
same check the download gate applies, so the served listing and the gate agree file by file.

The two run __per artifact__, and a version drops only when no artifact of it survives. A
dropped file records an 'Ecluse.Core.Package.InvalidIndexFile' under its own name, and an
emptied version an 'Ecluse.Core.Package.InvalidVersionManifest' under its version key. An
ecosystem whose version owns one artifact, npm's, therefore only ever records the second.
-}
module Ecluse.Core.Package.Filter (
    -- * Rule-filter plan
    FilterPlan (..),
    filterPlanFromDecisions,
    restrictToSurvivors,

    -- * Served-location enforcement
    enforceArtifactLocations,
    enforceArtifactLocationsOf,
) where

import Data.Aeson (Value (String))
import Data.Map.Strict qualified as Map
import Data.Set qualified as Set
import Data.Text qualified as T

import Ecluse.Core.Package (
    Artifact (artFilename, artUrl),
    InvalidEntry,
    InvalidEntryKind (InvalidIndexFile, InvalidVersionManifest),
    PackageDetails (pkgArtifacts),
    PackageInfo (infoDistTags, infoInvalidEntries, infoVersions),
    mkInvalidEntry,
    pkgVersion,
 )
import Ecluse.Core.Rules.Types (Decision (Admitted))
import Ecluse.Core.Security (AllowedHostPorts, artifactAuthorityHonoured, authorityLabel, hostAddress, hostPortAddress)
import Ecluse.Core.Security.Egress (registryUrlText, resolveTarballUrl)
import Ecluse.Core.Version (Version, renderVersion, selectLatest)

{- | The filtering decisions for one public packument, for the adapter to replay onto the raw
upstream @Value@. It carries only decisions, never a finished, re-serialisable document.
-}
data FilterPlan = FilterPlan
    { fpSurvivors :: Set Text
    {- ^ The surviving version keys (the raw 'Ecluse.Core.Package.infoVersions' keys):
    exactly those the rules engine approved. Empty when no version survived.
    -}
    , fpLatest :: Maybe Version
    {- ^ @dist-tags.latest@ resolved over the survivors: kept while it survives, else repointed
    (stable-preferring) to the highest survivor. Always one of 'fpSurvivors', or 'Nothing'.
    -}
    , fpDecisions :: [Decision]
    {- ^ Every version's 'Decision', admitted ones included, in version-key order so the adapter can
    zip them back onto the same-ordered versions. Feeds the no-survivors status and denial body.
    -}
    }
    deriving stock (Eq, Show)

{- | Build a 'FilterPlan' from per-version 'Decision's already taken. The decision map __must__
cover every version of the packument, because an undecided version does not survive.
A version survives iff its decision is 'Admitted'. Every other verdict drops it, fail-closed.
-}
filterPlanFromDecisions :: Map Text Decision -> PackageInfo -> FilterPlan
filterPlanFromDecisions decisions info =
    FilterPlan
        { fpSurvivors = survivors
        , fpLatest = selectLatest chosen survivingVersions
        , fpDecisions = Map.elems decisions
        }
  where
    -- A version survives only on an explicit approval. Every other outcome drops
    -- it: deny, deny-by-default, undecidable.
    survivors :: Set Text
    survivors = Map.keysSet (Map.filter isApproved decisions)

    isApproved :: Decision -> Bool
    isApproved = \case
        Admitted{} -> True
        _ -> False

    -- The parsed 'Version' a raw key projects to, if present in the packument. It
    -- both maps surviving keys to 'Version's and resolves @latest@.
    versionOf :: Text -> Maybe Version
    versionOf raw = pkgVersion <$> Map.lookup raw (infoVersions info)

    -- The upstream @latest@ tag's target. 'selectLatest' decides survival itself, so this version
    -- need only be present, not surviving.
    chosen :: Maybe Version
    chosen = Map.lookup "latest" (infoDistTags info) >>= versionOf . renderVersion

    -- 'selectLatest'\'s @survivors@: the surviving versions' parsed 'Version's.
    survivingVersions :: [Version]
    survivingVersions = mapMaybe versionOf (Set.toList survivors)

{- | Restrict a 'PackageInfo' to the surviving version keys, pruning @dist-tags@ to targets
that survive. 'Ecluse.Core.Package.Merge.mergePackuments' treats the result as already gated.
-}
restrictToSurvivors :: Set Text -> PackageInfo -> PackageInfo
restrictToSurvivors survivors info =
    info
        { infoVersions = Map.restrictKeys (infoVersions info) survivors
        , infoDistTags = Map.filter ((`Set.member` survivors) . renderVersion) (infoDistTags info)
        }

{- | Reduce a document to the artifact locations a client may be sent to, dropping each
artifact the scheme or the authority refuses and each version left with none.

@ecosystemHosts@ is the ecosystem's own artifact authorities and @upstreamBaseUrl@ the base URL
of the origin that served the document.
-}
enforceArtifactLocations :: AllowedHostPorts -> Text -> PackageInfo -> PackageInfo
enforceArtifactLocations ecosystemHosts upstreamBaseUrl info =
    info{infoVersions = kept, infoInvalidEntries = infoInvalidEntries info <> drops}
  where
    (kept, drops) = Map.foldrWithKey step (Map.empty, []) (infoVersions info)

    step rawVersion details (keptAcc, dropAcc) =
        case partitionArtifacts ecosystemHosts upstreamBaseUrl rawVersion details of
            (Just survivors, fileDrops) -> (Map.insert rawVersion survivors keptAcc, fileDrops <> dropAcc)
            (Nothing, emptied) -> (keptAcc, emptied <> dropAcc)

{- | The single-version form of 'enforceArtifactLocations', for the selective decode path.
'Nothing' means no artifact of the version survived, so the version drops.
-}
enforceArtifactLocationsOf :: AllowedHostPorts -> Text -> PackageDetails -> Maybe PackageDetails
enforceArtifactLocationsOf ecosystemHosts upstreamBaseUrl details =
    fst (partitionArtifacts ecosystemHosts upstreamBaseUrl (renderVersion (pkgVersion details)) details)

{- Partition one version's artifacts into the survivors and the drop records. 'Nothing'
survivors means the version itself drops, recorded once under its version key rather than once
per file, so an emptied version reads as one loss. -}
partitionArtifacts :: AllowedHostPorts -> Text -> Text -> PackageDetails -> (Maybe PackageDetails, [InvalidEntry])
partitionArtifacts ecosystemHosts upstreamBaseUrl rawVersion details =
    case nonEmpty (rights resolved) of
        Just survivors -> (Just details{pkgArtifacts = survivors}, map fileDrop refusals)
        Nothing -> (Nothing, map (versionDrop rawVersion) (take 1 refusals))
  where
    resolved = map (resolveArtifact ecosystemHosts upstreamBaseUrl) (toList (pkgArtifacts details))
    refusals = lefts resolved

{- The reason and the offending URL a refused artifact carries, named so a drop record can
reduce the URL to its authority. -}
data ArtifactRefusal = ArtifactRefusal
    { refusedFile :: Text
    , refusedReason :: Text
    , refusedUrl :: Text
    }

{- Record one dropped file under its own name. 'mkInvalidEntry' recognises a scheme-bearing
string, so the URL is reduced to its authority whatever its spelling. -}
fileDrop :: ArtifactRefusal -> InvalidEntry
fileDrop refusal =
    mkInvalidEntry InvalidIndexFile (refusedFile refusal) (String (authorityLabel (refusedUrl refusal))) (refusedReason refusal)

-- Record a version whose every artifact was refused, keyed by its raw version string.
versionDrop :: Text -> ArtifactRefusal -> InvalidEntry
versionDrop rawVersion refusal =
    mkInvalidEntry InvalidVersionManifest rawVersion (String (authorityLabel (refusedUrl refusal))) (refusedReason refusal)

{- Decide one artifact: normalise its scheme against the egress policy, then check its
authority against the origin that served the document. A non-https upstream is a test or dev
loopback, which the scheme step leaves alone; the authority check still applies, because the
download gate applies it whatever the upstream's scheme. -}
resolveArtifact :: AllowedHostPorts -> Text -> Artifact -> Either ArtifactRefusal Artifact
resolveArtifact ecosystemHosts upstreamBaseUrl art = do
    normalised <- normaliseScheme
    if artifactAuthorityHonoured ecosystemHosts originAuthority (hostPortAddress (artUrl normalised))
        then Right normalised
        else Left (refusal "artifact authority is neither the serving upstream nor a declared artifact host" (artUrl normalised))
  where
    originAuthority = hostPortAddress upstreamBaseUrl

    normaliseScheme = case httpsUpstreamHost upstreamBaseUrl of
        Nothing -> Right art
        Just upstreamHost -> case resolveTarballUrl upstreamHost (artUrl art) of
            Right resolved -> Right art{artUrl = registryUrlText resolved}
            Left reason -> Left (refusal reason (artUrl art))

    refusal reason url = ArtifactRefusal{refusedFile = artFilename art, refusedReason = reason, refusedUrl = url}

-- The bare host of an @https@ upstream base URL, or 'Nothing' for a non-https (test/dev
-- loopback) upstream whose artifact URLs the scheme normalisation leaves untouched.
httpsUpstreamHost :: Text -> Maybe Text
httpsUpstreamHost baseUrl
    | "https://" `T.isPrefixOf` T.toLower baseUrl = Just (hostAddress baseUrl)
    | otherwise = Nothing
