-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Merging several upstream packuments into the one document Écluse serves.

A packument is the /set of available versions/ of a package, and that set is spread
across upstreams. A trusted private upstream holds the vetted set, while a gated public
upstream holds the full history, including versions not yet mirrored.
Serving only the private document would hide those, so Écluse serves their __union__
rather than short-circuiting on a private hit. This module is the pure,
ecosystem-agnostic fold that reasons over that union on the
'Ecluse.Core.Package.PackageInfo' domain model. It lives above the registry handle,
written once and reused by every ecosystem, and it never imports a registry adapter.

__Decision surface, not served surface.__ This module reasons over the /typed/
'PackageInfo' but does __not__ emit a finished, re-serialisable 'PackageInfo'. The
document Écluse serves is the raw upstream document, rebuilt from the winning sources
so that every unmodeled wire key survives. The typed model is lossy, so re-encoding it
would drop those keys. The serve layer holds that raw document opaquely (as a
'Ecluse.Core.Registry.CachedDocument.CachedDoc') and never reads it, because the
rebuild runs through an injected adapter capability. This module therefore emits a
'MergePlan': exactly which versions survive, which input each survivor came from, the
reconciled @dist-tags@\/@time@, and the detected divergences. The serve layer
__replays that plan onto the raw documents__ through the same capability. See
@docs\/architecture\/registry-model.md@ → "Decision surface vs served surface".

The trust split is the __caller's__. It rides on each input as a 'Provenance' tag and
applies /before/ the merge. 'TrustedSource' (private) versions enter as-is.
'GatedSource' (public) versions are the already-rule-filtered set. This module does not
run rules: it reasons over exactly what it is handed (see
@docs\/architecture\/rules-engine.md@ → "Applying verdicts to a packument").

Two things make the merge more than a map union, and both are
__supply-chain signals, not silent reconciliations__:

* __Collision__. When the same version key comes from both a 'TrustedSource' and
  a 'GatedSource', the trusted copy wins, because it is the authority. The plan
  records it as the survivor's winning 'SourceId'.
* __Divergence__. The colliding copies __contradict on a shared integrity algorithm__
  when an algorithm both expose carries /disagreeing/ digests. That is exactly the
  tampering Écluse exists to catch. Copies may expose /different/ algorithm sets without
  contradicting on a shared one, as when one mirror also carries a legacy digest the
  other omits. Those copies describe the same bytes and are __not__ a divergence.
  The trusted copy still wins the merge, and the 'MergePlan' __reports__ a real
  contradiction. Whether to drop the version as well (fail-closed) is a policy decision
  left to the caller, so this module stays pure.

__The merge is a lawful 'Monoid'.__ The fold runs over a 'Merge' accumulator with a
lawful 'Semigroup' \/ 'Monoid'. 'mempty' is the empty merge, the degenerate identity at
zero inputs, and @(<>)@ is the trusted-wins union with order-independent divergence
detection. 'mergePackuments' assigns each input a 'SourceId' by list position,
@foldMap@s the contributions into the accumulator, and projects to a 'MergePlan'. See
the 'Semigroup' instance for the exact law domain (associative and identity,
intentionally __not__ commutative).

See @docs\/architecture\/registry-model.md@ → "Packument merge across upstreams".
-}
module Ecluse.Core.Package.Merge (
    -- * Provenance
    Provenance (..),

    -- * Merging
    SourceId,
    MergePlan (..),
    Divergence (..),
    IntegrityFingerprint,
    integrityHashes,
    mergePackuments,

    -- * Divergence policy (a post-plan projection)
    DivergencePolicy (..),
    parseDivergencePolicy,
    applyDivergencePolicy,

    -- * The merge accumulator
    -- $accumulator
    Merge,
    contribute,
    planFrom,
) where

import Data.Map.Strict qualified as Map
import Data.Set qualified as Set
import Data.Text qualified as T
import Data.Time (UTCTime)
import Data.Universe.Class (Universe (..))
import Data.Universe.Generic (universeGeneric)

import Ecluse.Core.Package (
    Artifact (..),
    Hash,
    HashAlg (SRI),
    PackageDetails (..),
    PackageInfo (..),
    PackageName,
    hashAlg,
    hashValue,
    sriBody,
 )
import Ecluse.Core.Package.Integrity (assertedAlg)
import Ecluse.Core.Version (Version, renderVersion, selectLatest)
import Ecluse.Core.Wire (WireVocab (..), parseWire)

{- | Which upstream a document came from. The caller decides this and applies it before merging.
'Ord' is the trust order: 'TrustedSource' sorts before 'GatedSource', so the smallest wins.
-}
data Provenance
    = {- | A private-upstream document. Its versions are already vetted, so they
      enter the union unfiltered and win any collision.
      -}
      TrustedSource
    | {- | A public-upstream document. Its versions are the set that already
      survived the rules engine. The merge unions them but never re-filters.
      -}
      GatedSource
    deriving stock (Eq, Ord, Show)

{- | The 0-based index of an input to one 'mergePackuments' call. The caller pairs each 'SourceId'
back to the raw @Value@ it passed at that position, which 'Provenance' alone cannot name.
-}
type SourceId = Int

{- | A version key present in more than one source whose copies disagree on a shared algorithm's
digest. The trusted copy wins, and both fingerprints stay so the caller can log, meter, and apply
a 'DivergencePolicy'. The merge surfaces the conflict, never reconciles it silently.
-}
data Divergence = Divergence
    { divVersion :: Text
    {- ^ The raw version-string key the conflict was found at (the
    'Ecluse.Core.Package.infoVersions' key).
    -}
    , divWinning :: IntegrityFingerprint
    -- ^ Integrity of the copy that won the merge (the higher-precedence source).
    , divLosing :: IntegrityFingerprint
    -- ^ Integrity of the copy that lost, kept so the conflict is auditable.
    }
    deriving stock (Eq, Ord, Show)

{- | The decisions a merge reached over several upstream packuments. The serve layer replays the
plan onto the raw upstream @Value@s. It is never a finished, re-serialisable document.
-}
data MergePlan = MergePlan
    { mpName :: PackageName
    {- ^ The package identity, carried from the contributions. A check upstream of the merge drops
    any contribution whose name disagrees, so this is never a substituted or manufactured value.
    -}
    , mpSurvivors :: Map Text SourceId
    {- ^ Each surviving version key mapped to the 'SourceId' of the input that won it. Trusted wins
    a collision. The serve layer takes that version's object from that source's raw @Value@.
    -}
    , mpDistTags :: Map Text Version
    {- ^ @dist-tags@ reconciled over the survivors. 'selectLatest' resolves @latest@, the plan keeps
    every other surviving-target tag, and it drops an absent-target tag.
    -}
    , mpArtifacts :: Map Text (NonEmpty Text)
    {- ^ The file names of each surviving version's artifacts, taken from the candidate that won
    it. An assembly that replays this plan serves exactly these files, so the served listing and
    the download gate agree file by file. A version whose artifact set is a singleton, npm's,
    carries one name.
    -}
    , mpTime :: Map Text UTCTime
    {- ^ The served @time@ map, rebuilt from the survivors. Each version's publish instant comes
    from the same candidate that won its manifest. A winner with no known time contributes no
    entry.
    -}
    , mpDivergences :: Set Divergence
    {- ^ Every distinct same-version integrity conflict: the winner's fingerprint against each
    fingerprint that contradicts it on a shared algorithm. Differing algorithm sets do not count.
    -}
    }
    deriving stock (Eq, Show)

{- | The operator's policy for a version an integrity 'Divergence' was found on
(@ECLUSE_INTEGRITY__DIVERGENCE_POLICY@). Both policies still emit the @WARNING@ log line and the
@ecluse.registry.merge.divergence@ counter. The policy decides only whether the version is withheld.
-}
data DivergencePolicy
    = {- | Serve the trusted (winning) copy and rely on the divergence signal alone (the
      default). The contested version stays in the listing.
      -}
      Warn
    | {- | Withhold every version a divergence was detected on from the served listing: it
      is dropped from the survivors, its @time@ entry removed, and any @dist-tag@
      (including @latest@) that pointed at it dropped. A resolver pinned to that exact
      version then fails to resolve it rather than receive a contested copy.
      -}
      FailClosed
    deriving stock (Eq, Generic, Ord, Show)

instance Universe DivergencePolicy where universe = universeGeneric

instance WireVocab DivergencePolicy where
    wireKind = "divergence policy"
    wireTable =
        (Warn, "warn")
            :| [(FailClosed, "fail-closed")]
    wireAliases = [(FailClosed, "fail_closed"), (FailClosed, "failclosed")]

{- | Parse the @ECLUSE_INTEGRITY__DIVERGENCE_POLICY@ value, tolerating surrounding
whitespace, case, and the underscored and run-together spellings of @fail-closed@.
-}
parseDivergencePolicy :: Text -> Either Text DivergencePolicy
parseDivergencePolicy = parseWire . T.toLower . T.strip

{- | Apply a 'DivergencePolicy' to a finished plan, after the serve layer has logged and metered
its divergences. 'FailClosed' can empty 'mpSurvivors', which the caller treats as no survivors.
-}
applyDivergencePolicy :: DivergencePolicy -> MergePlan -> MergePlan
applyDivergencePolicy Warn plan = plan
applyDivergencePolicy FailClosed plan =
    plan
        { mpSurvivors = Map.withoutKeys (mpSurvivors plan) dropped
        , mpArtifacts = Map.withoutKeys (mpArtifacts plan) dropped
        , mpTime = Map.withoutKeys (mpTime plan) dropped
        , mpDistTags = Map.filter (\target -> not (renderVersion target `Set.member` dropped)) (mpDistTags plan)
        }
  where
    dropped = Set.map divVersion (mpDivergences plan)

{- | An order-independent fingerprint of a version's artifacts: the sorted @(artifact filename,
asserted algorithm, comparable digest body)@ triples. A digest asserting no algorithm keys under
'Nothing', its own bucket. Only a shared file's shared algorithm disagreeing is a divergence.
-}
newtype IntegrityFingerprint = IntegrityFingerprint [(Text, Maybe HashAlg, Text)]
    deriving stock (Eq, Ord, Show)

{- | The sorted @(artifact filename, asserted algorithm, comparable digest body)@ triples, for an
audit trail.
-}
integrityHashes :: IntegrityFingerprint -> [(Text, Maybe HashAlg, Text)]
integrityHashes (IntegrityFingerprint hs) = hs

{- | The resolution order for a contribution: 'TrustedSource' first, then the lower 'SourceId'. A
'SourceId' is unique per input, so the order is strict and total and the minimum is the winner.
-}
rank :: Provenance -> SourceId -> (Provenance, SourceId)
rank prov sid = (prov, sid)

{- | One source's contribution to a single version key: the input that offered it, its integrity
fingerprint, and the typed details it carried. See 'candKey' for what identifies one.
-}
data Candidate = Candidate
    { candProvenance :: Provenance
    , candSourceId :: SourceId
    , candFingerprint :: ~IntegrityFingerprint
    {- ^ Deliberately lazy: the @~@ opts out of StrictData. Candidate ordering compares rank first,
    and ranks are unique, so only a genuinely colliding version key forces a fingerprint.
    -}
    , candDetails :: PackageDetails
    }
    deriving stock (Show)

-- Eq and Ord both go through this key. 'candDetails' is deliberately excluded: a 'SourceId' is
-- unique per call, so two contributions agreeing on rank and integrity are the same candidate.
candKey :: Candidate -> ((Provenance, SourceId), IntegrityFingerprint)
candKey c = (rank (candProvenance c) (candSourceId c), candFingerprint c)

instance Eq Candidate where
    a == b = candKey a == candKey b

instance Ord Candidate where
    compare a b = compare (candKey a) (candKey b)

{- | A value paired with the rank of the source that offered it. 'Ord' compares the rank alone, so
the minimum is the precedence winner and a collision resolves by provenance, not input position.
-}
data Ranked a = Ranked
    { rankedRank :: (Provenance, SourceId)
    , rankedValue :: a
    }
    deriving stock (Eq, Show)

instance (Eq a) => Ord (Ranked a) where
    compare a b = compare (rankedRank a) (rankedRank b)

-- Keeps the higher-precedence (smaller-rank) value. Associative and commutative, so a
-- 'Map.unionWith' over it resolves a key's collision independent of input order.
keepBetter :: Ranked a -> Ranked a -> Ranked a
keepBetter x y = if rankedRank x <= rankedRank y then x else y

{- $accumulator
The merge folds each input's 'contribute' into the lawful 'Merge' 'Monoid', which 'planFrom' then
projects to a 'MergePlan'. 'Merge' is opaque, so a 'SourceId' always names a real input position.
-}

{- | The monoidal accumulator the merge folds into. It leaves every version key's candidates
unresolved, because a pairwise winner decision during the fold is not associative for 3+ copies.
-}
data Merge = Merge
    { mergeCount :: Int
    -- ^ How many inputs this accumulator represents (the next free 'SourceId').
    , mergeVersions :: Map Text (Set Candidate)
    -- ^ Every candidate offered for each version key, unresolved.
    , mergeDistTags :: Map Text (Ranked Version)
    -- ^ The precedence-winning @dist-tags@ target offered for each tag.
    , mergeName :: Maybe PackageName
    {- ^ The package identity. Every contribution carries the same name, because a check upstream
    of the merge validates each one against the requested name. 'Nothing' only for 'mempty'.
    -}
    }
    deriving stock (Eq, Show)

{- | Associative with 'mempty' as identity, and intentionally __not__ commutative: @(<>)@ re-indexes
the right operand's 'SourceId's past the left operand's inputs, so a 'SourceId' keeps naming the
caller's list position. Precedence resolves by provenance, so the survivors do not depend on order.
-}
instance Semigroup Merge where
    a <> b =
        Merge
            { mergeCount = mergeCount a + mergeCount b
            , mergeVersions =
                Map.unionWith Set.union (mergeVersions a) (shiftVersions (mergeVersions b))
            , mergeDistTags =
                Map.unionWith keepBetter (mergeDistTags a) (shiftRanked <$> mergeDistTags b)
            , mergeName = mergeName a <|> mergeName b
            }
      where
        -- Re-index the right operand's SourceIds past the left operand's inputs, so a fold of
        -- single-input contributions lands each at its list index.
        offset = mergeCount a
        shiftVersions = fmap (Set.map shiftCandidate)
        shiftCandidate c = c{candSourceId = candSourceId c + offset}
        shiftRanked (Ranked (prov, sid) v) = Ranked (prov, sid + offset) v

instance Monoid Merge where
    mempty =
        Merge
            { mergeCount = 0
            , mergeVersions = Map.empty
            , mergeDistTags = Map.empty
            , mergeName = Nothing
            }

{- | One input's contribution to the accumulator, at local 'SourceId' @0@. The 'Semigroup' offset
re-indexes it to the input's position when 'mergePackuments' folds over the inputs.
-}
contribute :: Provenance -> PackageInfo -> Merge
contribute prov info =
    Merge
        { mergeCount = 1
        , mergeVersions = Map.map candidateFor (infoVersions info)
        , mergeDistTags = Map.map (Ranked here) (infoDistTags info)
        , mergeName = Just (infoName info)
        }
  where
    -- Local SourceId 0. The Semigroup offset re-indexes it to the input position.
    here = (prov, 0)
    candidateFor details =
        Set.singleton
            Candidate
                { candProvenance = prov
                , candSourceId = 0
                , candFingerprint = fingerprint details
                , candDetails = details
                }

{- | Reason over several upstream packuments, by 'Provenance', and emit the 'MergePlan' the serve
layer replays onto the raw @Value@s. Pure and total. 'TrustedSource' wins a version collision, and
a contradicting copy is recorded as a 'Divergence'. An empty input list yields 'Nothing'.
-}
mergePackuments :: [(Provenance, PackageInfo)] -> Maybe MergePlan
mergePackuments [] = Nothing
mergePackuments inputs = planFrom (foldMap (uncurry contribute) inputs)

{- | Project the resolved 'MergePlan' from a folded 'Merge'. It resolves each version key to its
precedence winner. 'Nothing' only for 'mempty', the empty merge, which has nothing to serve.
-}
planFrom :: Merge -> Maybe MergePlan
planFrom acc = do
    name <- mergeName acc
    pure
        MergePlan
            { mpName = name
            , mpSurvivors = Map.map (candSourceId . winnerOf) (mergeVersions acc)
            , mpArtifacts = Map.map (fmap artFilename . pkgArtifacts . candDetails . winnerOf) (mergeVersions acc)
            , mpDistTags = reconciledTags
            , mpTime = reconciledTimes
            , mpDivergences = divergences
            }
  where
    -- The precedence winner among a key's candidates: the minimum by rank. A key always has at
    -- least one candidate, so 'Set.findMin' is total here.
    winnerOf :: Set Candidate -> Candidate
    winnerOf = Set.findMin

    survives :: Text -> Bool
    survives key = Map.member key (mergeVersions acc)

    -- The surviving version objects (the details that won each key).
    survivingDetails :: [PackageDetails]
    survivingDetails =
        [candDetails (winnerOf cs) | cs <- Map.elems (mergeVersions acc)]

    -- Divergence is a property of the /set/ of distinct fingerprints offered for a key, never
    -- of a pairwise fold step. That keeps it order-independent and associative for 3+ sources.
    divergences :: Set Divergence
    divergences =
        Set.fromList
            [ Divergence{divVersion = key, divWinning = win, divLosing = lose}
            | (key, cs) <- Map.toList (mergeVersions acc)
            , -- A key offered by one source alone cannot diverge, because the winner
            -- never contradicts itself. The guard also keeps the lazy 'candFingerprint'
            -- unforced on the common collision-free merge.
            Set.size cs > 1
            , let win = candFingerprint (winnerOf cs)
            , let distinct = Set.fromList [candFingerprint c | c <- Set.toList cs]
            , lose <- Set.toList distinct
            , contradicts win lose
            ]

    -- The accumulator has already resolved same-tag collisions by provenance, so the carried
    -- tags never depend on the order the caller passed the inputs.
    reconciledTags :: Map Text Version
    reconciledTags =
        let carried = Map.filter (survives . renderVersion) (Map.map rankedValue (mergeDistTags acc))
         in case resolvedLatest of
                Nothing -> Map.delete "latest" carried
                Just v -> Map.insert "latest" v carried

    -- 'selectLatest' owns the keep-or-repoint precedence. The chosen argument is the
    -- provenance-winning source's @latest@, consistent with the version and dist-tag folds.
    resolvedLatest :: Maybe Version
    resolvedLatest =
        selectLatest chosenLatest (map pkgVersion survivingDetails)

    chosenLatest :: Maybe Version
    chosenLatest = rankedValue <$> Map.lookup "latest" (mergeDistTags acc)

    -- Each surviving version's publish instant comes from the /same/ winning candidate whose
    -- manifest is served, so no timestamp comes from another source. A winner with no known
    -- publish time drops out, so this map covers only a subset of the survivors.
    reconciledTimes :: Map Text UTCTime
    reconciledTimes =
        Map.mapMaybe (pkgPublishedAt . candDetails . winnerOf) (mergeVersions acc)

-- Sorted triples make the comparison order-independent across artifacts and hashes. Keying by
-- 'assertedAlg', not the raw wrapper tag, compares what each digest claims about each file.
fingerprint :: PackageDetails -> IntegrityFingerprint
fingerprint =
    IntegrityFingerprint
        . sort
        . concatMap artHashPairs
        . toList
        . pkgArtifacts
  where
    artHashPairs art = [(artFilename art, assertedAlg h, comparableBody h) | h <- artHashes art]

-- Comparing bodies is sound because the encoding is uniform within a shared resolved
-- algorithm: sha1 hex on both sides, sha256/sha512 SRI base64 on both sides.
comparableBody :: Hash -> Text
comparableBody h = case hashAlg h of
    SRI -> sriBody (hashValue h)
    _ -> hashValue h

-- A key present on one side alone never contradicts, because a mirror may add, omit, or
-- recompute a digest or carry a different file set without any byte being substituted. A
-- digest asserting no algorithm ('Nothing') keys apart, so it never compares against a real one.
contradicts :: IntegrityFingerprint -> IntegrityFingerprint -> Bool
contradicts a b =
    or (Map.intersectionWith (/=) (digestsByKey a) (digestsByKey b))
  where
    digestsByKey :: IntegrityFingerprint -> Map (Text, Maybe HashAlg) (Set Text)
    digestsByKey (IntegrityFingerprint triples) =
        Map.fromListWith Set.union [((file, alg), Set.singleton digest) | (file, alg, digest) <- triples]
