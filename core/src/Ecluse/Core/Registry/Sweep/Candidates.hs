-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The candidate set: the names a default cycle carries to the rules. A mirrored version's
metadata is immutable after publication, so an admitted version becomes a denied one only
through a new or changed advisory, an operator identity deny, or a rule-configuration change.
The first two are local facts, and this module reads them. The third is what the full walk is for.
-}
module Ecluse.Core.Registry.Sweep.Candidates (
    CandidateSet,
    candidateSet,
    identityDenyNames,
    inCandidates,
) where

import Data.Set qualified as Set
import Data.Text qualified as T

import Ecluse.Core.Cve (CveLookup (cveCoveredNames))
import Ecluse.Core.Package (PackageName)
import Ecluse.Core.Registry.Adapter.Capability (ProjectName)
import Ecluse.Core.Rules.Types (Rule (DenyByIdentity))

{- | The names one cycle decides, canonical under the ecosystem's own parser. The advisory
database records OSV's spelling and a store lists the backend's, so both sides are projected
through that one parser before they are compared.
-}
newtype CandidateSet = CandidateSet (Set PackageName)
    deriving stock (Eq, Show)

{- | The names to sweep: every name the loaded advisory generation covers, plus every name an
identity deny pins. Read it inside the generation's own bracket, so the set and the verdicts
taken against it come from one generation.
-}
candidateSet :: ProjectName -> [Rule] -> Maybe CveLookup -> IO CandidateSet
candidateSet project rules mLookup = do
    covered <- maybe (pure []) cveCoveredNames mLookup
    pure (CandidateSet (Set.fromList (mapMaybe project covered <> identityDenyNames project rules)))

{- | The package names a rule set's identity denies pin. A deny spells @name@ or
@name\@version@, and a name may itself carry an @\@@, so the split is at the __last__ one.
-}
identityDenyNames :: ProjectName -> [Rule] -> [PackageName]
identityDenyNames project rules = mapMaybe (project . beforeLastAt) [ident | DenyByIdentity ident <- rules]

{- Everything before the last @, where that leaves anything. A bare name has no @ to split on,
and a bare scoped name's only @ leads it, so both stand whole. -}
beforeLastAt :: Text -> Text
beforeLastAt raw = case T.stripSuffix "@" (fst (T.breakOnEnd "@" raw)) of
    Just name | not (T.null name) -> name
    _ -> raw

-- | Whether a name the store listed is one this cycle decides.
inCandidates :: CandidateSet -> PackageName -> Bool
inCandidates (CandidateSet names) = (`Set.member` names)
