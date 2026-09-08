-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Select names covered by advisories or explicit identity denies.
Other policy changes require a full store walk.
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

{- | Canonical names let the artifact and store use different display spellings.
The ecosystem parser preserves their shared identity.
-}
newtype CandidateSet = CandidateSet (Set PackageName)
    deriving stock (Eq, Show)

{- | Every name the loaded advisory generation covers, plus every name an identity deny pins. Read
it inside the generation's own bracket, so the set and its verdicts come from one generation.
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
