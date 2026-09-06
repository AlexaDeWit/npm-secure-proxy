-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Core.Registry.Sweep.CandidatesSpec (spec) where

import Test.Hspec

import Ecluse.Core.Cve (AdvisoryRange (..), CveLookup)
import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.Osv.Types (UpperBound (FixedBefore))
import Ecluse.Core.Package (PackageName, mkPackageName, mkScope)
import Ecluse.Core.Registry.Adapter (ProjectName, adapterProjectName)
import Ecluse.Core.Registry.Npm.Adapter (npmAdapter)
import Ecluse.Core.Registry.Sweep.Candidates (candidateSet, identityDenyNames, inCandidates)
import Ecluse.Core.Rules.Types (
    DenyIfCveParams (DenyIfCveParams, dicMinCvss, dicOnUnavailable),
    FailureAlignment (FailDeny),
    Rule (AllowByIdentity, DenyByIdentity, DenyIfCve, DenyInstallTimeExecution),
 )
import Ecluse.Test.Cve (fakeCveLookup)

spec :: Spec
spec = do
    identitySpec
    intersectionSpec

{- An identity deny spells a name, or a name and a version joined by @. A scoped npm name leads
with an @ of its own, so the split has to be at the last one and never the first. -}
identitySpec :: Spec
identitySpec = describe "identityDenyNames" $ do
    it "reads a bare name whole" $
        denied [DenyByIdentity "left-pad"] `shouldBe` [unscoped "left-pad"]

    it "drops the version from a name@version deny" $
        denied [DenyByIdentity "left-pad@1.3.0"] `shouldBe` [unscoped "left-pad"]

    it "splits a scoped name at the last @, keeping the namespace" $
        denied [DenyByIdentity "@babel/core@7.0.0"] `shouldBe` [scoped "babel" "core"]

    it "reads a bare scoped name whole, because its only @ leads it" $
        denied [DenyByIdentity "@babel/core"] `shouldBe` [scoped "babel" "core"]

    it "reads no name from a deny the ecosystem's grammar refuses" $
        denied [DenyByIdentity "NOT A NAME@1.0.0"] `shouldBe` []

    it "reads only the denies, never an allow or a rule that names no identity" $
        denied [AllowByIdentity "left-pad", DenyInstallTimeExecution] `shouldBe` []

{- The advisory database records OSV's spelling and a store lists the backend's, so both sides go
through the ecosystem's own parser before they are compared. -}
intersectionSpec :: Spec
intersectionSpec = describe "candidateSet" $ do
    it "carries every name the loaded generation covers" $ do
        candidates <- candidateSet project [] (Just (coveringLookup ["left-pad", "@babel/core"]))
        map (inCandidates candidates) [unscoped "left-pad", scoped "babel" "core"] `shouldBe` [True, True]

    it "carries a name no advisory covers only when a deny pins it" $ do
        candidates <- candidateSet project [DenyByIdentity "lodash@4.17.0"] (Just (coveringLookup ["left-pad"]))
        map (inCandidates candidates) [unscoped "lodash", unscoped "underscore"] `shouldBe` [True, False]

    it "intersects a differently spelled advisory name, because both sides are canonicalised" $ do
        -- OSV records a scoped name inline and a store lists it the same way, but the parser is
        -- what makes the two one value, so a spelling difference cannot miss a hit.
        candidates <- candidateSet project [] (Just (coveringLookup ["@babel/core"]))
        inCandidates candidates (scoped "babel" "core") `shouldBe` True

    it "reads no name from an advisory spelling the ecosystem's grammar refuses" $ do
        candidates <- candidateSet project [] (Just (coveringLookup ["NOT A NAME"]))
        inCandidates candidates (unscoped "left-pad") `shouldBe` False

    it "sweeps the identity half alone when no generation is loaded" $ do
        -- The advisory half is empty and the identity half still sweeps, so an unavailable
        -- database narrows the cycle rather than stopping it.
        candidates <- candidateSet project [DenyByIdentity "left-pad", advisoryRule] Nothing
        map (inCandidates candidates) [unscoped "left-pad", unscoped "lodash"] `shouldBe` [True, False]

denied :: [Rule] -> [PackageName]
denied = identityDenyNames project

project :: ProjectName
project = adapterProjectName npmAdapter

-- A lookup whose generation covers exactly the given names.
coveringLookup :: [Text] -> CveLookup
coveringLookup names = fakeCveLookup [(name, range) | name <- names]
  where
    range =
        AdvisoryRange
            { arCveId = "CVE-2026-0001"
            , arSeverity = Just 9.8
            , arIntroduced = Nothing
            , arUpperBound = FixedBefore "2.0.0"
            , arEpss = Nothing
            }

advisoryRule :: Rule
advisoryRule = DenyIfCve DenyIfCveParams{dicMinCvss = 7, dicOnUnavailable = FailDeny}

unscoped :: Text -> PackageName
unscoped = mkPackageName Npm Nothing

scoped :: Text -> Text -> PackageName
scoped namespace = mkPackageName Npm (Just (mkScope namespace))
