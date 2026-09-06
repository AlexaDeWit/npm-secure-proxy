-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Core.CveSpec (spec) where

import Test.Hspec (Spec, describe, it, shouldBe)

import Ecluse.Core.Cve (AdvisoryRange (..), insideAffectedRange, scoreAtLeast)
import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.Osv.Types (UpperBound (..))

-- A builder for an advisory segment, exposing only its bounds.
range :: Maybe Text -> UpperBound -> AdvisoryRange
range intro upper =
    AdvisoryRange
        { arCveId = "GHSA-test"
        , arSeverity = Nothing
        , arIntroduced = intro
        , arUpperBound = upper
        , arEpss = Nothing
        }

-- A builder for an interval closed by an inclusive @last_affected@ bound.
through :: Maybe Text -> Text -> AdvisoryRange
through intro lastAffected = range intro (LastAffected lastAffected)

-- A builder for an exact affected point (introduced == last_affected).
point :: Text -> AdvisoryRange
point v = through (Just v) v

inside :: Text -> AdvisoryRange -> Bool
inside = insideAffectedRange Npm

spec :: Spec
spec = do
    describe "scoreAtLeast" $ do
        it "clears the threshold at or above it, and not below" $ do
            scoreAtLeast 8.0 (Just 9.8) `shouldBe` True
            scoreAtLeast 8.0 (Just 8.0) `shouldBe` True
            scoreAtLeast 8.0 (Just 7.9) `shouldBe` False

        it "counts an absent score as clearing every threshold, the fail-closed direction" $ do
            -- Both deny rules read this: an unscored advisory must not slip a deny gate.
            scoreAtLeast 10.0 Nothing `shouldBe` True
            scoreAtLeast 0.0 Nothing `shouldBe` True

    describe "insideAffectedRange" $ do
        describe "the half-open interval [introduced, fixed)" $ do
            it "contains a version strictly between the bounds" $
                inside "1.5.0" (range (Just "1.0.0") (FixedBefore "2.0.0")) `shouldBe` True

            it "contains the introduced bound itself" $
                inside "1.0.0" (range (Just "1.0.0") (FixedBefore "2.0.0")) `shouldBe` True

            it "excludes a version below the introduced bound" $
                inside "0.9.0" (range (Just "1.0.0") (FixedBefore "2.0.0")) `shouldBe` False

            it "excludes the fixed bound itself (the fix is not affected)" $
                inside "2.0.0" (range (Just "1.0.0") (FixedBefore "2.0.0")) `shouldBe` False

            it "excludes a version above the fixed bound" $
                inside "2.1.0" (range (Just "1.0.0") (FixedBefore "2.0.0")) `shouldBe` False

        describe "open ends" $ do
            it "a missing introduced bound starts the range at the beginning" $
                inside "0.0.1" (range Nothing (FixedBefore "2.0.0")) `shouldBe` True

            it "an unbounded segment never ends the range" $
                inside "99.0.0" (range (Just "1.0.0") Unbounded) `shouldBe` True

        describe "the inclusive last_affected bound [introduced, last_affected]" $ do
            it "contains the last_affected bound itself (unlike a fix)" $
                inside "3.8.8" (through (Just "0") "3.8.8") `shouldBe` True

            it "excludes a version above the last_affected bound" $
                inside "3.9.0" (through (Just "0") "3.8.8") `shouldBe` False

        describe "an exact affected point (introduced == last_affected)" $ do
            it "is affected only at that exact version" $
                inside "1.0.0" (point "1.0.0") `shouldBe` True

            it "excludes any other version, above or below" $ do
                inside "1.0.1" (point "1.0.0") `shouldBe` False
                inside "0.9.9" (point "1.0.0") `shouldBe` False

        describe "fail-closed on unprovable comparisons" $ do
            it "an unparseable introduced bound counts as inside" $
                inside "0.0.1" (range (Just "not-a-version") (FixedBefore "2.0.0")) `shouldBe` True

            it "an unparseable fixed bound counts as inside" $
                inside "99.0.0" (range (Just "1.0.0") (FixedBefore "not-a-version")) `shouldBe` True

            it "an unparseable subject version counts as inside" $
                inside "definitely not semver" (range (Just "1.0.0") (FixedBefore "2.0.0")) `shouldBe` True

            it "answers a decoded \"0\" lower bound exactly as it answers the raw one" $ do
                -- Pilot decodes OSV's "0" lower bound to no lower bound at all. The two
                -- spellings must agree at every version, or the decode would move a verdict.
                let agrees upper v = inside v (range Nothing upper) `shouldBe` inside v (range (Just "0") upper)
                    versions = ["0.0.1", "1.0.0", "99.0.0", "definitely not semver"]
                traverse_ (agrees (FixedBefore "2.0.0")) versions
                traverse_ (agrees (LastAffected "3.8.8")) versions
                traverse_ (agrees Unbounded) versions
