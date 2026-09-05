-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Core.Registry.Sweep.WalkSpec (spec) where

import Data.Conduit (ConduitT, yield)
import Test.Hspec

import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.Package (PackageName, mkPackageName)
import Ecluse.Core.Registry.Maintenance (
    NamePrefix,
    StoreFault,
    mkNameAlphabet,
    noNameAlphabet,
    parseNamePrefix,
    protocolFault,
    renderNamePrefix,
 )
import Ecluse.Core.Registry.Sweep.Walk (
    BucketNames (BucketFaulted, BucketOverflowed, BucketRead),
    bucketNameBudget,
    collectBucket,
    resumeAfter,
    walkBuckets,
 )
import Ecluse.Test.Maintenance (withBucket)

spec :: Spec
spec = do
    sequenceSpec
    resumeSpec
    collectSpec

sequenceSpec :: Spec
sequenceSpec = describe "walkBuckets" $ do
    it "covers the alphabet's buckets in order, so a cursor's ordering decides resumption" $
        map renderNamePrefix (walkBuckets (mkNameAlphabet "abc")) `shouldBe` ["a", "b", "c"]

    it "covers a store its listing cannot partition as the one bucket that holds everything" $
        map renderNamePrefix (walkBuckets noNameAlphabet) `shouldBe` [""]

{- A restart re-does at most the bucket that was in flight, so resumption drops every bucket at
or before the one the last run recorded. -}
resumeSpec :: Spec
resumeSpec = describe "resumeAfter" $ do
    it "starts from the first bucket when no walk is under way" $
        map renderNamePrefix (resumeAfter Nothing buckets) `shouldBe` ["a", "b", "c"]

    it "drops the recorded bucket and everything before it" $
        withBucket "b" $ \b ->
            map renderNamePrefix (resumeAfter (Just b) buckets) `shouldBe` ["c"]

    it "has nothing left after the last bucket, which is what ends a walk" $
        withBucket "c" $
            \c -> resumeAfter (Just c) buckets `shouldBe` []

    it "resumes correctly past a split bucket, because the sequence stays ordered" $
        -- "aa" sorts after "a" and before "b", so a walk that split "a" and completed "aa"
        -- resumes at "ab" rather than skipping to the next whole bucket.
        withBucket "aa" $ \aa ->
            map renderNamePrefix (resumeAfter (Just aa) splitBuckets) `shouldBe` ["ab", "b", "c"]
  where
    buckets = walkBuckets (mkNameAlphabet "abc")

    -- The sequence a walk holds after "a" was split, which is what a cursor is read against.
    splitBuckets = spelledBuckets ["a", "aa", "ab", "b", "c"]

collectSpec :: Spec
collectSpec = describe "collectBucket" $ do
    it "reads a bucket whole and sorts it, so the walk's order does not follow the store's" $ do
        outcome <- withBucket "a" $ \a -> collectBucket alphabet a (pagesOf [["apricot", "almond"], ["apple"]])
        namesOf outcome `shouldBe` Just (map name ["almond", "apple", "apricot"])

    it "reads an empty bucket as no names rather than as a fault" $ do
        outcome <- withBucket "z" $ \z -> collectBucket alphabet z (pagesOf [])
        namesOf outcome `shouldBe` Just []

    it "reports the fault a listing stopped on, and nothing it read before it" $ do
        outcome <- withBucket "a" $ \a -> collectBucket alphabet a (faultingAfter [["apple"]])
        case outcome of
            BucketFaulted _ -> pass
            _ -> expectationFailure "expected the bucket to report the listing's fault"

    it "abandons a bucket that outgrew the budget and gives the narrower buckets covering it" $ do
        -- The stream stops as soon as the budget is crossed, so an oversized bucket costs a
        -- partial listing rather than the whole of it.
        outcome <- withBucket "a" $ \a -> collectBucket (mkNameAlphabet "ab") a (pagesOf [oversized])
        case outcome of
            BucketOverflowed narrower -> map renderNamePrefix narrower `shouldBe` ["aa", "ab"]
            _ -> expectationFailure "expected the oversized bucket to be split"

    it "reads a bucket exactly at the budget rather than splitting it" $ do
        outcome <- withBucket "a" $ \a -> collectBucket alphabet a (pagesOf [atBudget])
        fmap length (namesOf outcome) `shouldBe` Just bucketNameBudget
  where
    alphabet = mkNameAlphabet "abcz"
    oversized = [show n | n <- [1 .. bucketNameBudget + 1 :: Int]]
    atBudget = [show n | n <- [1 .. bucketNameBudget :: Int]]

    namesOf = \case
        BucketRead names -> Just names
        _ -> Nothing

-- A listing that yields the given pages and ends cleanly.
pagesOf :: [[Text]] -> ConduitT () [PackageName] IO (Maybe StoreFault)
pagesOf pages = Nothing <$ traverse_ (yield . map name) pages

-- A listing that yields the given pages and then stops on a fault.
faultingAfter :: [[Text]] -> ConduitT () [PackageName] IO (Maybe StoreFault)
faultingAfter pages = do
    traverse_ (yield . map name) pages
    pure (Just (protocolFault "the store stopped answering the listing"))

name :: Text -> PackageName
name = mkPackageName Npm Nothing

-- The buckets those spellings name, through the parser a cursor read uses.
spelledBuckets :: [Text] -> [NamePrefix]
spelledBuckets = mapMaybe (\raw -> parseNamePrefix (mkNameAlphabet (toString raw)) raw)
