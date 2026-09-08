-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT
{-# LANGUAGE OverloadedStrings #-}

{- | Advisory store parsing and object-key regressions.
Bucket prefixes must preserve the artifact filename.
-}
module Ecluse.Config.AdvisoryStoreSpec (spec) where

import Data.Text qualified as T
import Test.Hspec

import Ecluse.Config.AdvisoryStore (
    AdvisoryStoreTarget (..),
    AdvisoryStoreUrl,
    advisoryObjectKey,
    advisoryStoreBucket,
    advisoryStoreTarget,
    advisoryStoreUrlText,
    mkAdvisoryStoreUrl,
 )

-- The key every refusal must name, as the advisories decoder passes it.
storeKey :: Text
storeKey = "advisories.url"

store :: Either Text AdvisoryStoreUrl
store = mkAdvisoryStoreUrl storeKey "s3://my-advisories"

prefixed :: Either Text AdvisoryStoreUrl
prefixed = mkAdvisoryStoreUrl storeKey "s3://my-advisories/ecluse/osv"

-- | A refusal that names the offending key, never the value alone.
refusalNamingKey :: Either Text a -> Bool
refusalNamingKey = either (T.isInfixOf storeKey) (const False)

spec :: Spec
spec = describe "mkAdvisoryStoreUrl" $ do
    describe "derives the store from the scheme" $ do
        it "reads a bare bucket as the whole store" $
            fmap advisoryStoreTarget store `shouldBe` Right (S3Store "my-advisories" Nothing)

        it "reads the path as the key prefix" $
            fmap advisoryStoreTarget prefixed
                `shouldBe` Right (S3Store "my-advisories" (Just "ecluse/osv"))

        it "drops a prefix's surrounding slashes, so the key writes exactly one" $
            fmap advisoryStoreTarget (mkAdvisoryStoreUrl storeKey "s3://my-advisories/ecluse/")
                `shouldBe` Right (S3Store "my-advisories" (Just "ecluse"))

        it "reads a trailing slash alone as no prefix" $
            fmap advisoryStoreTarget (mkAdvisoryStoreUrl storeKey "s3://my-advisories/")
                `shouldBe` Right (S3Store "my-advisories" Nothing)

        it "trims the value and otherwise keeps it as written" $
            fmap advisoryStoreUrlText (mkAdvisoryStoreUrl storeKey "  s3://my-advisories/ecluse  ")
                `shouldBe` Right "s3://my-advisories/ecluse"

    describe "addresses an object the same way for Pilot and the proxy" $ do
        it "writes the bare file name with no prefix" $
            fmap (\u -> (advisoryStoreBucket u, advisoryObjectKey u "npm-osv-schema4.db")) store
                `shouldBe` Right ("my-advisories", "npm-osv-schema4.db")

        it "writes the prefix ahead of the file name" $
            fmap (`advisoryObjectKey` "npm-osv-schema4.db") prefixed
                `shouldBe` Right "ecluse/osv/npm-osv-schema4.db"

    describe "refuses what it cannot dial" $ do
        it "refuses a scheme this build does not know, naming the key" $
            for_ ["gs://my-advisories", "https://my-advisories", "my-advisories", "s3:/my-advisories"] $
                \raw -> mkAdvisoryStoreUrl storeKey raw `shouldSatisfy` refusalNamingKey

        it "refuses credential material, a query, and a fragment" $
            for_ ["s3://user:token@my-advisories", "s3://my-advisories?x=1", "s3://my-advisories#f"] $
                \raw -> mkAdvisoryStoreUrl storeKey raw `shouldSatisfy` refusalNamingKey

        it "refuses a bucket name S3 itself would refuse" $
            for_ ["s3://ab", "s3://My-Advisories", "s3://-advisories", "s3://advisories-", "s3:///prefix"] $
                \raw -> mkAdvisoryStoreUrl storeKey raw `shouldSatisfy` refusalNamingKey

        it "accepts the dotted and hyphenated names an existing bucket may carry" $
            for_ ["s3://my.advisories.example", "s3://a-b-c", "s3://abc"] $
                \raw -> mkAdvisoryStoreUrl storeKey raw `shouldSatisfy` isRight
