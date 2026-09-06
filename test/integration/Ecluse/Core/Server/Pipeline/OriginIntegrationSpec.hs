-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Core.Server.Pipeline.OriginIntegrationSpec (spec) where

import Data.Aeson (Value (String))
import Ecluse.Server.Pipeline.TestSupport
import Ecluse.Test.Wai
import Network.Wai (requestHeaders)
import Network.Wai.Test (simpleBody)
import Test.Hspec

spec :: Spec
spec = do
    credentialSpec
    privateAuthoritySpec
    partialAvailabilitySpec

credentialSpec :: Spec
credentialSpec = describe "credential authority (forward-to-private, strip-before-public)" $
    it "forwards the client credential to the private upstream and NEVER to the public upstream" $ do
        privateUp <- servingUpstream (encodePackument (privatePackument [("1.0.0", plainVersion "1.0.0")] "1.0.0"))
        publicUp <-
            servingUpstream
                (encodePackument (packument [("2.0.0", plainVersion "2.0.0")] "2.0.0" [("2.0.0", publishedDaysAgo 30)]))
        withProxy privateUp publicUp Nothing $ \app -> do
            _ <- getThing (Just "client-secret-token") app
            privAuth <- seenAuth privateUp
            pubAuth <- seenAuth publicUp
            privAuth `shouldBe` [Just "Bearer client-secret-token"]
            pubAuth `shouldBe` [Nothing]

privateAuthoritySpec :: Spec
privateAuthoritySpec = describe "private origin is the per-client authority (not cached across clients)" $ do
    it "re-consults the private upstream per client within the TTL -- each client's token reaches it" $ do
        privateUp <- servingUpstream (encodePackument (privatePackument [("1.0.0", plainVersion "1.0.0")] "1.0.0"))
        publicUp <-
            servingUpstream
                (encodePackument (packument [("2.0.0", plainVersion "2.0.0")] "2.0.0" [("2.0.0", publishedDaysAgo 30)]))
        withProxy privateUp publicUp Nothing $ \app -> do
            _ <- getThing (Just "tokenA") app
            _ <- getThing (Just "tokenB") app
            privAuth <- seenAuth privateUp
            pubAuth <- seenAuth publicUp
            privAuth `shouldBe` [Just "Bearer tokenA", Just "Bearer tokenB"]
            pubAuth `shouldBe` [Nothing]

    it "serves byte-identical bodies across identical repeat requests (the assembled representation is reused)" $ do
        (privateUp, publicUp) <- twoServingUpstreams
        withProxy privateUp publicUp Nothing $ \app -> do
            firstResp <- getThing (Just "tokenA") app
            secondResp <- getThing (Just "tokenA") app
            status firstResp `shouldBe` 200
            simpleBody secondResp `shouldBe` simpleBody firstResp
            header "ETag" secondResp `shouldBe` header "ETag" firstResp
            -- The reuse never skips the per-request private authorisation.
            seenAuth privateUp `shouldReturn` [Just "Bearer tokenA", Just "Bearer tokenA"]

    it "never serves one client's assembled document to another with a different private view" $ do
        -- The private upstream answers per credential. The assembled store is keyed by content, so
        -- client B's entry can never answer client A.
        let perToken req = case lookupAuth (requestHeaders req) of
                Just "Bearer token-a" -> encodePackument (privatePackument [("9.0.0", plainVersion "9.0.0")] "9.0.0")
                _ -> encodePackument (privatePackument [("9.0.1", plainVersion "9.0.1")] "9.0.1")
        privateUp <- servingUpstreamPer perToken
        publicUp <-
            servingUpstream
                (encodePackument (packument [("2.0.0", plainVersion "2.0.0")] "2.0.0" [("2.0.0", publishedDaysAgo 30)]))
        withProxy privateUp publicUp Nothing $ \app -> do
            respA <- getThing (Just "token-a") app
            respB <- getThing (Just "token-b") app
            respA2 <- getThing (Just "token-a") app
            servedVersions respA `shouldBe` ["2.0.0", "9.0.0"]
            servedVersions respB `shouldBe` ["2.0.0", "9.0.1"]
            servedVersions respA2 `shouldBe` ["2.0.0", "9.0.0"]
            simpleBody respA2 `shouldBe` simpleBody respA

partialAvailabilitySpec :: Spec
partialAvailabilitySpec = describe "partial-upstream availability" $ do
    it "serves the public set when the private upstream is unavailable" $ do
        privateUp <- failingUpstream
        publicUp <-
            servingUpstream
                (encodePackument (packument [("2.0.0", plainVersion "2.0.0")] "2.0.0" [("2.0.0", publishedDaysAgo 30)]))
        withProxy privateUp publicUp Nothing $ \app -> do
            resp <- getThing Nothing app
            status resp `shouldBe` 200
            servedVersions resp `shouldBe` ["2.0.0"]

    it "serves the private set when the public upstream is unavailable" $ do
        privateUp <- servingUpstream (encodePackument (privatePackument [("1.0.0", plainVersion "1.0.0")] "1.0.0"))
        publicUp <- failingUpstream
        withProxy privateUp publicUp Nothing $ \app -> do
            resp <- getThing Nothing app
            status resp `shouldBe` 200
            servedVersions resp `shouldBe` ["1.0.0"]

    it "degrades a private leg whose body is unparseable, serving the public set" $ do
        privateUp <- servingUpstream "this is not json at all"
        publicUp <-
            servingUpstream
                (encodePackument (packument [("2.0.0", plainVersion "2.0.0")] "2.0.0" [("2.0.0", publishedDaysAgo 30)]))
        withProxy privateUp publicUp Nothing $ \app -> do
            resp <- getThing Nothing app
            status resp `shouldBe` 200
            servedVersions resp `shouldBe` ["2.0.0"]

    it "degrades a private leg that decodes but does not project to a packument" $ do
        privateUp <- servingUpstream "[1, 2, 3]"
        publicUp <-
            servingUpstream
                (encodePackument (packument [("2.0.0", plainVersion "2.0.0")] "2.0.0" [("2.0.0", publishedDaysAgo 30)]))
        withProxy privateUp publicUp Nothing $ \app -> do
            resp <- getThing Nothing app
            status resp `shouldBe` 200
            servedVersions resp `shouldBe` ["2.0.0"]

    it "drops a private leg that self-reports a different package, serving the public set (200)" $ do
        privateUp <-
            servingUpstream
                (encodePackument (packumentNamed "other" [("1.0.0", plainVersion "1.0.0")] "1.0.0" [("1.0.0", publishedDaysAgo 30)]))
        publicUp <-
            servingUpstream
                (encodePackument (packument [("2.0.0", plainVersion "2.0.0")] "2.0.0" [("2.0.0", publishedDaysAgo 30)]))
        withProxy privateUp publicUp Nothing $ \app -> do
            resp <- getThing Nothing app
            status resp `shouldBe` 200
            servedVersions resp `shouldBe` ["2.0.0"]
            topLevel "name" resp `shouldBe` Just (String "thing")

    it "drops a public leg that self-reports a different package, serving the private set (200)" $ do
        privateUp <- servingUpstream (encodePackument (privatePackument [("1.0.0", plainVersion "1.0.0")] "1.0.0"))
        publicUp <-
            servingUpstream
                (encodePackument (packumentNamed "other" [("2.0.0", plainVersion "2.0.0")] "2.0.0" [("2.0.0", publishedDaysAgo 30)]))
        withProxy privateUp publicUp Nothing $ \app -> do
            resp <- getThing Nothing app
            status resp `shouldBe` 200
            servedVersions resp `shouldBe` ["1.0.0"]
            topLevel "name" resp `shouldBe` Just (String "thing")
