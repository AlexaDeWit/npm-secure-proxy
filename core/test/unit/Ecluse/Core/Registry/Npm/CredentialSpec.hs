-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Core.Registry.Npm.CredentialSpec (spec) where

import Data.List (lookup)
import Network.HTTP.Client qualified as Client
import Network.HTTP.Types.Header (RequestHeaders)
import Test.Hspec (Spec, describe, it, shouldBe)

import Ecluse.Core.Credential (ClientCredential (credSecret, credUsername), Secret, bareCredential, mkSecret)
import Ecluse.Core.Registry.Npm.Credential (npmCredential)
import Ecluse.Core.Registry.Request (attachCredential, credentialRecover)
import Ecluse.Test.Support (parseRequestOrFail)

spec :: Spec
spec = do
    recoverySpec
    encodingSpec

recoverySpec :: Spec
recoverySpec = describe "npm recovers the bearer token an npm client presents" $ do
    it "recovers the token text after the Bearer scheme" $
        recover [("Authorization", "Bearer npm_tok-abc")] `shouldBe` Just (mkSecret "npm_tok-abc")

    it "matches the scheme name case-insensitively" $ do
        recover [("Authorization", "bearer npm_tok-abc")] `shouldBe` Just (mkSecret "npm_tok-abc")
        recover [("Authorization", "BEARER npm_tok-abc")] `shouldBe` Just (mkSecret "npm_tok-abc")

    it "recovers nothing from a Basic credential" $
        recover [("Authorization", "Basic X190b2tlbl9fOnRvaw==")] `shouldBe` Nothing

    it "recovers nothing from a raw token presented with no scheme" $
        recover [("Authorization", "npm_tok-abc")] `shouldBe` Nothing

    it "recovers nothing from a Bearer scheme with an empty token" $ do
        recover [("Authorization", "Bearer")] `shouldBe` Nothing
        recover [("Authorization", "Bearer ")] `shouldBe` Nothing
        recover [("Authorization", "Bearer    ")] `shouldBe` Nothing

    it "recovers a pair carrying no username, because the Bearer grammar has no slot for one" $
        credUsername <$> recoverPair [("Authorization", "Bearer npm_tok-abc")] `shouldBe` Just Nothing

    it "recovers nothing when the request presents no Authorization header" $ do
        recover [] `shouldBe` Nothing
        recover [("X-Api-Key", "npm_tok-abc")] `shouldBe` Nothing

    it "recovers nothing when the scheme name is not delimited by a space" $ do
        recover [("Authorization", "Bearerfoo")] `shouldBe` Nothing
        recover [("Authorization", "Bearer\ttok")] `shouldBe` Nothing

    it "recovers nothing from a scheme that is not valid UTF-8" $ do
        recover [("Authorization", "\xff\xfe")] `shouldBe` Nothing
        recover [("Authorization", "\xff\xfe tok")] `shouldBe` Nothing

    it "decodes a token that is not valid UTF-8 leniently rather than throwing" $
        -- Recovery is total on any bytes a client can send. Invalid bytes decode to replacement
        -- text, which the constant-time compare then refuses. No exception crosses the serve path.
        recover [("Authorization", "Bearer \xff\xfe")]
            `shouldBe` Just (mkSecret (decodeUtf8 ("\xff\xfe" :: ByteString)))

encodingSpec :: Spec
encodingSpec = describe "npm carries an outbound credential as Bearer on Authorization" $ do
    it "writes the Bearer header and no other credential header" $ do
        req <- parseRequestOrFail "https://registry.test/is-odd"
        let headers = Client.requestHeaders (attachCredential npmCredential (Just (bareCredential (mkSecret "npm_tok-abc"))) req)
        lookup "Authorization" headers `shouldBe` Just "Bearer npm_tok-abc"
        lookup "X-Api-Key" headers `shouldBe` Nothing

    it "writes no credential header when the request is anonymous" $ do
        req <- parseRequestOrFail "https://registry.test/is-odd"
        lookup "Authorization" (Client.requestHeaders (attachCredential npmCredential Nothing req))
            `shouldBe` Nothing

    it "refuses to follow a redirect with the credential attached" $ do
        req <- parseRequestOrFail "https://registry.test/is-odd"
        Client.redirectCount (attachCredential npmCredential (Just (bareCredential (mkSecret "npm_tok-abc"))) req) `shouldBe` 0

    it "round-trips a recovered token back onto the wire under the same scheme" $ do
        req <- parseRequestOrFail "https://registry.test/is-odd"
        let recovered = recoverPair [("Authorization", "Bearer npm_tok-abc")]
        lookup "Authorization" (Client.requestHeaders (attachCredential npmCredential recovered req))
            `shouldBe` Just "Bearer npm_tok-abc"

-- | The secret half npm recovers, which every expectation above is written against.
recover :: RequestHeaders -> Maybe Secret
recover = fmap credSecret . recoverPair

-- | The whole credential npm recovers, for the cases about the pair itself.
recoverPair :: RequestHeaders -> Maybe ClientCredential
recoverPair = credentialRecover npmCredential
