-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Core.Registry.PyPI.CredentialSpec (spec) where

import Data.List (lookup)
import Network.HTTP.Client qualified as Client
import Network.HTTP.Types.Header (RequestHeaders)
import Test.Hspec (Spec, describe, it, shouldBe)

import Ecluse.Core.Credential (
    ClientCredential (ClientCredential, credSecret, credUsername),
    bareCredential,
    mkSecret,
 )
import Ecluse.Core.Registry.PyPI.Credential (pypiCredential)
import Ecluse.Core.Registry.Request (attachCredential, credentialRecover)
import Ecluse.Test.Support (parseRequestOrFail)

spec :: Spec
spec = do
    recoverySpec
    encodingSpec

recoverySpec :: Spec
recoverySpec = describe "PyPI recovers the Basic pair a Python client presents" $ do
    it "recovers both halves of the pair" $
        recover [("Authorization", "Basic YWxpY2U6aHVudGVyMg==")]
            `shouldBe` Just (ClientCredential (Just "alice") (mkSecret "hunter2"))

    it "recovers a token sent under twine's fixed username" $
        recover [("Authorization", "Basic X190b2tlbl9fOnB5cGktQWdFSQ==")]
            `shouldBe` Just (ClientCredential (Just "__token__") (mkSecret "pypi-AgEI"))

    it "admits any username, because the index rather than Écluse decides who a name is" $
        credUsername <$> recover [("Authorization", "Basic YWxpY2U6aHVudGVyMg==")] `shouldBe` Just (Just "alice")

    it "reads an empty username as no username at all" $
        recover [("Authorization", "Basic OnNlY3JldA==")] `shouldBe` Just (bareCredential (mkSecret "secret"))

    it "splits at the first colon, so a password may carry one" $
        credSecret <$> recover [("Authorization", "Basic dXNlcjpwYTpzcw==")] `shouldBe` Just (mkSecret "pa:ss")

    it "matches the scheme name case-insensitively" $ do
        recover [("Authorization", "basic YWxpY2U6aHVudGVyMg==")] `shouldBe` alicePair
        recover [("Authorization", "BASIC YWxpY2U6aHVudGVyMg==")] `shouldBe` alicePair

    it "recovers nothing from a Bearer credential, which is npm's presentation" $
        recover [("Authorization", "Bearer npm_tok-abc")] `shouldBe` Nothing

    it "recovers nothing from a payload that is not base64" $
        recover [("Authorization", "Basic not-base64!!")] `shouldBe` Nothing

    it "recovers nothing from a payload carrying no colon" $
        recover [("Authorization", "Basic bm9jb2xvbg==")] `shouldBe` Nothing

    it "recovers nothing from a pair whose password half is empty" $
        recover [("Authorization", "Basic YWxpY2U6")] `shouldBe` Nothing

    it "recovers nothing when the request presents no Authorization header" $ do
        recover [] `shouldBe` Nothing
        recover [("X-Api-Key", "tok-abc")] `shouldBe` Nothing

encodingSpec :: Spec
encodingSpec = describe "PyPI carries an outbound credential as Basic on Authorization" $ do
    it "renders the caller's pair verbatim, never a rewritten username" $ do
        req <- parseRequestOrFail "https://index.test/simple/requests/"
        let headers = Client.requestHeaders (attachCredential pypiCredential alicePair req)
        lookup "Authorization" headers `shouldBe` Just "Basic YWxpY2U6aHVudGVyMg=="

    it "renders a credential of its own under twine's fixed username" $ do
        req <- parseRequestOrFail "https://index.test/simple/requests/"
        let headers = Client.requestHeaders (attachCredential pypiCredential (Just (bareCredential (mkSecret "pypi-AgEI"))) req)
        lookup "Authorization" headers `shouldBe` Just "Basic X190b2tlbl9fOnB5cGktQWdFSQ=="

    it "writes no credential header when the request is anonymous" $ do
        req <- parseRequestOrFail "https://index.test/simple/requests/"
        lookup "Authorization" (Client.requestHeaders (attachCredential pypiCredential Nothing req))
            `shouldBe` Nothing

    it "refuses to follow a redirect with the credential attached" $ do
        req <- parseRequestOrFail "https://index.test/simple/requests/"
        Client.redirectCount (attachCredential pypiCredential alicePair req) `shouldBe` 0

    it "round-trips a recovered pair back onto the wire under the same scheme" $ do
        req <- parseRequestOrFail "https://index.test/simple/requests/"
        let recovered = recover [("Authorization", "Basic YWxpY2U6aHVudGVyMg==")]
        lookup "Authorization" (Client.requestHeaders (attachCredential pypiCredential recovered req))
            `shouldBe` Just "Basic YWxpY2U6aHVudGVyMg=="

-- | The pair every example builds on: a named user with a password.
alicePair :: Maybe ClientCredential
alicePair = Just (ClientCredential (Just "alice") (mkSecret "hunter2"))

recover :: RequestHeaders -> Maybe ClientCredential
recover = credentialRecover pypiCredential
