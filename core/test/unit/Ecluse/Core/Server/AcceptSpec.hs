-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Core.Server.AcceptSpec (spec) where

import Test.Hspec

import Ecluse.Core.Server.Accept (acceptsAny)

spec :: Spec
spec = describe "acceptsAny" $ do
    it "admits every served type when the request sends no Accept header" $
        acceptsAny [] served `shouldBe` True

    it "admits an exact match" $
        accepting "application/vnd.pypi.simple.v1+json" `shouldBe` True

    it "matches a media type case-insensitively, as the grammar is" $
        accepting "APPLICATION/VND.PYPI.SIMPLE.V1+JSON" `shouldBe` True

    it "admits the universal range" $
        accepting "*/*" `shouldBe` True

    it "admits a type-half range covering a served type" $
        accepting "application/*" `shouldBe` True

    it "refuses a type-half range over another type" $
        accepting "text/*" `shouldBe` False

    it "admits a served type listed beside ones it does not serve" $
        -- The Accept a modern pip sends: the JSON form first, then two it would settle for.
        accepting "application/vnd.pypi.simple.v1+json, application/vnd.pypi.simple.v1+html;q=0.1, text/html;q=0.01"
            `shouldBe` True

    it "refuses a request that lists only representations this route does not serve" $
        -- The legacy client floor: an HTML-only client gets the 406 rather than a wrong body.
        accepting "text/html, application/vnd.pypi.simple.v1+html" `shouldBe` False

    it "ignores a parameter that is not a quality" $
        accepting "application/vnd.pypi.simple.v1+json; charset=utf-8" `shouldBe` True

    it "reads q=0 as a rejection rather than a preference" $ do
        accepting "application/vnd.pypi.simple.v1+json;q=0" `shouldBe` False
        accepting "*/*;q=0.000" `shouldBe` False

    it "keeps a served type admitted when another range rejects everything" $
        accepting "*/*;q=0, application/vnd.pypi.simple.v1+json" `shouldBe` True

    it "tolerates the whitespace a client puts around a range and its parameters" $
        accepting "  application/vnd.pypi.simple.v1+json ; q=1  " `shouldBe` True

    it "refuses an Accept header that lists nothing at all" $
        accepting "" `shouldBe` False

-- | The media types the route under test serves.
served :: NonEmpty ByteString
served = "application/vnd.pypi.simple.v1+json" :| []

-- | Whether a request sending this Accept value admits one of the served types.
accepting :: ByteString -> Bool
accepting value = acceptsAny [("Accept", value)] served
