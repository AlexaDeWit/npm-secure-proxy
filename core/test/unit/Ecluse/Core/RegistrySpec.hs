-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Tests for registry access-failure classification and URL diagnostics.
Diagnostic URLs must exclude userinfo and query credentials.
-}
module Ecluse.Core.RegistrySpec (spec) where

import Ecluse.Core.Registry (UrlFormationError (EmptyBaseUrl, UnparseableUrl), isAuthorisationFailure, renderUrlFormationError)
import Test.Hspec

spec :: Spec
spec = do
    describe "isAuthorisationFailure" $ do
        it "retains only explicit authentication and authorisation refusals" $
            filter isAuthorisationFailure [100 .. 599] `shouldBe` [401, 403]
    describe "renderUrlFormationError" $ do
        it "excludes userinfo, paths, and query credentials" $
            renderUrlFormationError (UnparseableUrl "https://deploy:hunter2@upstream.test/base?token=abc")
                `shouldBe` "UnparseableUrl upstream.test:443"
        it "renders an empty base URL" $
            renderUrlFormationError EmptyBaseUrl `shouldBe` "EmptyBaseUrl"
