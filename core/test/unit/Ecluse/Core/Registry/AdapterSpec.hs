-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Core.Registry.AdapterSpec (spec) where

import Test.Hspec

import Ecluse.Core.Ecosystem (Ecosystem (Npm, PyPI, RubyGems))
import Ecluse.Core.Registry.Adapter (adapterEcosystem, adapterFor)

{- | Pin each arm of the adapter registry's dispatch: the build-support fact, independent of
configuration. A configured but unsupported ecosystem is the loud boot error
"Ecluse.CompositionSpec" pins over 'Ecluse.Composition.planMounts'.
-}
spec :: Spec
spec = describe "adapterFor (the ecosystem adapter registry)" $ do
    it "resolves npm to the adapter registered under its own ecosystem tag" $
        (adapterEcosystem <$> adapterFor Npm) `shouldBe` Just Npm

    it "resolves PyPI to the adapter registered under its own ecosystem tag" $
        (adapterEcosystem <$> adapterFor PyPI) `shouldBe` Just PyPI

    it "resolves RubyGems to no adapter (unsupported by the build, a loud miss)" $
        (adapterEcosystem <$> adapterFor RubyGems) `shouldBe` Nothing
