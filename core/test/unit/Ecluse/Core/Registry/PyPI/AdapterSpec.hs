-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Core.Registry.PyPI.AdapterSpec (spec) where

import Test.Hspec

import Ecluse.Core.Ecosystem (Ecosystem (Npm, PyPI, RubyGems))
import Ecluse.Core.Registry.Adapter (
    AdapterArtifact (artifactHosts),
    AdapterMaintenance (maintenanceListing, maintenanceVersionDelete),
    RegistryAdapter (adapterArtifact, adapterEcosystem, adapterMaintenance, adapterPublish),
    adapterFor,
 )

spec :: Spec
spec = describe "the PyPI adapter" $ do
    it "is what the registry resolves the ecosystem to, so a pypi mount serves" $
        fmap adapterEcosystem (adapterFor PyPI) `shouldBe` Just PyPI

    it "declares the files host public PyPI serves distribution bytes from" $
        -- The artifact-host gate folds this in, so the secure-default same-host policy admits
        -- the files host with no operator naming a hostname.
        fmap (artifactHosts . adapterArtifact) (adapterFor PyPI)
            `shouldBe` Just ["https://files.pythonhosted.org"]

    it "carries no publish capability, so the upload route stays the documented refusal" $
        fmap (isJust . adapterPublish) (adapterFor PyPI) `shouldBe` Just False

    it "spells neither store-maintenance verb, so a Dredger against such a store refuses" $ do
        -- PyPI has no public wire endpoint for listing a store's projects or deleting a
        -- release, so the Dredger names the missing verb rather than sweeping half the store.
        fmap (isJust . maintenanceListing . adapterMaintenance) (adapterFor PyPI) `shouldBe` Just False
        fmap (isJust . maintenanceVersionDelete . adapterMaintenance) (adapterFor PyPI) `shouldBe` Just False

    it "leaves npm's publish capability filled, so npm keeps writing as it did" $
        fmap (isJust . adapterPublish) (adapterFor Npm) `shouldBe` Just True

    it "leaves an ecosystem this build ships no adapter for unresolved" $
        fmap adapterEcosystem (adapterFor RubyGems) `shouldBe` Nothing
