-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Composition.ValidateSpec (spec) where

import Data.Map.Strict qualified as Map
import Test.Hspec

import Ecluse.Composition.BootError (
    BootError (
        FirstPartyMissing,
        MirrorTargetOnMountEndpoint,
        MirrorTargetWithoutPublish,
        MissingAdapter,
        PublicationTargetOnPublicUpstream,
        PublicationTargetWithoutPublish,
        PublishStaticCredentialNeedsEdge
    ),
 )
import Ecluse.Composition.Endpoints (publicationTargetUrl)
import Ecluse.Composition.Support (
    clearedRepository,
    codeArtifactEnvVars,
    codeArtifactMirrorUrl,
    expectConfig,
    noMaintenanceBackend,
    overrideEnv,
    staticEnvVars,
    withoutPrivateUpstreamUrl,
 )
import Ecluse.Composition.Types (RegistryRole (MirrorPruner, MirrorWriter))
import Ecluse.Composition.Validate (
    ValidatedPlan (vpMirrorStores, vpMounts, vpPublications, vpSettings),
    VettedMount (vmEcosystem),
    VettedPublication (vpubFirstParty, vpubStaticToken, vpubTarget),
    vetBoot,
 )
import Ecluse.Composition.Vet (runVet)
import Ecluse.Config (
    AppConfig (cfgMounts),
    Config,
    FirstParty (FirstPartyNpmScopes),
    MountConfig (mntMirrorTarget),
    StoreTag (TagRegistry),
 )
import Ecluse.Core.Credential (unSecret)
import Ecluse.Core.Ecosystem (Ecosystem (Npm, PyPI, RubyGems))
import Ecluse.Core.Package (mkScope)
import Ecluse.Core.Security.Egress (registryUrlText)

{- | Tests the boot's validate phase: the four groups a role's pass runs, and the plan a cleared
configuration reifies from. The groups compose with '<*>', so one run reports all of them.
-}
spec :: Spec
spec = do
    clearedSpec
    refusalSpec

clearedSpec :: Spec
clearedSpec = describe "vetBoot -- what a cleared configuration reifies" $ do
    it "clears the active mounts and leaves the raw settings on the plan beside them" $ do
        plan <- expectVetted MirrorWriter staticEnvVars
        map vmEcosystem (vpMounts plan) `shouldBe` [Npm]
        -- Nothing vets the settings, so the plan carries them as loaded rather than dropping them.
        Map.keys (cfgMounts (vpSettings plan)) `shouldBe` [Npm]

    it "clears a declared publication target with its namespaces and its static credential" $ do
        plan <- expectVetted MirrorWriter (overrideEnv "ECLUSE_SERVER__AUTH_TOKEN" "edge-token" staticPublishEnv)
        case Map.lookup Npm (vpPublications plan) of
            Nothing -> expectationFailure "expected the publishing mount to clear a publication"
            Just publication -> do
                registryUrlText (publicationTargetUrl (vpubTarget publication))
                    `shouldBe` "https://publish.example.test"
                vpubFirstParty publication `shouldBe` FirstPartyNpmScopes (pure (mkScope "acme"))
                fmap unSecret (vpubStaticToken publication) `shouldBe` Just "publish-write-token"

    it "clears no publication for a mount that declares no target, so PUT stays a 405" $ do
        plan <- expectVetted MirrorWriter staticEnvVars
        Map.keys (vpPublications plan) `shouldBe` []

    it "clears the deleting role the backend for a mirror store no other endpoint holds" $ do
        plan <- expectVetted MirrorPruner codeArtifactEnvVars
        fmap repositoryOf (Map.lookup Npm (vpMirrorStores plan)) `shouldBe` Just "mirror"

    it "clears a backend for every mount that declares a mirror target" $ do
        -- The plan's one store witness. A collapse the endpoint rules refuse yields no plan at
        -- all, so a backend the plan carries is one no other declared endpoint holds.
        plan <- expectVetted MirrorPruner codeArtifactEnvVars
        Map.keys (vpMirrorStores plan) `shouldBe` mirroringMounts (vpSettings plan)

    it "clears a writing role no store at all, because no writing role sweeps one" $ do
        -- The same configuration the deleting role gets a store from. A writing role holds a
        -- witness for a delete it may not perform, so its pass issues none.
        plan <- expectVetted MirrorWriter codeArtifactEnvVars
        Map.keys (vpMirrorStores plan) `shouldBe` []

    it "clears a writing role a mirror target this build cannot sweep, and says nothing of it" $ do
        -- Only the Dredger deletes, so only its pass reads the maintenance rule. The checker
        -- names the Dredger's refusal for this configuration, so an operator still learns of it.
        config <- expectConfig staticEnvVars Nothing
        let (advisories, outcome) = runVet MirrorWriter (vetBoot config)
        advisories `shouldBe` []
        fmap (Map.keys . vpMirrorStores) outcome `shouldBe` Right []
  where
    repositoryOf = fromMaybe "<not a CodeArtifact store>" . clearedRepository

refusalSpec :: Spec
refusalSpec = describe "vetBoot -- the refusals its four groups earn" $ do
    it "refuses a mount whose ecosystem this build ships no adapter for" $
        refusalsFor MirrorWriter (overrideEnv "ECLUSE_MOUNTS__RUBYGEMS__ENABLED" "true" staticEnvVars)
            `shouldReturn` [MissingAdapter RubyGems]

    it "refuses a mirror target on a mount whose ecosystem this build writes nothing for" $
        -- The mirror would drain a queue it could never publish from, so the boot stops rather
        -- than serving with a mirror that fails every job.
        refusalsFor
            MirrorWriter
            ( overrideEnv "ECLUSE_MOUNTS__PYPI__ENABLED" "true" $
                overrideEnv "ECLUSE_MOUNTS__PYPI__PRIVATE_UPSTREAM__REGISTRY__URL" "https://private.example.test/pypi/" $
                    overrideEnv "ECLUSE_MOUNTS__PYPI__MIRROR_TARGET__REGISTRY__URL" "https://mirror.example.test/pypi/" $
                        overrideEnv "ECLUSE_MOUNTS__PYPI__MIRROR_TARGET__REGISTRY__TOKEN" "t" staticEnvVars
            )
            `shouldReturn` [MirrorTargetWithoutPublish PyPI]

    it "refuses a publication target on a mount whose ecosystem this build writes nothing for" $
        -- The relay would have no adapter to reach the target with, so the boot stops rather
        -- than serving a publish route that refuses every attempt an operator configured for.
        refusalsFor
            MirrorWriter
            ( overrideEnv "ECLUSE_MOUNTS__PYPI__ENABLED" "true" $
                overrideEnv "ECLUSE_MOUNTS__PYPI__FIRST_PARTY" "acme-*" $
                    overrideEnv "ECLUSE_MOUNTS__PYPI__PUBLICATION_TARGET__REGISTRY__URL" "https://publish.example.test/pypi/" staticEnvVars
            )
            `shouldReturn` [PublicationTargetWithoutPublish PyPI]

    it "refuses a publication target that leaves the anti-shadowing guard nothing to enforce" $
        refusalsFor MirrorWriter (withoutFirstParty publishingEnv)
            `shouldReturn` [FirstPartyMissing Npm]

    it "refuses a static publish credential with no verifiable inbound edge" $
        refusalsFor MirrorWriter staticPublishEnv
            `shouldReturn` [PublishStaticCredentialNeedsEdge Npm TagRegistry]

    it "refuses the deleting role a mirror target this build has no maintenance backend for" $
        refusalsFor MirrorPruner staticEnvVars `shouldReturn` [noMaintenanceBackend]

    it "refuses the deleting role a collision on a target it has a backend for" $
        -- The plan carries the cleared backend alone, so a collision has to stop the boot
        -- through the endpoint rule. A backend the pass would clear yields no plan either way.
        refusalsFor MirrorPruner (overrideEnv "ECLUSE_MOUNTS__NPM__PRIVATE_UPSTREAM__CODE_ARTIFACT__URL" codeArtifactMirrorUrl (withoutPrivateUpstreamUrl codeArtifactEnvVars))
            `shouldReturn` [MirrorTargetOnMountEndpoint Npm Npm "privateUpstream" codeArtifactMirrorUrl]

    it "reports the mount refusal beside the maintenance refusal from one deleting-role run" $
        refusalsFor MirrorPruner (overrideEnv "ECLUSE_MOUNTS__RUBYGEMS__ENABLED" "true" staticEnvVars)
            `shouldReturn` [MissingAdapter RubyGems, noMaintenanceBackend]

    it "reports a refusal from each of the writing groups in one run" $ do
        -- The point of the applicative: the mount group refusing does not hide what the publish
        -- policy and the endpoint rules would have said about the same configuration.
        let envVars =
                overrideEnv "ECLUSE_MOUNTS__RUBYGEMS__ENABLED" "true" $
                    withoutFirstParty (overrideEnv "ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__REGISTRY__URL" "https://public.example.test/npm/" staticEnvVars)
        refusalsFor MirrorWriter envVars
            `shouldReturn` [ MissingAdapter RubyGems
                           , FirstPartyMissing Npm
                           , PublicationTargetOnPublicUpstream Npm Npm "https://public.example.test/npm/"
                           ]

-- | The npm mount publishing to a registry of its own, under the namespaces the guard enforces.
publishingEnv :: [(String, String)]
publishingEnv =
    overrideEnv "ECLUSE_MOUNTS__NPM__FIRST_PARTY" "@acme" $
        overrideEnv "ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__REGISTRY__URL" "https://publish.example.test" staticEnvVars

-- | 'publishingEnv' publishing under a static credential, which needs an inbound edge beside it.
staticPublishEnv :: [(String, String)]
staticPublishEnv = overrideEnv "ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__REGISTRY__TOKEN" "publish-write-token" publishingEnv

-- | Drop the first-party declaration, leaving the target the guard has nothing to check against.
withoutFirstParty :: [(String, String)] -> [(String, String)]
withoutFirstParty = filter ((/= "ECLUSE_MOUNTS__NPM__FIRST_PARTY") . fst)

-- | Every mount that declares a mirror target, which is what both store groups enumerate.
mirroringMounts :: AppConfig -> [Ecosystem]
mirroringMounts app =
    [eco | (eco, mcfg) <- Map.toAscList (cfgMounts app), isJust (mntMirrorTarget mcfg)]

-- | Vet an environment layer for one role, failing the test on a refusal.
expectVetted :: RegistryRole -> [(String, String)] -> IO ValidatedPlan
expectVetted role envVars = do
    config <- expectConfig envVars Nothing
    either (\errs -> fail ("boot vetting refused: " <> show errs)) pure (vetted role config)

-- | Every refusal one role's pass earns from an environment layer.
refusalsFor :: RegistryRole -> [(String, String)] -> IO [BootError]
refusalsFor role envVars = fromLeft [] . vetted role <$> expectConfig envVars Nothing

vetted :: RegistryRole -> Config -> Either [BootError] ValidatedPlan
vetted role config = snd (runVet role (vetBoot config))
