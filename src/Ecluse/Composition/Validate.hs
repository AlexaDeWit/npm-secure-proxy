-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The boot's validate phase: one pass over the loaded configuration that yields every pure
refusal and every advisory a role earns, and the plan a cleared configuration reifies from.

The composition root builds from 'ValidatedPlan' alone, so a mount binding, a publish relay, or a
store sweep cannot be assembled out of a configuration this pass never cleared. What no rule
decides stays on 'vpSettings', where reading it raw is honest rather than a hole.
-}
module Ecluse.Composition.Validate (
    -- * The validate phase
    ValidatedPlan (vpMounts, vpPublications, vpMirrorStores, vpSettings),
    vetBoot,

    -- * What it clears
    VettedMount (vmEcosystem, vmAdapter, vmMount, vmConfig),
    VettedPublication (vpubTarget, vpubFirstParty, vpubStaticToken),
) where

import Data.Map.Strict qualified as Map

import Ecluse.Composition.BootError (
    BootError (FirstPartyMissing, MirrorTargetWithoutPublish, MissingAdapter, PublishStaticCredentialNeedsEdge),
 )
import Ecluse.Composition.Endpoints (
    PublicationTarget,
    VettedEndpoints (vePublicationTargets),
    vetEndpoints,
 )
import Ecluse.Composition.Maintenance (ClearedBackend, vetStoreBackends)
import Ecluse.Composition.Vet (Severity (Refuse), Vet, rule)
import Ecluse.Config (
    AppConfig (cfgMounts, cfgServer),
    Config (configApp, configMounts),
    FirstParty,
    Mount,
    MountConfig (mntFirstParty, mntPublicationTarget),
    PublicationEndpoint (peTarget, peToken),
    ServerSettings (srvAuthToken),
    StoreTag,
    Target (tgtTag),
    mountRegistries,
    regMirrorTarget,
 )
import Ecluse.Core.Credential (Secret)
import Ecluse.Core.Ecosystem (Ecosystem)
import Ecluse.Core.Registry.Adapter (RegistryAdapter, adapterFor, adapterPublish)

{- | What the pure boot pass cleared: the mounts a role may serve, the endpoints it may use, and
the settings no rule vets.
-}
data ValidatedPlan = ValidatedPlan
    { vpMounts :: [VettedMount]
    -- ^ Every active mount, in ascending ecosystem order, with the adapter that serves it.
    , vpPublications :: Map Ecosystem VettedPublication
    -- ^ Each mount's cleared publish path, absent where the mount declares no target.
    , vpMirrorStores :: Map Ecosystem ClearedBackend
    {- ^ The backend for each store a sweep may delete from. Only @ecluse dredger@'s pass
    clears one.
    -}
    , vpSettings :: AppConfig
    {- ^ The settings no rule vets. The mounts it still carries are the raw declarations, and
    'vpMounts' holds the vetted ones the runtime reads.
    -}
    }

-- | One active mount, paired with the adapter this build ships for its ecosystem.
data VettedMount = VettedMount
    { vmEcosystem :: Ecosystem
    , vmAdapter :: RegistryAdapter
    , vmMount :: Mount
    , vmConfig :: MountConfig
    }

{- | A mount's cleared publish path: the vetted endpoint, the first-party namespaces the
anti-shadowing guard enforces, and the static credential the inbound edge gate covers.
-}
data VettedPublication = VettedPublication
    { vpubTarget :: PublicationTarget
    , vpubFirstParty :: FirstParty
    , vpubStaticToken :: Maybe Secret
    }

{- | Vet the whole loaded configuration for one role. The four groups compose with '<*>', so one
run reports every refusal and every advisory rather than the first group's alone.
-}
vetBoot :: Config -> Vet ValidatedPlan
vetBoot config =
    assemble
        <$> vetMounts config
        <*> vetPublishPolicy app
        <*> vetEndpoints (cfgMounts app)
        <*> vetStoreBackends adapterFor (configMounts config)
  where
    app = configApp config

    assemble mounts policies endpoints backends =
        ValidatedPlan
            { vpMounts = mounts
            , vpPublications = Map.intersectionWith cleared (vePublicationTargets endpoints) policies
            , vpMirrorStores = backends
            , vpSettings = app
            }

    cleared target (firstParty, staticToken) = VettedPublication target firstParty staticToken

{- Every active mount, refusing the ecosystems this build ships no adapter for. Serving one would
answer every route with a stub, which is a wiring fault rather than a posture an operator chose. -}
vetMounts :: Config -> Vet [VettedMount]
vetMounts config = catMaybes <$> traverse vetMount (activeMounts config)

{- 'Ecluse.Config.loadConfig' derives 'configMounts' from 'cfgMounts' entry for entry, so the two
maps share a keyset and this pairing is total. -}
activeMounts :: Config -> [(Ecosystem, (Mount, MountConfig))]
activeMounts config =
    Map.toAscList (Map.intersectionWith (,) (configMounts config) (cfgMounts (configApp config)))

-- 'Nothing' only where the rule refused, and a refused pass yields no plan to carry it into.
vetMount :: (Ecosystem, (Mount, MountConfig)) -> Vet (Maybe VettedMount)
vetMount (eco, (mount, mcfg)) =
    vetted
        <$ rule (const (Refuse MissingAdapter)) unservedEcosystem eco
        <* rule (const (Refuse MirrorTargetWithoutPublish)) mirrorsWithoutPublish eco
  where
    vetted = adapterFor eco <&> \adapter -> VettedMount eco adapter mount mcfg

    unservedEcosystem e
        | isNothing (adapterFor e) = Just e
        | otherwise = Nothing

    {- A mirror target on an ecosystem this build writes nothing for. The mirror would drain a
    queue it could never publish from, so the mount is refused at the boot rather than serving
    with a mirror that silently fails every job. -}
    mirrorsWithoutPublish e = do
        guard (isJust (regMirrorTarget (mountRegistries mount)))
        adapter <- adapterFor e
        guard (isNothing (adapterPublish adapter))
        pure e

{- The two couplings a declared publication target carries: the first-party namespaces the
guard enforces, and the inbound edge a static publish credential needs. -}
vetPublishPolicy :: AppConfig -> Vet (Map Ecosystem (FirstParty, Maybe Secret))
vetPublishPolicy app =
    Map.fromList . catMaybes <$> traverse (vetPublication (srvAuthToken (cfgServer app))) publishingMounts
  where
    publishingMounts =
        [ (eco, mcfg)
        | (eco, mcfg) <- Map.toAscList (cfgMounts app)
        , isJust (mntPublicationTarget mcfg)
        ]

vetPublication :: Maybe Secret -> (Ecosystem, MountConfig) -> Vet (Maybe (Ecosystem, (FirstParty, Maybe Secret)))
vetPublication inboundToken subject@(eco, mcfg) =
    cleared
        <$ rule (const (Refuse FirstPartyMissing)) firstPartyMissing subject
        <* rule (const (Refuse (uncurry PublishStaticCredentialNeedsEdge))) (staticWithoutEdge inboundToken) subject
  where
    cleared = mntFirstParty mcfg <&> \firstParty -> (eco, (firstParty, publicationToken mcfg))

-- The static fallback the relay forwards when the publishing client sends none.
publicationToken :: MountConfig -> Maybe Secret
publicationToken mcfg = peToken =<< mntPublicationTarget mcfg

firstPartyMissing :: (Ecosystem, MountConfig) -> Maybe Ecosystem
firstPartyMissing (eco, mcfg)
    | isNothing (mntFirstParty mcfg) = Just eco
    | otherwise = Nothing

{- Any unauthenticated client could otherwise publish within scope under Écluse's own credential.
The tag rides along, because the credential's key path nests below it. -}
staticWithoutEdge :: Maybe Secret -> (Ecosystem, MountConfig) -> Maybe (Ecosystem, StoreTag)
staticWithoutEdge inboundToken (eco, mcfg) = do
    guard (isJust (publicationToken mcfg) && isNothing inboundToken)
    endpoint <- mntPublicationTarget mcfg
    pure (eco, tgtTag (peTarget endpoint))
