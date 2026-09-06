-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The wiring half of the boot's effectful tier: turn the 'ValidatedPlan' that
"Ecluse.Composition.Plan" resolves and "Ecluse.Composition.Validate" clears into the served
'MountBinding's and the worker's publish targets. Every refusal 'resolveBootWiring' reports needs a
live environment: it mints each mount's mirror-write credential and runs
'Ecluse.Core.Rules.prepare', which allocates per-rule engine state once at boot. That is why this
is 'IO' and why @ecluse check-config@ reaches none of it. "Ecluse.Composition.Executable" runs it
as one phase, and 'WiringPorts' carries the clock and the adapter resolver in, so a unit test runs
the assembly without opening a listener (see @docs\/architecture\/configuration.md@ → "Validation").
-}
module Ecluse.Composition (
    -- * The environment-dependent wiring
    ResolveAdapter,
    WiringPorts (..),
    BootWiring (..),
    resolveBootWiring,

    -- * Boot-time wiring
    planMounts,

    -- * The first-party privilege
    firstPartyName,

    -- * Publish-side wiring
    PublishBudget (..),
    PublishTarget (..),
    planPublishTargets,
) where

import Data.Map.Strict qualified as Map
import Data.Set qualified as Set
import Data.Text qualified as T
import Data.Time (UTCTime)
import Validation (eitherToValidation, validationToEither)

import Ecluse.Composition.BootError (BootError (..))
import Ecluse.Composition.Credential (
    CredentialProviders,
    initCredentialProviders,
    initializedEcosystems,
    lookupProvider,
 )
import Ecluse.Composition.Endpoints (publicationTargetUrl)
import Ecluse.Composition.Validate (
    ValidatedPlan (vpMounts, vpPublications, vpSettings),
    VettedMount (vmAdapter, vmConfig, vmEcosystem, vmMount),
    VettedPublication (vpubFirstParty, vpubStaticToken, vpubTarget),
 )
import Ecluse.Config (
    AppConfig (..),
    EgressSettings (..),
    FirstParty (..),
    IntegritySettings (..),
    MirrorTarget (mtUrl),
    Mount (..),
    MountConfig (..),
    MountIntegrity (..),
    MountRegistries (..),
    ServerSettings (..),
    StoreTag,
    Url,
    regMirrorTarget,
    regPrivateUpstream,
    unUrl,
 )
import Ecluse.Core.Credential (CredentialProvider)
import Ecluse.Core.Credential.Refresh (CredentialReporters)
import Ecluse.Core.Ecosystem (Ecosystem, prefixFor)
import Ecluse.Core.Package (PackageName)
import Ecluse.Core.Registry.Adapter (
    RegistryAdapter,
    adapterArtifact,
    adapterMetadata,
    adapterProjectName,
    adapterPublish,
    artifactHosts,
 )
import Ecluse.Core.Registry.Npm.Publish (npmPublishAllowed)
import Ecluse.Core.Registry.PyPI.FirstParty (pypiFirstPartyName)
import Ecluse.Core.Rules (RuleDeps, prepare, rdCurrentAdvisoryEtag)
import Ecluse.Core.Security (Limits)
import Ecluse.Core.Security.Egress (RegistryUrl, mkRegistryUrl)
import Ecluse.Core.Server.Admission.Bytes (ByteAdmission)
import Ecluse.Core.Server.Context (MountBinding, PackumentDeps (..), PublishDeps (..))
import Ecluse.Core.Server.Response (HelpMessage, mkHelpMessage)
import Ecluse.Core.Server.Upstream (MirrorServePlan (MirrorOnAdmit, NoMirrorWrite), mountUpstreams)
import Ecluse.Core.Text (stripTrailingSlash)

{- | Resolve an ecosystem's deps to its complete mount, 'Nothing' for an ecosystem this build
ships no adapter for. "Ecluse.Service" holds the one implementation.
-}
type ResolveAdapter = Ecosystem -> PackumentDeps -> Maybe PublishDeps -> Maybe MountBinding

{- | The capabilities the wiring is built through, injected so a unit test runs the boot-time
assembly without opening a listener.
-}
data WiringPorts = WiringPorts
    { wpReporters :: StoreTag -> CredentialReporters
    -- ^ Where a store's credential provider records its mint breaker and refresh outcomes.
    , wpResolveAdapter :: ResolveAdapter
    -- ^ The ecosystem-to-binding resolver, 'Nothing' for an ecosystem this build ships no adapter for.
    , wpClock :: IO UTCTime
    -- ^ The clock every mount's serve path reads.
    , wpRuleDeps :: Ecosystem -> RuleDeps
    -- ^ One ecosystem's rule capabilities, including its advisory-database lookup.
    }

{- | What only a live environment settled: the mounts the front door serves, and the publish
targets the worker writes approved artifacts through.
-}
data BootWiring = BootWiring
    { bwBindings :: [MountBinding]
    -- ^ The resolved mounts. A worker-only role builds them for their rules, and serves none.
    , bwPublishTargets :: [PublishTarget]
    -- ^ One target per mirrored mount, each holding the provider that mints its write token.
    }

{- | Build the boot wiring from the cleared plan, or the refusals only a live environment can
settle. The credential providers stay internal: a mount reaches one through the wiring it produced.
-}
resolveBootWiring :: WiringPorts -> Limits -> Maybe PublishBudget -> ValidatedPlan -> IO (Either [BootError] BootWiring)
resolveBootWiring ports limits publishBudget plan = do
    -- The mirror-write credential mints once, eagerly, so a misconfiguration fails at boot. Both
    -- groups below consume the providers, so this step runs before them, not alongside them.
    providersE <- initCredentialProviders (wpReporters ports) (map vmMount (vpMounts plan))
    case providersE of
        Left errs -> pure (Left errs)
        Right providers -> do
            bindingsE <- planMounts (wpResolveAdapter ports) (wpClock ports) (wpRuleDeps ports) providers limits publishBudget plan
            -- The serve side and the publish side read the same providers independently, so
            -- 'Validation' reports both rather than the mounts' refusals alone.
            pure . validationToEither $
                BootWiring
                    <$> eitherToValidation bindingsE
                    <*> eitherToValidation (planPublishTargets providers plan)

{- | The publish-side byte discipline: the process-wide aggregate admission and the
per-request cap. It exists exactly when a publication target is configured.
-}
data PublishBudget = PublishBudget
    { pbBodyBudget :: ByteAdmission
    , pbMaxRequestBytes :: Int
    }

{- | Turn the boot's cleared plan into the served 'MountBinding's, or every remaining boot error at
once. The caller injects every capability, so this opens no socket, and the 'Limits' arrive resolved.
-}
planMounts ::
    ResolveAdapter ->
    IO UTCTime ->
    (Ecosystem -> RuleDeps) ->
    CredentialProviders ->
    Limits ->
    Maybe PublishBudget ->
    ValidatedPlan ->
    IO (Either [BootError] [MountBinding])
planMounts resolveAdapter clock ruleDepsFor providers limits publishBudget plan = do
    bindingResults <- traverse bindingFor (vpMounts plan)
    pure $ case partitionEithers bindingResults of
        ([], bindings) -> Right bindings
        (errs, _) -> Left (concat errs)
  where
    app :: AppConfig
    app = vpSettings plan

    -- The operator help message, derived from the environment layer like the
    -- inbound token, so every mount's denials carry it.
    helpMessage :: Maybe HelpMessage
    helpMessage = mkHelpMessage <$> srvHelpMessage (cfgServer app)

    {- The plan cleared the adapter, so only the credential reference and the injected resolver
    are still this mount's to check, and it reports both in one run. -}
    bindingFor :: VettedMount -> IO (Either [BootError] MountBinding)
    bindingFor vetted = do
        deps <- packumentDepsFor (vmAdapter vetted) (vmMount vetted) (vmConfig vetted)
        pure $ case (credentialError providers (vmMount vetted), resolveAdapter eco deps (publishDeps vetted)) of
            (Nothing, Just binding) -> Right binding
            (mCredErr, mBinding) ->
                Left (maybeToList mCredErr <> [MissingAdapter eco | isNothing mBinding])
      where
        eco = vmEcosystem vetted

    -- A mount the pass cleared no publication for leaves @PUT \/{pkg}@ answering @405@.
    publishDeps :: VettedMount -> Maybe PublishDeps
    publishDeps vetted =
        Map.lookup (vmEcosystem vetted) (vpPublications plan)
            >>= publishDepsFor (vmAdapter vetted) app limits publishBudget helpMessage

    {- The ecosystem-shaped fields are the adapter's own records, carried whole, and the
    rest is the mount's configuration. @mountBaseUrl@ owns the @dist.tarball@ base. -}
    packumentDepsFor :: RegistryAdapter -> Mount -> MountConfig -> IO PackumentDeps
    packumentDepsFor adapter mount mcfg = do
        -- 'prepare' allocates an effectful rule's resilience policy and breaker once per mount.
        -- The deps below bridge that same 'RuleDeps' non-pinning advisory-ETag reader.
        let ruleDeps = ruleDepsFor (mountEcosystem mount)
        prepared <- prepare ruleDeps (mountPolicy mount)
        let regs = mountRegistries mount
        pure
            PackumentDeps
                { -- The leading argument is the adapter's declared artifact hosts: the
                  -- ecosystem's own same-host equivalence for the tarball gate.
                  pdUpstreams =
                    mountUpstreams
                        (artifactHosts (adapterArtifact adapter))
                        (regPrivateUpstream regs)
                        (regPublicUpstream regs)
                        (maybe NoMirrorWrite (MirrorOnAdmit . mtUrl) (regMirrorTarget regs))
                , -- Deny by default: a mount that declares no namespaces owns none, so every
                  -- name resolves through both upstreams as before.
                  pdFirstParty = maybe (const False) firstPartyName (mntFirstParty mcfg)
                , pdMountBaseUrl = mountBaseUrl (srvPublicUrl (cfgServer app)) (mountEcosystem mount)
                , pdRules = prepared
                , -- The operator-configured ranges extending the fixed internal-range block
                  -- on the dist.tarball host gate. The same list applies to every mount,
                  -- because a network's internal ranges are a deployment-wide fact.
                  pdAdditionalBlockedRanges = egrAdditionalBlockedRanges (cfgEgress app)
                , pdLimits = limits
                , pdInboundToken = srvAuthToken (cfgServer app)
                , pdNow = clock
                , pdAdvisoryEtag = rdCurrentAdvisoryEtag ruleDeps
                , pdHelp = helpMessage
                , -- The global public-integrity admission floor, validated at config
                  -- load, carried onto every mount's deps so the public gate refuses
                  -- a below-floor version.
                  pdMinIntegrity = intMinPublic (cfgIntegrity app)
                , -- The trusted-integrity admission floor: the global default
                  -- (SHA-256, loosenable below it), refined per mount so a legacy
                  -- registry's loosening never leaks onto a neighbouring mount.
                  pdMinTrustedIntegrity = fromMaybe (intMinTrusted (cfgIntegrity app)) (miMinTrusted (mntIntegrity mcfg))
                , -- The cross-upstream divergence policy: the global default
                  -- (warn), refined per mount for the same reason.
                  pdDivergencePolicy = fromMaybe (intDivergencePolicy (cfgIntegrity app)) (miDivergencePolicy (mntIntegrity mcfg))
                , pdMetadata = adapterMetadata adapter
                , pdArtifact = adapterArtifact adapter
                , pdEgressUrl = mkRegistryUrl
                }

-- A serve-only mount never writes, so it references no provider and can never fail here.
credentialError :: CredentialProviders -> Mount -> Maybe BootError
credentialError providers mount = case regMirrorTarget (mountRegistries mount) of
    Nothing -> Nothing
    Just _ ->
        if mountEcosystem mount `Set.member` initializedEcosystems providers
            then Nothing
            else Just (UnresolvedCredential (mountEcosystem mount))

-- Absolute under ECLUSE_SERVER__PUBLIC_URL when set, otherwise the relative prefix path.
-- A real install path must set it: an npm client reads a leading slash as a @file:@ path.
mountBaseUrl :: Maybe Url -> Ecosystem -> Text
mountBaseUrl publicUrl eco =
    case publicUrl of
        Nothing -> mountBasePath eco
        Just public -> stripTrailingSlash (unUrl public) <> mountBasePath eco

-- The relative path a client's registry endpoint maps onto (npm becomes /npm).
mountBasePath :: Ecosystem -> Text
mountBasePath eco = "/" <> T.intercalate "/" (toList (prefixFor eco))

{- | Build the first-party publish dependencies from a cleared publication. 'Nothing' without a
publish budget, which the memory plan allocates exactly when some mount publishes.
-}
publishDepsFor :: RegistryAdapter -> AppConfig -> Limits -> Maybe PublishBudget -> Maybe HelpMessage -> VettedPublication -> Maybe PublishDeps
publishDepsFor adapter app limits publishBudget helpMessage publication = do
    budget <- publishBudget
    -- An ecosystem this build writes nothing for carries no publish capability, so the mount's
    -- publish route stays opt-out and answers its documented refusal.
    publish <- adapterPublish adapter
    pure
        PublishDeps
            { pubTargetUrl = publicationTargetUrl (vpubTarget publication)
            , pubAllowed = firstPartyName (vpubFirstParty publication)
            , pubStaticToken = vpubStaticToken publication
            , pubInboundToken = srvAuthToken (cfgServer app)
            , pubLimits = limits
            , pubBodyBudget = pbBodyBudget budget
            , pubMaxRequestBytes = pbMaxRequestBytes budget
            , pubHelp = helpMessage
            , pubProjectName = adapterProjectName adapter
            , pubAdapter = publish
            }

{- | Whether a name belongs to a namespace this deployment owns. Each arm derives the one predicate every
consumer of the privilege reads, so none can disagree about which names are privileged.
-}
firstPartyName :: FirstParty -> PackageName -> Bool
firstPartyName = \case
    FirstPartyNpmScopes scopes -> npmPublishAllowed (toList scopes)
    FirstPartyPyPI entries -> pypiFirstPartyName entries

{- | One ecosystem's resolved publish target: the endpoint the worker writes approved
artifacts to, and the provider that mints its bearer token. Resolved once, not per request.
-}
data PublishTarget = PublishTarget
    { ptEcosystem :: Ecosystem
    -- ^ The ecosystem this publish target serves.
    , ptMirrorUrl :: RegistryUrl
    -- ^ The mirror-target endpoint the worker publishes approved artifacts to.
    , ptCredentials :: CredentialProvider
    -- ^ The provider minting the mirror-target write token.
    }

{- | Resolve each cleared mount to its publish target, or the aggregated boot errors. An
unresolved credential raises the same error 'planMounts' reports for the serve side.
-}
planPublishTargets ::
    CredentialProviders ->
    ValidatedPlan ->
    Either [BootError] [PublishTarget]
planPublishTargets providers plan =
    case partitionEithers (mapMaybe (publishTargetFor providers . vmMount) (vpMounts plan)) of
        ([], targets) -> Right targets
        (errs, _) -> Left (concat errs)

-- 'Nothing' for a serve-only mount, which writes nothing and has no target. A
-- mirrored mount without an initialised provider is the unresolved-credential error.
publishTargetFor :: CredentialProviders -> Mount -> Maybe (Either [BootError] PublishTarget)
publishTargetFor providers mount = do
    target <- regMirrorTarget (mountRegistries mount)
    pure $ case lookupProvider (mountEcosystem mount) providers of
        Just provider ->
            Right
                PublishTarget
                    { ptEcosystem = mountEcosystem mount
                    , ptMirrorUrl = mtUrl target
                    , ptCredentials = provider
                    }
        Nothing ->
            Left [UnresolvedCredential (mountEcosystem mount)]
