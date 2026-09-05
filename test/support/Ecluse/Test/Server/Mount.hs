-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Test fixtures for a mount's serve dependencies.

The module name follows this support library's @Ecluse.X -> Ecluse.Test.X@ convention.

'serveDepsFor' is the one shared builder for a mount's 'PackumentDeps'. It takes the ecosystem's
adapter and fills the standard production wiring once: that adapter's metadata and artifact
capability records, the derived tarball-host gate, and the policy defaults. A call site passes
only its own axes and record-updates the few fields unique to it, so a 'PackumentDeps' schema
change lands in one place. 'npmServeDeps' and 'inertPackumentDeps' are npm's aliases.

== The inert deps

'inertDepsFor' is complete but __unreachable__: every upstream it names is a closed port. A
'Ecluse.Core.Server.Context.MountBinding' always carries packument dependencies, so a spec that
never drives the data plane must still supply them. A spec that /does/ drive it builds its own
through 'serveDepsFor' against a live stub upstream.

== Varying an upstream

'withPrivateBaseUrl', 'overPrivateBaseUrl', 'withMirrorPlan', and 'withEcosystemHosts' each
rebind the deps' whole upstream cluster through 'mountUpstreams', so the tarball-host gate
re-derives with the URL. A fixture cannot express a stale gate, because the cluster's
constructor is private and its selectors are not exported. See "Ecluse.Core.Server.Upstream".
-}
module Ecluse.Test.Server.Mount (
    serveDepsFor,
    inertDepsFor,
    npmServeDeps,
    pypiServeDeps,
    inertPackumentDeps,
    withPrivateBaseUrl,
    overPrivateBaseUrl,
    withMirrorPlan,
    withEcosystemHosts,
) where

import Data.Time (UTCTime (UTCTime), fromGregorian)

import Ecluse.Core.Package.Merge (DivergencePolicy (Warn))
import Ecluse.Core.Registry.Adapter.Types (AdapterArtifact (artifactHosts), RegistryAdapter (adapterArtifact, adapterMetadata))
import Ecluse.Core.Registry.Npm.Adapter (npmAdapter)
import Ecluse.Core.Registry.PyPI.Adapter (pypiAdapter)
import Ecluse.Core.Rules (PreparedRule)
import Ecluse.Core.Security (defaultLimits)
import Ecluse.Core.Security.Egress (RegistryUrl, mkRegistryUrl)
import Ecluse.Core.Security.Egress.DevHttp (loopbackRegistryUrl)
import Ecluse.Core.Server.Context (PackumentDeps (..), pdMirror, pdPrivateBaseUrl, pdPublicBaseUrl)
import Ecluse.Core.Server.Upstream (MirrorServePlan (MirrorOnAdmit), mountUpstreams)
import Ecluse.Test.Package (defaultMinIntegrity, defaultMinTrustedIntegrity)

{- | A mount's serve dependencies over @adapter@. The upstreams, mirror plan, rules, and clock
are parameters, and the rest carry defaults.
-}
serveDepsFor :: RegistryAdapter -> Maybe RegistryUrl -> RegistryUrl -> MirrorServePlan -> [PreparedRule] -> IO UTCTime -> PackumentDeps
serveDepsFor adapter privateBaseUrl publicBaseUrl mirror rules clock =
    PackumentDeps
        { -- The adapter's own declared artifact hosts, so a fixture's gate honours exactly what
          -- the composition root's would. 'withEcosystemHosts' varies them where a spec must.
          pdUpstreams = mountUpstreams (artifactHosts (adapterArtifact adapter)) privateBaseUrl publicBaseUrl mirror
        , -- Deny by default, matching a mount that declares no namespaces. A spec pinning the
          -- privilege record-updates this field.
          pdFirstParty = const False
        , pdMountBaseUrl = "https://proxy.test"
        , pdRules = rules
        , pdAdditionalBlockedRanges = []
        , pdLimits = defaultLimits
        , pdInboundToken = Nothing
        , pdNow = clock
        , pdAdvisoryEtag = pure Nothing
        , pdHelp = Nothing
        , pdMinIntegrity = defaultMinIntegrity
        , pdMinTrustedIntegrity = defaultMinTrustedIntegrity
        , pdDivergencePolicy = Warn
        , pdMetadata = adapterMetadata adapter
        , pdArtifact = adapterArtifact adapter
        , pdEgressUrl = mkRegistryUrl
        }

-- | 'serveDepsFor' over 'Ecluse.Core.Registry.Npm.Adapter.npmAdapter'.
npmServeDeps :: Maybe RegistryUrl -> RegistryUrl -> MirrorServePlan -> [PreparedRule] -> IO UTCTime -> PackumentDeps
npmServeDeps = serveDepsFor npmAdapter

-- | 'serveDepsFor' over 'Ecluse.Core.Registry.PyPI.Adapter.pypiAdapter'.
pypiServeDeps :: Maybe RegistryUrl -> RegistryUrl -> MirrorServePlan -> [PreparedRule] -> IO UTCTime -> PackumentDeps
pypiServeDeps = serveDepsFor pypiAdapter

{- | A mount's serve dependencies wired to nowhere: a closed loopback port for every base URL, an
empty rule set, and a fixed clock. It is complete enough to bind a
'Ecluse.Core.Server.Context.MountBinding', but a packument or artifact request through it fails to
connect instead of reaching an upstream.
-}
inertDepsFor :: RegistryAdapter -> PackumentDeps
inertDepsFor adapter =
    (serveDepsFor adapter (Just closedPort) closedPort (MirrorOnAdmit closedPort) [] (pure fixedNow))
        { pdMountBaseUrl = "http://proxy.invalid"
        }
  where
    -- Port 1 is reserved and never listening, so a fetch through these deps fails to
    -- connect rather than reaching anything.
    closedPort = loopbackRegistryUrl "http://localhost:1"

    fixedNow :: UTCTime
    fixedNow = UTCTime (fromGregorian 2020 1 1) 0

-- | 'inertDepsFor' over 'Ecluse.Core.Registry.Npm.Adapter.npmAdapter'.
inertPackumentDeps :: PackumentDeps
inertPackumentDeps = inertDepsFor npmAdapter

{- | Rebind a fixture's upstreams with the private base URL replaced. The rebind drops any declared
ecosystem artifact hosts, so a fixture that wants both applies 'withEcosystemHosts' last.
-}
withPrivateBaseUrl :: Maybe RegistryUrl -> PackumentDeps -> PackumentDeps
withPrivateBaseUrl privateBaseUrl = rebind [] (const privateBaseUrl) id

{- | 'withPrivateBaseUrl' deriving the new private base URL from the old. A mount with no
private upstream stays without one, and declared ecosystem artifact hosts are dropped.
-}
overPrivateBaseUrl :: (RegistryUrl -> RegistryUrl) -> PackumentDeps -> PackumentDeps
overPrivateBaseUrl f = rebind [] (fmap f) id

{- | Rebind a fixture's upstreams with the mirror serve plan replaced. It drops any
declared ecosystem artifact hosts, as 'withPrivateBaseUrl' does.
-}
withMirrorPlan :: MirrorServePlan -> PackumentDeps -> PackumentDeps
withMirrorPlan mirror = rebind [] id (const mirror)

{- | Rebind a fixture's upstreams declaring the given ecosystem artifact hosts, which join the
gate's allowlist. The upstream URLs carry over unchanged.
-}
withEcosystemHosts :: [Text] -> PackumentDeps -> PackumentDeps
withEcosystemHosts ecosystemHosts = rebind ecosystemHosts id id

-- The one rebinding point every fixture tweak routes through, so the gate derives from what the
-- result carries. The cluster does not carry the ecosystem hosts, so each rebind states or drops
-- them.
rebind :: [Text] -> (Maybe RegistryUrl -> Maybe RegistryUrl) -> (MirrorServePlan -> MirrorServePlan) -> PackumentDeps -> PackumentDeps
rebind ecosystemHosts onPrivate onMirror d =
    d{pdUpstreams = mountUpstreams ecosystemHosts (onPrivate (pdPrivateBaseUrl d)) (pdPublicBaseUrl d) (onMirror (pdMirror d))}
