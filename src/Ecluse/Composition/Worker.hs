-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The composition root's worker bundle construction: the per-ecosystem 'WorkerPolicies'
the mirror worker dispatches every job through.

'Ecluse.Service.withServiceRuntime' consumes it for every role, so the embedded and the
dedicated worker dispatch through one construction. Only the composition root consumes the
adapter registry: the worker receives plain handles. Each bundle reuses its mount's __own__
'PackumentDeps', so the ingest decision cannot diverge from the serve decision.
-}
module Ecluse.Composition.Worker (
    workerPoliciesFor,
    mirrorTransportFor,
) where

import Data.Map.Strict qualified as Map

import Ecluse.Composition (PublishTarget (ptCredentials, ptEcosystem, ptMirrorUrl))
import Ecluse.Core.Credential (mintSecret)
import Ecluse.Core.Ecosystem (Ecosystem, parseEcosystem)
import Ecluse.Core.Registry.Adapter (adapterFor, adapterPublish, publishCodec)
import Ecluse.Core.Registry.Adapter.Capability (AdapterMetadata (metadataNewClient))
import Ecluse.Core.Registry.Metadata (fetchVersionDetails)
import Ecluse.Core.Registry.Origin (originClient)
import Ecluse.Core.Registry.Publish (
    MirrorPublish,
    MirrorTransport (MirrorTransport, ptLimits, ptManager, ptMintToken),
    newMirrorPublish,
 )
import Ecluse.Core.Security (Limits (maxBodyBytes), Origin (UntrustedOrigin), defaultLimits, thgPublicHostPort)
import Ecluse.Core.Security.Egress (registryUrlText)
import Ecluse.Core.Server.Cache (Source (Source))
import Ecluse.Core.Server.Context (
    PackumentDeps,
    pdArtifact,
    pdFirstParty,
    pdLimits,
    pdMetadata,
    pdMinIntegrity,
    pdNow,
    pdPublicBaseUrl,
    pdRules,
    pdTarballHostGate,
    tarballHostHonoured,
 )
import Ecluse.Core.Server.Metadata (ManifestCaching (Cached))
import Ecluse.Core.Telemetry.Metrics (Upstream (Public))
import Ecluse.Core.Worker (WorkerPolicies, WorkerPolicy (..))
import Ecluse.Runtime.Env (Env, envManager, envMetadataCache, envMetrics, envPrivateManager, envTelemetry)
import Ecluse.Runtime.Server (MountBinding (bindingPackumentDeps, bindingPrefix))
import Ecluse.Runtime.Telemetry.Instruments (metricsPortOf)
import Ecluse.Runtime.Telemetry.Tracing (tracingPortOf)

{- | Build the worker's per-ecosystem bundles from the served mounts and the resolved
publish targets, keyed by the ecosystem each mount's path prefix names. A job for an
ecosystem absent here is fail-closed at the worker.
-}
workerPoliciesFor :: Env -> [MountBinding] -> [PublishTarget] -> Int -> WorkerPolicies
workerPoliciesFor env bindings targets artifactMaxBytes =
    Map.fromList
        [ (eco, workerPolicyFor env deps publish artifactMaxBytes)
        | binding <- bindings
        , let prefixHead :| _ = bindingPrefix binding
        , let deps = bindingPackumentDeps binding
        , Just eco <- [parseEcosystem prefixHead]
        , Just publish <- [mirrorPublishFor env deps targetsByEcosystem eco]
        ]
  where
    targetsByEcosystem = Map.fromList [(ptEcosystem target, target) | target <- targets]

{- Marry one ecosystem's mirror write to the shared publish transport. 'Nothing' when it
resolves no publish target or no adapter, so the caller wires no half-publish bundle. -}
mirrorPublishFor :: Env -> PackumentDeps -> Map.Map Ecosystem PublishTarget -> Ecosystem -> Maybe MirrorPublish
mirrorPublishFor env deps targets eco = do
    target <- Map.lookup eco targets
    adapter <- adapterFor eco
    publish <- adapterPublish adapter
    pure (newMirrorPublish (mirrorTransportFor env deps target) (ptMirrorUrl target) (publishCodec publish))

{- | The shared mirror-write transport for one mount. The presence probe reads under the
mount's own 'pdLimits', because the shipped metadata-path default would let a larger
mirror packument overrun the bound and defeat duplicate suppression.
-}
mirrorTransportFor :: Env -> PackumentDeps -> PublishTarget -> MirrorTransport
mirrorTransportFor env deps target =
    MirrorTransport
        { ptManager = envPrivateManager env
        , ptMintToken = Just <$> mintSecret (ptCredentials target)
        , ptLimits = pdLimits deps
        }

{- Build one mount's worker bundle. The metadata client is anonymous, so no client credential
reaches the public origin, and the host allowlist gates it with certificate validation
authenticating the dialled host. The no-op callbacks elide the client's own failure and
dropped-entry logs, because the worker logs its re-evaluation outcome per job. -}
workerPolicyFor :: Env -> PackumentDeps -> MirrorPublish -> Int -> WorkerPolicy
workerPolicyFor env deps publish artifactMaxBytes =
    WorkerPolicy
        { -- The mount's own first-party predicate, so the worker refuses a name the
          -- deployment owns exactly as the serve and publish paths do.
          wpFirstParty = pdFirstParty deps
        , wpResolveVersion = fetchVersionDetails client
        , wpRules = pdRules deps
        , wpMinIntegrity = pdMinIntegrity deps
        , wpArtifactHostHonoured =
            -- The same host gate the serve path applies before its public artifact fetch, closed
            -- against the public upstream authority.
            tarballHostHonoured UntrustedOrigin deps (thgPublicHostPort (pdTarballHostGate deps))
        , -- The mount's own artifact capability, the adapter record the serve deps
          -- carry, so the worker fetches a job's bytes exactly as the serve path would.
          wpArtifact = pdArtifact deps
        , wpPublish = publish
        , -- The artifact fetch cap comes from the memory plan's mirror-artifact tenant,
          -- not the metadata-path default, because a tarball far exceeds the packument cap. The
          -- other limits do not apply to an opaque tarball, so they stay at their defaults.
          wpArtifactLimits = defaultLimits{maxBodyBytes = artifactMaxBytes}
        , wpNow = pdNow deps
        }
  where
    client =
        metadataNewClient
            (pdMetadata deps)
            (tracingPortOf (envTelemetry env))
            (metricsPortOf (envMetrics env))
            Public
            (Cached (envMetadataCache env) (Source (registryUrlText publicBaseUrl)))
            (\_ _ -> pure ())
            (\_ _ -> pure ())
            (\_ -> pure ())
            publicOrigin

    publicBaseUrl = pdPublicBaseUrl deps

    publicOrigin = originClient (pdLimits deps) (envManager env) publicBaseUrl Nothing
