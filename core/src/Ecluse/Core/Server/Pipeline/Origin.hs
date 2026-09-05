-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Resolving a packument's upstream origins:

* the per-origin fetch with its credential posture
* the read-handle construction over the mount's dependencies
* the typed outcome the merge consumes

The credential-authority invariant lives here (see
@docs\/architecture\/registry-model.md@ → "Credential flow and authority"). The private (trusted) origin is fetched
__uncached__ with the client's own forwarded credential, so the upstream re-authorises
every client itself. The public origin is fetched __anonymous__: the client's credential
is stripped before any public-upstream fetch. It resolves through the shared metadata
cache, one shared document serving every client. A fetch that fails degrades to no
contribution rather than an error. A self-reported /different/ package name stays distinct
('OriginNameMismatch'), so the no-valid-origin terminal can render a @502@ apart from a
transient outage.

"Ecluse.Core.Server.Pipeline.Packument" gates, merges, and serves what resolves here.
"Ecluse.Core.Server.Pipeline.Tarball" shares the public read handle
('withPublicMetadataClient'), so its single-version gate and the packument fetch collapse
onto one cache entry.
-}
module Ecluse.Core.Server.Pipeline.Origin (
    -- * A resolved contribution
    Contribution (..),
    fingerprintPiece,

    -- * The per-origin outcome
    OriginResult (..),
    originManifest,
    originMissed,

    -- * Fetching the two origins
    fetchPrivateOrigin,
    fetchPublicOrigin,
    withPublicMetadataClient,
    withPrivateMetadataClient,

    -- * One origin's coordinates
    mountOrigin,
) where

import Data.Map.Strict qualified as Map
import Katip (Severity (DebugS), logFM, ls)
import Network.HTTP.Client (Manager)
import UnliftIO (withRunInIO)
import UnliftIO.Exception (tryAny)

import Ecluse.Core.Credential (ClientCredential)
import Ecluse.Core.Package (PackageInfo (infoVersions), PackageName, renderPackageName)
import Ecluse.Core.Package.Merge (Provenance)
import Ecluse.Core.Registry.Adapter.Capability (AdapterMetadata (metadataNewClient))
import Ecluse.Core.Registry.CachedDocument (CachedDoc)
import Ecluse.Core.Registry.Metadata (
    ContentDigest,
    Manifest,
    MetadataClient (fetchFullManifest),
    MetadataError (MetadataNameMismatch),
 )
import Ecluse.Core.Registry.Origin (OriginClient (ocBaseUrl), originClient)
import Ecluse.Core.Security.Egress (RegistryUrl, registryUrlText)
import Ecluse.Core.Server.Cache (Source (Source))
import Ecluse.Core.Server.Context (
    Handler,
    PackumentDeps (..),
    ServeRuntime (..),
    pdPrivateBaseUrl,
    pdPublicBaseUrl,
 )
import Ecluse.Core.Server.Metadata (ManifestCaching (Cached, Uncached))
import Ecluse.Core.Server.Pipeline.Diagnostics (logInvalidEntries, logMetadataFailure)
import Ecluse.Core.Telemetry.Metrics qualified as Metric

{- | A resolved upstream contribution: the parsed packument the pipeline decides over, the
raw document its served body is rebuilt from, and the origin body's digest for the derived
validator. The raw document travels opaquely, so the pipeline never reads it and only hands
it to the injected adapter capabilities.
-}
data Contribution = Contribution
    { srcProvenance :: Provenance
    , srcInfo :: PackageInfo
    , srcValue :: CachedDoc
    , srcDigest :: ContentDigest
    }

{- | One source's slice of the derived validator. With the mount base URL and the package
name, these are exactly the inputs the assembled document is a deterministic function of.
-}
fingerprintPiece :: Contribution -> (Provenance, ContentDigest, [Text])
fingerprintPiece s = (srcProvenance s, srcDigest s, Map.keys (infoVersions (srcInfo s)))

{- | The outcome of resolving one upstream origin for a packument. A name mismatch stays
distinct, so the no-valid-origin terminal status can render a @502@ instead of treating a
wrong-package answer as a transient outage.
-}
data OriginResult
    = -- | A packument that decoded and whose self-reported name matched the request.
      OriginResolved Manifest
    | {- | The origin answered, but its packument self-reported a name for a /different/
      package. It is dropped as untrusted for this request, and it is the @502@ signal
      when no origin is valid.
      -}
      OriginNameMismatch
    | {- | The origin did not yield a usable packument: unreachable, undecodable, or a
      genuine absence. It degrades to no contribution.
      -}
      OriginUnresolved
    | {- | The origin is not configured on this mount (a serve-only mount with no private
      upstream). Structurally absent, kept distinct from 'OriginUnresolved' so an
      unconfigured leg never contributes the degraded-availability signal a __failed__
      fetch rightly does.
      -}
      OriginAbsent

-- | The resolved manifest an origin contributed, if any.
originManifest :: OriginResult -> Maybe Manifest
originManifest = \case
    OriginResolved manifest -> Just manifest
    OriginNameMismatch -> Nothing
    OriginUnresolved -> Nothing
    OriginAbsent -> Nothing

{- | Whether an origin yielded no document and claimed nothing about a different package. An
unreachable upstream lands here too: nothing else may answer for a single-authority name.
-}
originMissed :: OriginResult -> Bool
originMissed = \case
    OriginResolved{} -> False
    OriginNameMismatch -> False
    OriginUnresolved -> True
    OriginAbsent -> True

{- Every fetch outcome arrives typed in the 'MetadataError' channel, so the exception arm
catches an invariant break only. A handle that escapes its contract costs one origin's
contribution, never the whole merge. -}
originResultOf :: Either SomeException (Either MetadataError Manifest) -> OriginResult
originResultOf = \case
    Left _ -> OriginUnresolved
    Right (Left (MetadataNameMismatch _)) -> OriginNameMismatch
    Right (Left _) -> OriginUnresolved
    Right (Right manifest) -> OriginResolved manifest

{- | Resolve the private (trusted) upstream origin, __uncached__, forwarding the client's own
credential (the @passthrough@ posture). A failed fetch degrades to no contribution
rather than an error.

Under @passthrough@ the private upstream is the per-client authority for who may read what.
The metadata cache keys on the base URL alone, with no credential dimension, so a cached
private document would let one client's hit serve another client's document and bypass that
authorisation.
-}
fetchPrivateOrigin :: PackumentDeps -> ServeRuntime -> Maybe ClientCredential -> PackageName -> Handler OriginResult
fetchPrivateOrigin deps rt token name = case pdPrivateBaseUrl deps of
    -- No private upstream on this mount (a serve-only pure public gate): the leg is
    -- structurally absent, so this constructs no client and attempts no fetch.
    Nothing -> pure OriginAbsent
    Just privateBase -> do
        logFM DebugS (ls ("fetching private origin for " <> renderPackageName name))
        resolved <-
            tryAny $
                withPrivateMetadataClient rt deps privateBase token $ \client ->
                    fetchFullManifest client name
        pure (originResultOf resolved)

{- | Resolve the public (gated, anonymous) upstream origin through the metadata cache, keyed
by the origin's base URL as its 'Source'. The origin carries no client credential, so one
entry serves every client without crossing a trust boundary, and a hit keeps the typed view
coherent with the bytes it decoded from.
-}
fetchPublicOrigin :: PackumentDeps -> ServeRuntime -> PackageName -> Handler OriginResult
fetchPublicOrigin deps rt name = do
    logFM DebugS (ls ("fetching public origin for " <> renderPackageName name))
    resolved <-
        tryAny $
            withPublicMetadataClient rt deps (pdPublicBaseUrl deps) $ \client ->
                fetchFullManifest client name
    pure (originResultOf resolved)

{- Run an action over a per-request read handle for one origin. 'withRunInIO' captures the
request's @katip@ context into the failure logs, and the fetch holds the mount's 'Limits'. -}
withMetadataClient ::
    ServeRuntime ->
    PackumentDeps ->
    Metric.Upstream ->
    ManifestCaching ->
    OriginClient ->
    (MetadataClient -> IO a) ->
    Handler a
withMetadataClient rt deps upstream caching origin k =
    withRunInIO $ \runInIO ->
        k $
            metadataNewClient
                (pdMetadata deps)
                (srTracing rt)
                (srMetrics rt)
                upstream
                caching
                (\nm err -> runInIO (logMetadataFailure nm baseUrl err))
                (\nm entries -> runInIO (logInvalidEntries nm baseUrl entries))
                (\nm -> runInIO (logFM DebugS (ls ("fetching packument from origin for " <> renderPackageName nm))))
                origin
  where
    -- The log lines name the origin, and a diagnostic reads characters, not a witness.
    baseUrl = registryUrlText (ocBaseUrl origin)

{- | The private origin's read handle: __uncached__, carrying the client's own credential. The
private upstream is the per-client authority for who may read what, and the metadata cache keys
on the base URL with no credential dimension, so one client's entry must never serve another's.
-}
withPrivateMetadataClient :: ServeRuntime -> PackumentDeps -> RegistryUrl -> Maybe ClientCredential -> (MetadataClient -> IO a) -> Handler a
withPrivateMetadataClient rt deps baseUrl token =
    withMetadataClient rt deps Metric.Private Uncached (mountOrigin deps (srPrivateManager rt) baseUrl token)

{- | The public origin's read handle: anonymous, resolved through the shared metadata cache
under the base URL's 'Source'. Both 'fetchFullManifest' and the tarball gate's
'fetchVersionMetadata' go through it, so they share one cache entry.
-}
withPublicMetadataClient :: ServeRuntime -> PackumentDeps -> RegistryUrl -> (MetadataClient -> IO a) -> Handler a
withPublicMetadataClient rt deps baseUrl =
    withMetadataClient rt deps Metric.Public caching (mountOrigin deps (srPublicManager rt) baseUrl Nothing)
  where
    caching = Cached (srMetadataCache rt) (Source (registryUrlText baseUrl))

{- | One origin's coordinates for this mount: its own response bound, the leg's manager, and
the credential posture the caller decided. The artifact path forms its request through it too.
-}
mountOrigin :: PackumentDeps -> Manager -> RegistryUrl -> Maybe ClientCredential -> OriginClient
mountOrigin deps = originClient (pdLimits deps)
