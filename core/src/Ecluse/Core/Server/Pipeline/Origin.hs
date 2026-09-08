-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Resolve metadata origins with their credential posture and typed outcomes.
Private reads forward the caller's credential without caching. Public reads are anonymous.
Explicit access refusals remain distinct for the packument pipeline.
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
    MetadataError (MetadataAuthorisationFailure, MetadataNameMismatch),
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

-- | A parsed contribution with opaque source bytes and a digest for the derived validator.
data Contribution = Contribution
    { srcProvenance :: Provenance
    , srcInfo :: PackageInfo
    , srcValue :: CachedDoc
    , srcDigest :: ContentDigest
    }

-- | One source's slice of the derived validator. With the mount base URL and the package name, these are exactly the inputs the assembled document is a deterministic function of.
fingerprintPiece :: Contribution -> (Provenance, ContentDigest, [Text])
fingerprintPiece s = (srcProvenance s, srcDigest s, Map.keys (infoVersions (srcInfo s)))

-- | One origin's contribution, access refusal, identity mismatch, or absence.
data OriginResult
    = -- | A packument that decoded and whose self-reported name matched the request.
      OriginResolved Manifest
    | -- | An explicit upstream access refusal, retaining its 401 or 403.
      OriginAuthorisationFailure Int
    | -- | An invalid package identity, contributing a 502 when no valid origin remains.
      OriginNameMismatch
    | -- | The origin did not yield a usable packument: unreachable, undecodable, or a genuine absence. It degrades to no contribution.
      OriginUnresolved
    | -- | An unconfigured origin contributes neither metadata nor an availability failure.
      OriginAbsent

-- | The resolved manifest an origin contributed, if any.
originManifest :: OriginResult -> Maybe Manifest
originManifest = \case
    OriginAuthorisationFailure _ -> Nothing
    OriginResolved manifest -> Just manifest
    OriginNameMismatch -> Nothing
    OriginUnresolved -> Nothing
    OriginAbsent -> Nothing

-- | Whether an origin yielded neither a document nor an explicit access or identity refusal.
originMissed :: OriginResult -> Bool
originMissed = \case
    OriginAuthorisationFailure _ -> False
    OriginResolved{} -> False
    OriginNameMismatch -> False
    OriginUnresolved -> True
    OriginAbsent -> True

originResultOf :: Either SomeException (Either MetadataError Manifest) -> OriginResult
originResultOf = \case
    Left _ -> OriginUnresolved
    Right (Left (MetadataAuthorisationFailure code)) -> OriginAuthorisationFailure code
    Right (Left (MetadataNameMismatch _)) -> OriginNameMismatch
    Right (Left _) -> OriginUnresolved
    Right (Right manifest) -> OriginResolved manifest

-- | Resolve the private origin uncached with the caller's credential, retaining explicit access refusals.
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

-- | Resolve the public (gated, anonymous) upstream origin through the metadata cache, keyed by the origin's base URL as its 'Source'.
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

-- | The private origin's read handle: uncached, carrying the client's own credential, because the cache keys on the base URL alone and one client's entry must never serve another's.
withPrivateMetadataClient :: ServeRuntime -> PackumentDeps -> RegistryUrl -> Maybe ClientCredential -> (MetadataClient -> IO a) -> Handler a
withPrivateMetadataClient rt deps baseUrl token =
    withMetadataClient rt deps Metric.Private Uncached (mountOrigin deps (srPrivateManager rt) baseUrl token)

-- | An anonymous read handle sharing the metadata cache across listing and artifact requests.
withPublicMetadataClient :: ServeRuntime -> PackumentDeps -> RegistryUrl -> (MetadataClient -> IO a) -> Handler a
withPublicMetadataClient rt deps baseUrl =
    withMetadataClient rt deps Metric.Public caching (mountOrigin deps (srPublicManager rt) baseUrl Nothing)
  where
    caching = Cached (srMetadataCache rt) (Source (registryUrlText baseUrl))

-- | One origin's coordinates for this mount: its own response bound, the leg's manager, and the credential posture the caller decided. The artifact path forms its request through it too.
mountOrigin :: PackumentDeps -> Manager -> RegistryUrl -> Maybe ClientCredential -> OriginClient
mountOrigin deps = originClient (pdLimits deps)
