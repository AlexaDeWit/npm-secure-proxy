-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Caching, metrics, and failure logs around registry metadata reads.
Private reads remain uncached. Anonymous public reads share full-document and version caches.
-}
module Ecluse.Core.Server.Metadata (
    -- * Caching policy
    ManifestCaching (..),

    -- * Constructing a per-request read handle
    newMetadataClient,

    -- * Projecting one version
    selectVersion,
) where

import Data.Map.Strict qualified as Map

import Ecluse.Core.Package (InvalidEntry, PackageDetails, PackageInfo (infoInvalidEntries, infoVersions), PackageName)
import Ecluse.Core.Registry (FetchFault (FetchBoundExceeded, FetchTransport, FetchUrlUnformable))
import Ecluse.Core.Registry.Metadata (
    Manifest (Manifest, manifestDigest, manifestInfo, manifestRaw),
    MetadataClient (..),
    MetadataError (MetadataAuthorisationFailure, MetadataBoundExceeded, MetadataFetch, MetadataNameMismatch, MetadataUndecodable),
 )

import Ecluse.Core.Server.Cache (
    CacheEntry (CacheEntry, entryDigest, entryInfo, entryRaw),
    MetadataCache,
    Source,
    cachedMetadata,
    cachedVersion,
    resolveMetadata,
    resolveVersion,
 )
import Ecluse.Core.Telemetry.Metrics qualified as Metric
import Ecluse.Core.Telemetry.Record (MetricsPort (..), timedSeconds)
import Ecluse.Core.Version (Version, renderVersion)

-- | Private reads require per-client authorisation. Only anonymous public metadata may use the shared cache.
data ManifestCaching
    = -- | Re-authorise the caller at the private upstream on every request.
      Uncached
    | -- | Resolve through the shared metadata cache under the origin's 'Source' key: the anonymous public origin.
      Cached MetadataCache Source

-- | Apply caching, failure logging, and metrics to the adapter's metadata reads.
newMetadataClient ::
    MetricsPort ->
    Metric.Upstream ->
    ManifestCaching ->
    (PackageName -> MetadataError -> IO ()) ->
    (PackageName -> [InvalidEntry] -> IO ()) ->
    (PackageName -> IO ()) ->
    (PackageName -> IO (Either MetadataError Manifest)) ->
    (PackageName -> Version -> IO (Either MetadataError (Maybe PackageDetails))) ->
    MetadataClient
newMetadataClient metrics upstream caching logFailure logInvalid logFetch rawFetch rawFetchVersion =
    MetadataClient
        { fetchFullManifest = fmap (fmap entryToManifest) . resolveEntry
        , fetchVersionMetadata = resolveVersionHybrid
        }
  where
    resolveEntry :: PackageName -> IO (Either MetadataError CacheEntry)
    resolveEntry name = case caching of
        Uncached -> manifestLeader name
        Cached cache source -> resolveMetadata metrics cache source name (manifestLeader name)

    manifestLeader :: PackageName -> IO (Either MetadataError CacheEntry)
    manifestLeader name = do
        logFetch name
        recordedFetch metrics upstream $
            rawFetch name >>= \case
                Right manifest -> do
                    let invalid = infoInvalidEntries (manifestInfo manifest)
                    unless (null invalid) (logInvalid name invalid)
                    pure (Right (CacheEntry (manifestInfo manifest) (manifestRaw manifest) (manifestDigest manifest)))
                Left err -> logFailure name err >> pure (Left err)

    -- The single-version hybrid: the small version cache, then the warm full cache
    -- read-only, then a cold selective fetch. Uncached, it is the raw selective fetch.
    resolveVersionHybrid :: PackageName -> Version -> IO (Either MetadataError (Maybe PackageDetails))
    resolveVersionHybrid name version = case caching of
        Uncached -> versionLeader name version
        Cached cache source -> do
            -- (1) The single-version cache: a positive snapshot or a cached determined
            -- absence both short-circuit.
            cached <- cachedVersion cache source name version
            case cached of
                Just details -> pure (Right details)
                Nothing -> do
                    warm <- cachedMetadata cache source name
                    case warm of
                        Just entry -> pure (Right (selectVersion version (entryInfo entry)))
                        -- (3) Cold: lead the selective fetch through the version cache.
                        Nothing -> resolveVersion metrics cache source name version (versionLeader name version)

    -- The single-version single-flight leader: run only on a cold miss, logging a failure once.
    versionLeader :: PackageName -> Version -> IO (Either MetadataError (Maybe PackageDetails))
    versionLeader name version = do
        logFetch name
        recordedFetch metrics upstream $
            rawFetchVersion name version >>= \case
                Right details -> pure (Right details)
                Left err -> logFailure name err >> pure (Left err)

-- | Find a version by its ecosystem-rendered key in a package snapshot.
selectVersion :: Version -> PackageInfo -> Maybe PackageDetails
selectVersion version info = Map.lookup (renderVersion version) (infoVersions info)

-- Widen a cached entry back to the read handle's 'Manifest'. The same three fields,
-- named for the boundary each type serves: the cache stores, the handle answers.
entryToManifest :: CacheEntry -> Manifest
entryToManifest entry =
    Manifest
        { manifestInfo = entryInfo entry
        , manifestRaw = entryRaw entry
        , manifestDigest = entryDigest entry
        }

{- Record one upstream metadata fetch around a leader action: its latency on success, or the
bounded error cause otherwise. The leader runs only on a miss, so this never meters a cache hit. -}
recordedFetch :: MetricsPort -> Metric.Upstream -> IO (Either MetadataError a) -> IO (Either MetadataError a)
recordedFetch metrics upstream action = do
    (result, seconds) <- timedSeconds action
    case result of
        Right _ -> mpUpstreamFetch metrics upstream Metric.Status2xx seconds
        Left err -> mpUpstreamFetchError metrics upstream (metadataErrorCause err)
    pure result

{- Classify a leader-fetch failure into the bounded @ecluse.upstream.fetch.errors@ cause. It reads
the typed 'MetadataError', never error text, so the label set stays bounded by construction. -}
metadataErrorCause :: MetadataError -> Metric.Cause
metadataErrorCause = \case
    MetadataAuthorisationFailure _ -> Metric.OtherCause
    MetadataUndecodable -> Metric.Decode
    MetadataNameMismatch _ -> Metric.Decode
    MetadataBoundExceeded _ -> Metric.OtherCause
    MetadataFetch (FetchUrlUnformable _) -> Metric.OtherCause
    MetadataFetch (FetchBoundExceeded _) -> Metric.OtherCause
    MetadataFetch (FetchTransport _) -> Metric.Connection
