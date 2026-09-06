-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Wiring a per-request "Ecluse.Core.Registry.Metadata.MetadataClient" for the serve
path: the cross-cutting caching, metrics, and failure-logging policy wrapped around a
registry's raw fetch primitive.

The read boundary's /type/ lives in the registry layer (agnostic). A registry's raw
fetch primitive lives with that registry (npm's in
"Ecluse.Core.Registry.Npm.Metadata"). What lives __here__ is the serve-path policy
that is the same regardless of ecosystem. That policy covers whether an origin resolves
through the shared metadata cache, recording the upstream-fetch metrics, and logging a
failure once in the request's context. Keeping that policy in the serve layer is what lets the
registry layer stay free of the cache and telemetry.

The two operations differ in how they resolve. The full-manifest op resolves the whole
packument through the shared full-packument cache. The single-version op takes a
__hybrid__ path, so a cold tarball gate need not pay a whole-packument decode to consult
one version (see 'newMetadataClient'). It consults a small @(package, version)@ cache,
then the warm full-packument cache __read-only__. A packument @GET@ followed by its
tarball gate therefore still collapses to one upstream call. Only on a cold miss does it
lead its own __selective__ fetch into the @(package, version)@ cache. That fetch parses
just the requested version out of the full bytes, and never writes the whole packument
back to the shared cache.
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
    MetadataError (MetadataBoundExceeded, MetadataFetch, MetadataNameMismatch, MetadataUndecodable),
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

{- | How a read handle resolves the full manifest for one origin. The private origin is the
per-client authority and must never be shared, and the public origin is anonymous and shared.
-}
data ManifestCaching
    = {- | Resolve directly, uncached: the per-client private origin. It is re-fetched
      every request, so the upstream re-authorises each client's own forwarded credential.
      -}
      Uncached
    | {- | Resolve through the shared metadata cache under the origin's 'Source' key:
      the anonymous public origin. Concurrent and subsequent reads therefore collapse to
      one upstream call, and both operations of the resulting handle share this one entry.
      -}
      Cached MetadataCache Source

{- | Build a per-request read handle from a registry's raw fetch primitives, wired with the
caching policy, the upstream-fetch metrics, and a request-context failure log.

The single-version op tries the @(package, version)@ cache, then the full-packument cache
read-only, then a cold selective fetch. It never writes a whole packument back to the shared
cache, and every log runs once per real fetch inside the single-flight leader.
-}
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

    -- The full-manifest single-flight leader: it runs only on a cache miss. A failure is logged
    -- once here, and the cache stores nothing and hands the same 'Left' to every coalesced
    -- follower.
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
                    -- (2) The warm full-packument cache, read-only: select the version
                    -- from the shared entry the packument @GET@ populated. Nothing is
                    -- written back to the version cache, the install one-call property.
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

{- | Select one version's details out of a parsed packument, by its rendered form. The store
sweep projects every version it decides out of one manifest through this.
-}
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
    MetadataUndecodable -> Metric.Decode
    MetadataNameMismatch _ -> Metric.Decode
    MetadataBoundExceeded _ -> Metric.OtherCause
    MetadataFetch (FetchUrlUnformable _) -> Metric.OtherCause
    MetadataFetch (FetchBoundExceeded _) -> Metric.OtherCause
    MetadataFetch (FetchTransport _) -> Metric.Connection
