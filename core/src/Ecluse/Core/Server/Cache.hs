-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Three isolated metadata stores share TTL and single-flight machinery.
Public metadata and content-addressed responses follow the sharing policy in the web-layer architecture.
-}
module Ecluse.Core.Server.Cache (
    -- * Configuration
    CacheConfig (..),
    StoreBudget (..),

    -- * The cache handle
    MetadataCache,
    newMetadataCache,

    -- * Cache entries
    Source (..),
    CacheEntry (..),
    weighCacheEntry,

    -- * Resolution
    resolveMetadata,
    cachedMetadata,

    -- * Single-version resolution
    resolveVersion,
    cachedVersion,

    -- * Assembled-representation resolution
    resolveAssembled,
) where

import Data.ByteString qualified as BS
import Data.Text.Short qualified as TS
import Data.Time (NominalDiffTime)

import Ecluse.Core.Package (
    PackageDetails,
    PackageInfo,
    PackageName,
    pkgCanonical,
    pkgEcosystem,
    pkgNamespace,
    renderScope,
 )
import Ecluse.Core.Registry.CachedDocument (CachedDoc, weighCachedDoc)
import Ecluse.Core.Registry.Metadata (ContentDigest, MetadataError)
import Ecluse.Core.Server.Cache.Store (
    CacheOccupancy (..),
    SingleFlight,
    lookupStore,
    lookupStoreTouching,
    newSingleFlight,
    resolveSingleFlight,
 )
import Ecluse.Core.Server.Cache.VersionWeight (weighVersion)
import Ecluse.Core.Server.MemoryModel (expandWireBytes)
import Ecluse.Core.Telemetry.Record (
    MetricsPort,
    mpAssembledCacheResidentBytes,
    mpCacheEntries,
    mpCacheRequest,
    mpCacheResidentBytes,
    mpVersionCacheResidentBytes,
 )
import Ecluse.Core.Version (Version, renderVersion)

-- | Limits for one store's entry count and accounted bytes.
data StoreBudget = StoreBudget
    { sbMaxEntries :: Int
    -- ^ The maximum number of distinct entries held. An insert past this evicts.
    , sbMaxBytes :: Int
    -- ^ The resident-byte budget the held entries are kept under.
    }
    deriving stock (Eq, Show)

-- | Three sub-budgets carved from one cache aggregate, with a shared TTL.
data CacheConfig = CacheConfig
    { cacheTtl :: NominalDiffTime
    , cacheFullBudget :: StoreBudget
    -- ^ The full-packument store's bounds, keyed by @(source, package)@.
    , cacheVersionBudget :: StoreBudget
    -- ^ The single-version store's bounds (retained-field accounting).
    , cacheAssembledBudget :: StoreBudget
    -- ^ The assembled-representation store's bounds (exact strict-bytes weights).
    }
    deriving stock (Eq, Show)

-- | An upstream base URL partitions entries without carrying credentials.
newtype Source = Source Text
    deriving stock (Eq, Ord, Show)

-- | A typed view paired with the raw document and digest from the same fetch.
data CacheEntry = CacheEntry
    { entryInfo :: PackageInfo
    -- ^ The typed packument view the rules and merge reason over.
    , entryRaw :: CachedDoc
    -- ^ The raw upstream document the served body is built from.
    , entryDigest :: ContentDigest
    }
    deriving stock (Eq, Show)

-- | Estimate retained bytes using the shared expansion model over the encoded raw document.
weighCacheEntry :: CacheEntry -> Int
weighCacheEntry e = weighEncodedBytes (weighCachedDoc (entryRaw e))

-- Scale through the one shared wire-to-resident model ("Ecluse.Core.Server.MemoryModel"), so this
-- weigher and the composition root's memory plan never drift on the expansion factor.
weighEncodedBytes :: Int64 -> Int
weighEncodedBytes = expandWireBytes . fromIntegral

weighAssembled :: ByteString -> Int
weighAssembled bytes = BS.length bytes + assembledEntryOverheadBytes

assembledEntryOverheadBytes :: Int
assembledEntryOverheadBytes = 256

newtype CacheKey = CacheKey Text
    deriving stock (Eq, Ord, Show)
    deriving newtype (Hashable)

keyText :: Source -> PackageName -> Text
keyText (Source source) name =
    source
        <> "\x1f"
        <> show (pkgEcosystem name)
        <> "\x1f"
        <> maybe "" renderScope (pkgNamespace name)
        <> "\x1f"
        <> TS.toText (pkgCanonical name)

-- | Project a 'Source' and a 'PackageName' to their full-packument cache key.
cacheKey :: Source -> PackageName -> CacheKey
cacheKey source name = CacheKey (keyText source name)

newtype VersionKey = VersionKey Text
    deriving stock (Eq, Ord, Show)
    deriving newtype (Hashable)

versionKey :: Source -> PackageName -> Version -> VersionKey
versionKey source name version = VersionKey (keyText source name <> "\x1f" <> renderVersion version)

-- | Isolated full-document, selected-version, and assembled-response stores.
data MetadataCache = MetadataCache
    { mcFull :: SingleFlight MetadataError CacheKey CacheEntry
    -- ^ The full-packument store, keyed by @(source, package)@.
    , mcVersion :: SingleFlight MetadataError VersionKey (Maybe PackageDetails)
    , mcAssembled :: SingleFlight Void Text ByteString
    }

-- | Build each store with its own bounds and the shared TTL.
newMetadataCache :: CacheConfig -> IO MetadataCache
newMetadataCache cfg =
    MetadataCache
        <$> newStore (cacheFullBudget cfg) weighCacheEntry
        <*> newStore (cacheVersionBudget cfg) weighVersion
        <*> newStore (cacheAssembledBudget cfg) weighAssembled
  where
    newStore :: StoreBudget -> (v -> Int) -> IO (SingleFlight e k v)
    newStore budget = newSingleFlight (cacheTtl cfg) (sbMaxEntries budget) (sbMaxBytes budget)

-- | Coalesce public metadata fetches. Failures reach all waiters and retain nothing.
resolveMetadata :: MetricsPort -> MetadataCache -> Source -> PackageName -> IO (Either MetadataError CacheEntry) -> IO (Either MetadataError CacheEntry)
resolveMetadata = resolveMetadataWith (pure ())

resolveMetadataWith :: IO () -> MetricsPort -> MetadataCache -> Source -> PackageName -> IO (Either MetadataError CacheEntry) -> IO (Either MetadataError CacheEntry)
resolveMetadataWith afterClaim metrics cache source name =
    resolveSingleFlight
        afterClaim
        (mpCacheRequest metrics)
        ( \occ -> do
            mpCacheEntries metrics (occEntries occ)
            mpCacheResidentBytes metrics (occBytes occ)
        )
        (mcFull cache)
        (cacheKey source name)

-- | Cache a selectively decoded release or its absence. Oversized releases remain uncached.
resolveVersion :: MetricsPort -> MetadataCache -> Source -> PackageName -> Version -> IO (Either MetadataError (Maybe PackageDetails)) -> IO (Either MetadataError (Maybe PackageDetails))
resolveVersion = resolveVersionWith (pure ())

resolveVersionWith :: IO () -> MetricsPort -> MetadataCache -> Source -> PackageName -> Version -> IO (Either MetadataError (Maybe PackageDetails)) -> IO (Either MetadataError (Maybe PackageDetails))
resolveVersionWith afterClaim metrics cache source name version =
    resolveSingleFlight
        afterClaim
        (const pass)
        (mpVersionCacheResidentBytes metrics . occBytes)
        (mcVersion cache)
        (versionKey source name version)

-- | Memoise a response under the content digest of this request's authorised inputs.
resolveAssembled :: MetricsPort -> MetadataCache -> Text -> IO ByteString -> IO ByteString
resolveAssembled metrics cache key render =
    either absurd id
        <$> resolveSingleFlight
            (pure ())
            (const pass)
            (mpAssembledCacheResidentBytes metrics . occBytes)
            (mcAssembled cache)
            key
            (Right <$> render)

-- | Read full metadata without fetching or refreshing recency.
cachedMetadata :: MetadataCache -> Source -> PackageName -> IO (Maybe CacheEntry)
cachedMetadata cache source name = lookupStore (mcFull cache) (cacheKey source name)

-- | Read and refresh recency. 'Just' 'Nothing' is a cached absence.
cachedVersion :: MetadataCache -> Source -> PackageName -> Version -> IO (Maybe (Maybe PackageDetails))
cachedVersion cache source name version = lookupStoreTouching (mcVersion cache) (versionKey source name version)
