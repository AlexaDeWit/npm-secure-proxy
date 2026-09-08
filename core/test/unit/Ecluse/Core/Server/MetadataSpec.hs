-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Core.Server.MetadataSpec (spec) where

import Data.Aeson (Value (String))
import Data.Map.Strict qualified as Map
import Test.Hspec
import UnliftIO (concurrently, mapConcurrently)
import UnliftIO.Concurrent (threadDelay)

import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.Fault (TransportCause (TransportUnreachable), transportFault)
import Ecluse.Core.Package (
    Artifact (..),
    ArtifactKind (Tarball),
    Availability (Available),
    CodeExecSignal (NoCodeOnInstall),
    InvalidEntry,
    PackageDetails (..),
    PackageInfo (..),
    PackageName,
    Trust (TrustUnknown),
 )
import Ecluse.Core.Registry (FetchFault (FetchTransport))
import Ecluse.Core.Registry.CachedDocument (npmCached)
import Ecluse.Core.Registry.Metadata (
    Manifest (Manifest, manifestDigest, manifestInfo, manifestRaw),
    MetadataClient (fetchFullManifest, fetchVersionMetadata),
    MetadataError (MetadataAuthorisationFailure, MetadataFetch, MetadataUndecodable),
    digestOf,
 )
import Ecluse.Core.Server.Cache (MetadataCache, Source (Source), cachedMetadata, newMetadataCache)
import Ecluse.Core.Server.Metadata (ManifestCaching (Cached, Uncached), newMetadataClient)
import Ecluse.Core.Telemetry.Metrics qualified as Metric
import Ecluse.Core.Telemetry.Record (MetricsPort (mpUpstreamFetchError))
import Ecluse.Core.Version (Version, mkVersion, renderVersion)
import Ecluse.Test.Package (unscopedNpm)
import Ecluse.Test.Port (noopMetricsPort)
import Ecluse.Test.Server.Cache (defaultCacheConfig)

-- | Tests for the serve-path read handle, whose single-version op is hybrid.
spec :: Spec
spec = do
    describe "newMetadataClient -- single-version hybrid topology" $ do
        it "reuses the warm full-packument cache: a GET then its version select is one upstream call" $ do
            calls <- newIORef (0 :: Int)
            cache <- newMetadataCache defaultCacheConfig
            let info = manifest name ["1.0.0", "2.0.0"]
                client = publicClient cache (countingFull calls info) (countingVersion calls info)
            -- Populate the full cache (one upstream call) ...
            _ <- fetchFullManifest client name
            readIORef calls `shouldReturn` 1
            -- ... then the single-version op selects from that warm entry: no second call,
            -- and no selective version fetch.
            found <- fetchVersionMetadata client name (ver "1.0.0")
            fmap (fmap pkgVersion) found `shouldBe` Right (Just (ver "1.0.0"))
            readIORef calls `shouldReturn` 1

        it "cold: leads a selective single-version fetch, caches it, and a repeat hits the version cache" $ do
            calls <- newIORef (0 :: Int)
            cache <- newMetadataCache defaultCacheConfig
            let info = manifest name ["1.0.0"]
                client = publicClient cache (countingFull calls info) (countingVersion calls info)
            -- No preceding GET: the version op leads its own selective fetch (one call) ...
            cold <- fetchVersionMetadata client name (ver "1.0.0")
            fmap (fmap pkgVersion) cold `shouldBe` Right (Just (ver "1.0.0"))
            readIORef calls `shouldReturn` 1
            -- ... and the version cache serves a repeat, no second call.
            warmHit <- fetchVersionMetadata client name (ver "1.0.0")
            fmap (fmap pkgVersion) warmHit `shouldBe` Right (Just (ver "1.0.0"))
            readIORef calls `shouldReturn` 1
            -- The cold single-version path stays isolated on writes: it never populated the
            -- shared full-packument cache (only the version cache).
            cachedMetadata cache source name `shouldReturn` Nothing

        it "caches a determined absence: an absent version is a Nothing re-served without a re-fetch" $ do
            calls <- newIORef (0 :: Int)
            cache <- newMetadataCache defaultCacheConfig
            let info = manifest name ["1.0.0"]
                client = publicClient cache (countingFull calls info) (countingVersion calls info)
            -- A version the metadata does not carry is a forwarded miss (a 404), and the
            -- cache holds it as a determined absence ...
            absent <- fetchVersionMetadata client name (ver "2.0.0")
            fmap (fmap pkgVersion) absent `shouldBe` Right Nothing
            readIORef calls `shouldReturn` 1
            -- ... so the negative cache entry serves a repeat, no second call.
            absentHit <- fetchVersionMetadata client name (ver "2.0.0")
            fmap (fmap pkgVersion) absentHit `shouldBe` Right Nothing
            readIORef calls `shouldReturn` 1

    describe "newMetadataClient -- caching policy" $
        it "an uncached handle fetches on every call (the per-client private origin)" $ do
            calls <- newIORef (0 :: Int)
            let info = manifest name ["1.0.0"]
                client =
                    newMetadataClient noopMetricsPort Metric.Private Uncached noLog noInvalidLog noFetchLog (countingFull calls info) (countingVersion calls info)
            _ <- fetchFullManifest client name
            _ <- fetchFullManifest client name
            readIORef calls `shouldReturn` 2

    describe "newMetadataClient -- failure propagation" $ do
        for_ [401, 403] $ \code ->
            it ("records and preserves private access refusal " <> show code <> " on every read") $ do
                causes <- newIORef []
                failures <- newIORef []
                let refusal = MetadataAuthorisationFailure code
                    port = noopMetricsPort{mpUpstreamFetchError = \upstream cause -> modifyIORef' causes ((upstream, cause) :)}
                    recordFailure who err = modifyIORef' failures ((who, err) :)
                    client = newMetadataClient port Metric.Private Uncached recordFailure noInvalidLog noFetchLog (const (pure (Left refusal))) (\_ _ -> pure (Left refusal))
                replicateM_ 2 $ do
                    full <- fetchFullManifest client name
                    void full `shouldBe` Left refusal
                    single <- fetchVersionMetadata client name (ver "1.0.0")
                    void single `shouldBe` Left refusal
                readIORef causes `shouldReturn` replicate 4 (Metric.Private, Metric.OtherCause)
                readIORef failures `shouldReturn` replicate 4 (name, refusal)

        it "propagates a MetadataError from both operations and caches nothing on failure" $ do
            calls <- newIORef (0 :: Int)
            cache <- newMetadataCache defaultCacheConfig
            let client = publicClient cache (failingFull calls) (failingVersion calls)
            full <- fetchFullManifest client name
            case full of
                Left err -> err `shouldBe` MetadataUndecodable
                Right _ -> expectationFailure "expected the failure to propagate"
            single <- fetchVersionMetadata client name (ver "1.0.0")
            case single of
                Left err -> err `shouldBe` MetadataUndecodable
                Right _ -> expectationFailure "expected the failure to propagate"
            -- A failed fetch caches nothing, so each op (the full leg, then the cold
            -- single-version leg) re-ran its fetch.
            readIORef calls `shouldReturn` 2

        it "an unreachable upstream is not cached: the next resolve fetches afresh" $ do
            -- The transport fault rides the same typed channel: the first resolve
            -- reports it, nothing is cached, and a recovered upstream serves the next.
            calls <- newIORef (0 :: Int)
            cache <- newMetadataCache defaultCacheConfig
            let info = manifest name ["1.0.0"]
                outage = unreachableFull calls
                recovered = countingFull calls info
            first' <- fetchFullManifest (publicClient cache outage (failingVersion calls)) name
            isUnreachable first' `shouldBe` True
            cachedMetadata cache source name `shouldReturn` Nothing
            second' <- fetchFullManifest (publicClient cache recovered (failingVersion calls)) name
            fmap (infoName . manifestInfo) second' `shouldBe` Right name
            readIORef calls `shouldReturn` 2

        it "records the Connection error cause for an unreachable upstream" $ do
            -- The upstream-fetch error metric keeps its bounded cause: the transport
            -- arm classifies as Connection.
            calls <- newIORef (0 :: Int)
            causes <- newIORef ([] :: [Metric.Cause])
            cache <- newMetadataCache defaultCacheConfig
            let port = noopMetricsPort{mpUpstreamFetchError = \_ cause -> atomicModifyIORef' causes (\cs -> (cause : cs, ()))}
                client =
                    newMetadataClient port Metric.Public (Cached cache source) noLog noInvalidLog noFetchLog (unreachableFull calls) (failingVersion calls)
            _ <- fetchFullManifest client name
            readIORef causes `shouldReturn` [Metric.Connection]

        it "logs a failure once per real fetch: coalesced followers never re-log" $ do
            -- Coalesced followers share the failing leader's typed Left, and the failure log fires
            -- once inside the leader, never per follower.
            fetches <- newIORef (0 :: Int)
            failureLogs <- newIORef (0 :: Int)
            started <- newEmptyMVar
            release <- newEmptyMVar
            cache <- newMetadataCache defaultCacheConfig
            let blockingOutage _name = do
                    atomicModifyIORef' fetches (\n -> (n + 1, ()))
                    _ <- tryPutMVar started ()
                    takeMVar release
                    pure (Left (MetadataFetch (FetchTransport (transportFault TransportUnreachable "refused"))))
                countingLog _name _err = atomicModifyIORef' failureLogs (\n -> (n + 1, ()))
                client =
                    newMetadataClient noopMetricsPort Metric.Public (Cached cache source) countingLog noInvalidLog noFetchLog blockingOutage (failingVersion fetches)
            (results, ()) <-
                concurrently
                    (mapConcurrently (const (fetchFullManifest client name)) [1 .. 8 :: Int])
                    ( do
                        takeMVar started
                        threadDelay 30000 -- give the others time to coalesce
                        putMVar release ()
                    )
            map isUnreachable results `shouldBe` replicate 8 True
            readIORef fetches `shouldReturn` 1
            readIORef failureLogs `shouldReturn` 1

name :: PackageName
name = unscopedNpm "is-odd"

ver :: Text -> Version
ver = mkVersion Npm

source :: Source
source = Source "https://public.example"

noLog :: PackageName -> MetadataError -> IO ()
noLog _ _ = pure ()

noInvalidLog :: PackageName -> [InvalidEntry] -> IO ()
noInvalidLog _ _ = pure ()

noFetchLog :: PackageName -> IO ()
noFetchLog _ = pure ()

-- | A public (cached, anonymous) read handle over an injected full and single-version fetch.
publicClient ::
    MetadataCache ->
    (PackageName -> IO (Either MetadataError Manifest)) ->
    (PackageName -> Version -> IO (Either MetadataError (Maybe PackageDetails))) ->
    MetadataClient
publicClient cache =
    newMetadataClient noopMetricsPort Metric.Public (Cached cache source) noLog noInvalidLog noFetchLog

-- | A counting full-manifest fetch: bumps the call counter, then yields the given manifest paired with a marker raw 'Value'.
countingFull :: IORef Int -> PackageInfo -> PackageName -> IO (Either MetadataError Manifest)
countingFull calls info _name = do
    atomicModifyIORef' calls (\n -> (n + 1, ()))
    pure (Right Manifest{manifestInfo = info, manifestRaw = fst npmCached (String "raw"), manifestDigest = digestOf "raw-bytes"})

-- | Count each selective fetch and resolve its version from the supplied snapshot.
countingVersion :: IORef Int -> PackageInfo -> PackageName -> Version -> IO (Either MetadataError (Maybe PackageDetails))
countingVersion calls info _name version = do
    atomicModifyIORef' calls (\n -> (n + 1, ()))
    pure (Right (Map.lookup (renderVersion version) (infoVersions info)))

-- | A counting full-manifest fetch that always fails, so a test can assert nothing is cached.
failingFull :: IORef Int -> PackageName -> IO (Either MetadataError Manifest)
failingFull calls _name = do
    atomicModifyIORef' calls (\n -> (n + 1, ()))
    pure (Left MetadataUndecodable)

-- | A counting full-manifest fetch reporting an unreachable upstream (the transport arm).
unreachableFull :: IORef Int -> PackageName -> IO (Either MetadataError Manifest)
unreachableFull calls _name = do
    atomicModifyIORef' calls (\n -> (n + 1, ()))
    pure (Left (MetadataFetch (FetchTransport (transportFault TransportUnreachable "refused"))))

-- | Whether a full-manifest outcome is the unreachable-upstream fault.
isUnreachable :: Either MetadataError Manifest -> Bool
isUnreachable = \case
    Left (MetadataFetch (FetchTransport _)) -> True
    _ -> False

-- | A counting single-version fetch that always fails.
failingVersion :: IORef Int -> PackageName -> Version -> IO (Either MetadataError (Maybe PackageDetails))
failingVersion calls _name _version = do
    atomicModifyIORef' calls (\n -> (n + 1, ()))
    pure (Left MetadataUndecodable)

-- | A manifest self-reporting @name@ with the given versions, each an inert snapshot.
manifest :: PackageName -> [Text] -> PackageInfo
manifest who versions =
    PackageInfo
        { infoName = who
        , infoVersions = Map.fromList [(v, details who v) | v <- versions]
        , infoDistTags = Map.empty
        , infoInvalidEntries = []
        }

-- | A minimal per-version snapshot, identifiable by its parsed version.
details :: PackageName -> Text -> PackageDetails
details who rawVer =
    PackageDetails
        { pkgName = who
        , pkgVersion = ver rawVer
        , pkgPublishedAt = Nothing
        , pkgInstallCode = NoCodeOnInstall
        , pkgTrust = TrustUnknown
        , pkgAvailability = Available
        , pkgArtifacts = artifact :| []
        , pkgLicenses = []
        , pkgPublisher = Nothing
        }
  where
    artifact =
        Artifact
            { artFilename = "pkg-" <> rawVer <> ".tgz"
            , artUrl = "https://example.test/pkg-" <> rawVer <> ".tgz"
            , artKind = Tarball
            , artHashes = []
            , artSize = Nothing
            , artInterpreter = Nothing
            , artYanked = False
            , artProvenance = Nothing
            }
