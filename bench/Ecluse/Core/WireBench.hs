-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Measure npm metadata decoding and projection over the captured package corpus.
Each result forces every version through its decoded or projected fields.
-}
module Ecluse.Core.WireBench (
    benchmarks,
) where

import Data.Aeson (Value)
import Data.List.NonEmpty qualified as NE
import Data.Map.Strict qualified as Map
import Ecluse.Bench.Corpus (LoadedEntry, entryName)
import Ecluse.Core.Package (PackageInfo, PackageName, artHashes, infoVersions, pkgArtifacts)
import Ecluse.Core.Registry (RegistryResponse (RegistryResponse))
import Ecluse.Core.Registry.Metadata (MetadataError)
import Ecluse.Core.Registry.Npm.Metadata (projectNpmManifest)
import Ecluse.Core.Registry.Npm.Project (parseVersionList)
import Ecluse.Core.Security (defaultLimits)
import Ecluse.Test.Corpus (CorpusPackage (cpPackage))
import Test.Tasty.Bench (Benchmark, bench, bgroup, whnf)

-- | The decode and projection benches over each corpus entry.
benchmarks :: [LoadedEntry] -> Benchmark
benchmarks loaded =
    bgroup
        "wire+project (per package)"
        [ bgroup
            (entryName le)
            [ bench "decode" (whnf decodeDepth raw)
            , bench "decode+project" (whnf projectDepth (raw, cpPackage cp))
            ]
        | le@(cp, raw, _) <- loaded
        ]

-- | Decode bytes through 'parseVersionList', forcing every version.
decodeDepth :: ByteString -> Int
decodeDepth raw = either (const (-1)) length (parseVersionList (RegistryResponse 200 raw))

-- | Decode and project to 'PackageInfo' in one pass, forcing every version.
projectDepth :: (ByteString, PackageName) -> Int
projectDepth (raw, name) = infoDepthE (projectNpmManifest defaultLimits name raw)

infoDepthE :: Either MetadataError (PackageInfo, Value) -> Int
infoDepthE = either (const (-1)) (infoDepth . fst)

-- | Force every projected version by folding a deep field (the artifact digests) across the version map.
infoDepth :: PackageInfo -> Int
infoDepth info = Map.foldr (\pd acc -> length (artHashes (NE.head (pkgArtifacts pd))) + acc) 0 (infoVersions info)
