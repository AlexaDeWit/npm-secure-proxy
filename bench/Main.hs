-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The Écluse benchmark entry point: the work-per-request micro-benches over the pure
@ecluse-core@ hot paths, the version-count complexity assertions, and the
synthetic-corpus generator's correctness tests, all in one @tasty@ tree.

@tasty-bench@ reports time and allocated bytes for each bench. It reports the allocations
under @+RTS -T@, baked into the component's RTS options. Allocations are the
machine-independent signal the baseline tracks. Time is informational.

The generator tests and the complexity assertions are ordinary @tasty@ test cases mixed
into the same tree. A malformed corpus or an accidentally quadratic hot path therefore
fails the run with a non-zero exit, the one red state this harness recognises.
-}
module Main (main) where

import Data.Aeson (Value (Object, String))
import Data.Aeson.KeyMap qualified as KeyMap
import Data.Map.Strict qualified as Map
import Data.Text qualified as T
import Ecluse.Bench.Corpus (
    benchPackageName,
    benchPackageText,
    loadCorpus,
    projectInfo,
    syntheticPackumentBytes,
    syntheticPackumentValue,
    versionKeysOf,
    withLoaded,
 )
import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.MergeBench qualified as MergeBench
import Ecluse.Core.Package (infoVersions, mkPackageName)
import Ecluse.Core.Registry (RegistryResponse (RegistryResponse))
import Ecluse.Core.Registry.Npm.Filter (rewriteVersion)
import Ecluse.Core.Registry.Npm.Project (parseVersionList)
import Ecluse.Core.Registry.Npm.Route (tarballPath)
import Ecluse.Core.RouteBench qualified as RouteBench
import Ecluse.Core.RulesBench qualified as RulesBench
import Ecluse.Core.SecurityBench qualified as SecurityBench
import Ecluse.Core.SelectiveBench qualified as SelectiveBench
import Ecluse.Core.ServeBench qualified as ServeBench
import Ecluse.Core.StreamBench qualified as StreamBench
import Ecluse.Core.VersionBench qualified as VersionBench
import Ecluse.Core.WireBench qualified as WireBench
import Ecluse.Test.Corpus (syntheticProxyBase)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.Bench (bgroup, defaultMain)
import Test.Tasty.HUnit (assertBool, assertFailure, testCase, (@?=))

main :: IO ()
main = do
    -- Decode the curated corpus once, before the measured window, so no bench times it.
    -- Eager, not a tasty 'env' resource, which the bench reporters mishandle mixed with HUnit.
    corpusEntries <- withLoaded <$> loadCorpus
    defaultMain
        [ bgroup
            "ecluse-core (work-per-request)"
            [ RouteBench.benchmarks
            , WireBench.benchmarks corpusEntries
            , SelectiveBench.benchmarks corpusEntries
            , VersionBench.benchmarks corpusEntries
            , RulesBench.benchmarks corpusEntries
            , MergeBench.benchmarks corpusEntries
            , ServeBench.benchmarks corpusEntries
            , StreamBench.benchmarks
            , SecurityBench.benchmarks corpusEntries
            ]
        , generatorTests
        ]

{- | Correctness tests for the synthetic packument generator. They run inside the
benchmark, so a broken corpus stops the run rather than benching a degenerate input.
-}
generatorTests :: TestTree
generatorTests =
    testGroup
        "synthetic packument generator"
        [ testCase "yields the requested version count" $
            length (versionKeysOf (syntheticPackumentValue sampleCount)) @?= sampleCount
        , testCase "decodes with every version preserved" $
            case parseVersionList (RegistryResponse (syntheticPackumentBytes sampleCount)) of
                Left err -> assertFailure ("synthetic packument did not decode: " <> show err)
                Right versions -> length versions @?= sampleCount
        , testCase "projects with every version preserved" $
            Map.size (infoVersions (projectInfo benchPackageName (syntheticPackumentValue sampleCount)))
                @?= sampleCount
        , testCase "rewrites every tarball onto the proxy origin" $ do
            let urls = tarballUrlsOf (rewriteAllVersions (syntheticPackumentValue sampleCount))
            length urls @?= sampleCount
            assertBool
                "every rewritten tarball should sit under the proxy origin"
                (all (rewrittenPrefix `T.isPrefixOf`) urls)
        ]
  where
    sampleCount :: Int
    sampleCount = 500

    -- Apply the serve assembly's per-version rewrite to every version of the
    -- synthetic packument, as the fused assembly pass does per survivor.
    rewriteAllVersions :: Value -> Value
    rewriteAllVersions = \case
        Object top
            | Just (Object versions) <- KeyMap.lookup "versions" top ->
                Object (KeyMap.insert "versions" (Object (fmap (rewriteVersion versionPrefix) versions)) top)
        other -> other

    -- The served-URL renderer the assembly hands the rewrite, rendered from the artifact route.
    versionPrefix :: Text -> Maybe Text
    versionPrefix file = (\path -> syntheticProxyBase <> "/" <> path) <$> tarballPath (mkPackageName Npm Nothing benchPackageText) file

    rewrittenPrefix :: Text
    rewrittenPrefix = syntheticProxyBase <> "/" <> benchPackageText <> "/-/"

-- | Every @dist.tarball@ URL in a packument value, in @versions@-object order.
tarballUrlsOf :: Value -> [Text]
tarballUrlsOf value =
    [ url
    | Object top <- [value]
    , Just (Object versions) <- [KeyMap.lookup "versions" top]
    , (_, versionValue) <- KeyMap.toList versions
    , Object versionObject <- [versionValue]
    , Just (Object dist) <- [KeyMap.lookup "dist" versionObject]
    , Just (String url) <- [KeyMap.lookup "tarball" dist]
    ]
