-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

-- | Request routing costs for npm and PyPI, including malformed filename scaling.
module Ecluse.Core.RouteBench (
    benchmarks,
) where

import Data.Text qualified as T
import Network.HTTP.Types.Method (Method, methodGet, methodPut)

import Ecluse.Bench.Fit (notWorseThanLinear)
import Ecluse.Core.Registry.Npm.Route (npmRoutes)
import Ecluse.Core.Registry.PyPI.Route (pypiRoutes)
import Ecluse.Core.Server.Route (Route (routeName), RouteName (RouteName), matchRoute)
import Ecluse.Test.Registry.PyPI (separatorHeavySdist)
import Test.Tasty.Bench (Benchmark, bench, bgroup, env, whnf)

-- | Normal request costs and PyPI filename complexity fits.
benchmarks :: Benchmark
benchmarks =
    bgroup
        "route.match"
        [ env (pure requests) $ \reqs -> bench "mixed npm requests" (whnf classifyDepth reqs)
        , bench "normal PyPI sdist" (whnf classifyPyPI "requests-2.34.2.tar.gz")
        , bench "normal PyPI wheel" (whnf classifyPyPI "requests-2.34.2-py3-none-any.whl")
        , notWorseThanLinear
            "malformed PyPI filename separators"
            (64, 8192)
            (\count -> separatorHeavySdist "requests" (fromIntegral count) "benchmark")
            classifyPyPI
        , notWorseThanLinear
            "valid PyPI filename separators"
            (64, 8192)
            (\count -> "requests" <> T.replicate (fromIntegral count) "_" <> "1.tar.gz")
            classifyPyPI
        ]

requests :: [(Method, [Text])]
requests = concat (replicate 1000 sample)
  where
    sample =
        [ (methodGet, ["express"])
        , (methodGet, ["lodash"])
        , (methodGet, ["@babel", "core"])
        , (methodGet, ["@types", "node"])
        , (methodGet, ["express", "-", "express-4.18.2.tgz"])
        , (methodGet, ["@babel", "core", "-", "core-7.24.0.tgz"])
        , (methodGet, ["-", "ping"])
        , (methodGet, ["-", "v1", "search"])
        , (methodGet, ["favicon.ico"])
        , (methodGet, [])
        , (methodPut, ["@acme", "widget"]) -- a first-party publish (bare-package PUT)
        , (methodPut, ["express", "-", "express-4.18.2.tgz"]) -- a PUT to a non-publish path
        ]

classifyDepth :: [(Method, [Text])] -> Int
classifyDepth = foldl' (\acc (method, segments) -> acc + matchDepth method segments) 0
  where
    matchDepth method segments =
        -- npm's routes negotiate no media type, so the bench routes with no Accept header.
        maybe 0 (routeNameLength . routeName . fst) (matchRoute npmRoutes method [] segments)

classifyPyPI :: Text -> Int
classifyPyPI file =
    maybe 0 (routeNameLength . routeName . fst) (matchRoute pypiRoutes methodGet [] ["simple", "requests", file])

routeNameLength :: RouteName -> Int
routeNameLength (RouteName name) = T.length name
