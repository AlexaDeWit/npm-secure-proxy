-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Work-per-request bench for request routing: the npm classifier
("Ecluse.Core.Registry.Npm.Route") that turns a request's method and path segments into
a typed 'Route'. It runs on every request, before any metadata work.

The input is a representative mix of the request shapes the proxy sees: bare and scoped
packuments, tarball coordinates, the @ping@ probe, search, first-party publishes
(@PUT@), and unrecognised paths. The bench therefore reflects the real classifier branch
distribution rather than one hot path.
-}
module Ecluse.Core.RouteBench (
    benchmarks,
) where

import Data.Text qualified as T
import Network.HTTP.Types.Method (Method, methodGet, methodPut)

import Ecluse.Core.Registry.Npm.Route (npmRoutes)
import Ecluse.Core.Server.Route (Route (routeName), RouteName (RouteName), matchRoute)
import Test.Tasty.Bench (Benchmark, bench, bgroup, env, whnf)

-- | The classifier bench over a mixed batch of realistic requests.
benchmarks :: Benchmark
benchmarks =
    env (pure requests) $ \reqs ->
        bgroup
            "route.match"
            [ bench "mixed npm requests" (whnf classifyDepth reqs)
            ]

-- | A batch of realistic npm requests (method + path segments), the classifier's input.
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

{- | Route every request, summing the matched route's identifier length so the fold forces
each result. The route's action is a closure, so the identifier is what the bench forces.
-}
classifyDepth :: [(Method, [Text])] -> Int
classifyDepth = foldl' (\acc (method, segments) -> acc + matchDepth method segments) 0
  where
    matchDepth method segments =
        -- npm's routes negotiate no media type, so the bench routes with no Accept header.
        maybe 0 (nameLength . routeName . fst) (matchRoute npmRoutes method [] segments)

    nameLength (RouteName n) = T.length n
