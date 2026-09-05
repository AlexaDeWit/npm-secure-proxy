-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.ServiceSpec (spec) where

import Data.Time (addUTCTime, getCurrentTime)
import Test.Hspec

import Ecluse.Core.Ecosystem (Ecosystem (..))
import Ecluse.Core.Worker (
    Liveness (liveHealthy, liveLastPoll),
    WorkerHeartbeat,
    newWorkerHeartbeat,
    recordPoll,
    workerHeartbeatStaleAfter,
 )
import Ecluse.Runtime.Server (MountBinding (bindingPrefix))
import Ecluse.Service (mountBindingFor, workerLiveness)
import Ecluse.Test.Server.Mount (inertPackumentDeps)

{- | A heartbeat whose last poll is older than 'workerHeartbeatStaleAfter': a consume loop
that stopped advancing, which is what the worker arm of @\/livez@ exists to catch.
-}
stalledHeartbeat :: IO WorkerHeartbeat
stalledHeartbeat = do
    heartbeat <- newWorkerHeartbeat
    now <- getCurrentTime
    recordPoll heartbeat (addUTCTime (negate (workerHeartbeatStaleAfter + 60)) now)
    pure heartbeat

spec :: Spec
spec = do
    describe "workerLiveness -- what /livez answers once the spawn decision is derived" $ do
        it "reports a stalled consume loop as not live where the process runs one" $ do
            liveness <- stalledHeartbeat >>= workerLiveness True
            liveHealthy liveness `shouldBe` False

        it "stays live where the process runs no consume loop to stall" $ do
            liveness <- stalledHeartbeat >>= workerLiveness False
            liveHealthy liveness `shouldBe` True
            liveLastPoll liveness `shouldBe` Nothing

        it "carries the last poll instant so an orchestrator can judge staleness itself" $ do
            heartbeat <- newWorkerHeartbeat
            now <- getCurrentTime
            recordPoll heartbeat now
            liveness <- workerLiveness True heartbeat
            liveHealthy liveness `shouldBe` True
            liveLastPoll liveness `shouldBe` Just now

        it "is live before the first poll, because a starting worker is not a stalled one" $ do
            liveness <- newWorkerHeartbeat >>= workerLiveness True
            liveHealthy liveness `shouldBe` True
            liveLastPoll liveness `shouldBe` Nothing

    describe "mountBindingFor -- ecosystem drives the binding" $ do
        it "resolves npm to a binding whose prefix is derived from the ecosystem (/npm)" $
            (bindingPrefix <$> mountBindingFor Npm inertPackumentDeps Nothing) `shouldBe` Just ("npm" :| [])

        it "resolves PyPI to a binding under its own derived prefix (/pypi)" $
            (bindingPrefix <$> mountBindingFor PyPI inertPackumentDeps Nothing) `shouldBe` Just ("pypi" :| [])

        it "has no binding for an ecosystem with no adapter wired (loud Nothing, not a stub)" $
            (bindingPrefix <$> mountBindingFor RubyGems inertPackumentDeps Nothing) `shouldBe` Nothing
