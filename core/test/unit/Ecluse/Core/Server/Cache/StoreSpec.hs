-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
-- SPDX-License-Identifier: MIT
{-# LANGUAGE TupleSections #-}

{- | Store bounds and single-flight lifecycle checks.
Weights exercise admission without allocating the reported byte counts.
-}
module Ecluse.Core.Server.Cache.StoreSpec (spec) where

import Data.Time (NominalDiffTime)
import Test.Hspec
import UnliftIO (async, cancel, concurrently, mapConcurrently, timeout, wait)
import UnliftIO.Concurrent (threadDelay)
import UnliftIO.Exception (throwIO, try)

import Ecluse.Core.Server.Cache.Store (
    CacheOccupancy (..),
    SingleFlight,
    lookupStore,
    lookupStoreTouching,
    newSingleFlight,
    resolveSingleFlight,
 )
import Ecluse.Core.Telemetry.Metrics qualified as Metric

data StoreFault = StoreFault
    deriving stock (Eq, Show)

newtype UnexpectedFault = UnexpectedFault StoreFault
    deriving stock (Show)

instance Exception UnexpectedFault

data LeaderEscaped = LeaderEscaped
    deriving stock (Eq, Show)

instance Exception LeaderEscaped

flatWeight :: Int
flatWeight = 100

newStore :: NominalDiffTime -> Int -> Int -> IO (SingleFlight StoreFault Text Text)
newStore ttl maxEntries maxBytes = newSingleFlight ttl maxEntries maxBytes (const flatWeight)

roomyStore :: IO (SingleFlight StoreFault Text Text)
roomyStore = newStore 60 100 (100 * flatWeight)

resolve :: SingleFlight StoreFault Text Text -> Text -> IO (Either StoreFault Text) -> IO (Either StoreFault Text)
resolve = resolveSingleFlight (pure ()) (const pass) (const pass)

resolveWith :: IO () -> SingleFlight StoreFault Text Text -> Text -> IO (Either StoreFault Text) -> IO (Either StoreFault Text)
resolveWith afterClaim = resolveSingleFlight afterClaim (const pass) (const pass)

resolveWithRequests :: IORef [Metric.CacheResult] -> IO () -> SingleFlight StoreFault Text Text -> Text -> IO (Either StoreFault Text) -> IO (Either StoreFault Text)
resolveWithRequests seen afterClaim =
    resolveSingleFlight afterClaim (\r -> atomicModifyIORef' seen (\rs -> (r : rs, ()))) (const pass)

resolveOk :: SingleFlight StoreFault Text Text -> Text -> IO Text -> IO Text
resolveOk sf key fetch = either (throwIO . UnexpectedFault) pure =<< resolve sf key (Right <$> fetch)

resolveOkRecording :: IORef (Maybe CacheOccupancy) -> SingleFlight StoreFault Text Text -> Text -> IO Text -> IO Text
resolveOkRecording seen sf key fetch =
    either (throwIO . UnexpectedFault) pure
        =<< resolveSingleFlight (pure ()) (const pass) (writeIORef seen . Just) sf key (Right <$> fetch)

resolveOkAccumulating :: IORef [CacheOccupancy] -> SingleFlight StoreFault Text Text -> Text -> IO Text -> IO Text
resolveOkAccumulating seen sf key fetch =
    either (throwIO . UnexpectedFault) pure
        =<< resolveSingleFlight (pure ()) (const pass) (\occ -> atomicModifyIORef' seen (\os -> (occ : os, ()))) sf key (Right <$> fetch)

countingFetch :: IORef Int -> Text -> IO Text
countingFetch calls value = atomicModifyIORef' calls (\n -> (n + 1, ())) $> value

spec :: Spec
spec = do
    describe "resolveSingleFlight -- collapse" $ do
        it "collapses concurrent resolutions of one key to a single fetch" $ do
            sf <- roomyStore
            calls <- newIORef (0 :: Int)
            started <- newEmptyMVar
            release <- newEmptyMVar

            let fetch = do
                    atomicModifyIORef' calls (\n -> (n + 1, ()))
                    _ <- tryPutMVar started ()
                    takeMVar release
                    pure "raw"
            (results, ()) <-
                concurrently
                    (mapConcurrently (const (resolveOk sf "hot" fetch)) [1 .. 8 :: Int])
                    ( do
                        takeMVar started
                        threadDelay 30000 -- give the others time to coalesce
                        putMVar release ()
                    )
            results `shouldBe` replicate 8 ("raw" :: Text)
            readIORef calls `shouldReturn` 1

        it "has the value in the store the instant the leader's fetch returns" $ do
            sf <- roomyStore
            _ <- resolveOk sf "fresh" (pure "raw")
            lookupStore sf "fresh" `shouldReturn` Just "raw"

        it "does not re-fetch for a caller arriving right after the fetch returns" $ do
            sf <- roomyStore
            calls <- newIORef 0
            _ <- resolveOk sf "back-to-back" (countingFetch calls "raw")
            _ <- resolveOk sf "back-to-back" (countingFetch calls "raw")
            readIORef calls `shouldReturn` 1

    describe "resolveSingleFlight -- typed failure channel" $ do
        it "hands the leader's Left to every coalesced follower, caching nothing" $ do
            sf <- roomyStore
            calls <- newIORef (0 :: Int)
            started <- newEmptyMVar
            release <- newEmptyMVar
            let failing = do
                    atomicModifyIORef' calls (\n -> (n + 1, ()))
                    _ <- tryPutMVar started ()
                    takeMVar release
                    pure (Left StoreFault)
            (results, ()) <-
                concurrently
                    (mapConcurrently (const (resolve sf "shared-fault" failing)) [1 .. 8 :: Int])
                    ( do
                        takeMVar started
                        threadDelay 30000 -- give the others time to coalesce
                        putMVar release ()
                    )
            results `shouldBe` replicate 8 (Left StoreFault)
            readIORef calls `shouldReturn` 1
            lookupStore sf "shared-fault" `shouldReturn` Nothing

        it "re-raises a synchronously escaping leader to its followers (the invariant channel)" $ do
            result <- timeout 5_000_000 $ do
                sf <- roomyStore
                started <- newEmptyMVar
                release <- newEmptyMVar
                let escaping = do
                        putMVar started ()
                        () <- takeMVar release
                        throwIO LeaderEscaped
                leader <- async (try (resolveOk sf "escape" escaping) :: IO (Either LeaderEscaped Text))
                takeMVar started
                follower <- async (try (resolveOk sf "escape" escaping) :: IO (Either LeaderEscaped Text))
                threadDelay 30000 -- give the follower time to register on the marker
                putMVar release ()
                (,) <$> wait leader <*> wait follower
            case result of
                Nothing -> expectationFailure "wedged: an escaping leader parked its follower"
                Just (leaderOutcome, followerOutcome) -> do
                    leaderOutcome `shouldBe` Left LeaderEscaped
                    followerOutcome `shouldBe` Left LeaderEscaped

    describe "resolveSingleFlight -- single-flight orphan window" $ do
        it "unblocks a waiting follower and lets a later caller re-lead when the leader is cancelled at the claim handoff" $ do
            result <- timeout 5_000_000 $ do
                sf <- roomyStore
                calls <- newIORef (0 :: Int)
                reached <- newEmptyMVar
                release <- newEmptyMVar
                armed <- newIORef True -- only the first (cancelled) leader parks
                let fetch = Right <$> countingFetch calls "raw"
                    afterClaim = do
                        wasArmed <- atomicModifyIORef' armed (False,)
                        when wasArmed $ do
                            putMVar reached () -- claimed the slot, parked at the handoff
                            takeMVar release -- block interruptibly so the cancel lands here
                leader <- async (resolveWith afterClaim sf "wedge" fetch)
                takeMVar reached

                follower <- async (try (resolve sf "wedge" fetch) :: IO (Either SomeException (Either StoreFault Text)))
                threadDelay 30000 -- give the follower time to register on the marker
                cancel leader -- cancel in the handoff window: the slot must still free
                wait follower
            case result of
                Nothing -> expectationFailure "wedged: a cancelled leader orphaned the in-flight slot"
                Just (Left _) -> expectationFailure "follower failed instead of recovering"
                Just (Right recovered) -> recovered `shouldBe` Right "raw"

        it "frees the slot for a later caller when the leader's fetch is cancelled mid-flight" $ do
            result <- timeout 5_000_000 $ do
                sf <- roomyStore
                calls <- newIORef (0 :: Int)
                started <- newEmptyMVar
                release <- newEmptyMVar
                let blockingFetch = do
                        atomicModifyIORef' calls (\n -> (n + 1, ()))
                        putMVar started () -- in the fetch (slot claimed)
                        () <- takeMVar release -- block so the leader can be cancelled here
                        pure "unreached"
                leader <- async (resolveOk sf "midflight" blockingFetch)
                takeMVar started -- the leader holds the slot and is inside the fetch
                cancel leader -- async-cancel mid-fetch: the slot must still free
                recovered <- resolveOk sf "midflight" (countingFetch calls "raw")
                n <- readIORef calls
                pure (recovered, n)
            case result of
                Nothing -> expectationFailure "wedged: a mid-flight cancel orphaned the in-flight slot"
                Just (recovered, n) -> do
                    recovered `shouldBe` "raw"
                    n `shouldBe` 2 -- the cancelled fetch and the recovering re-lead, no caching of the failure
        it "counts one miss per logical resolution even when a cancelled leader forces the follower to re-resolve" $ do
            result <- timeout 5_000_000 $ do
                sf <- roomyStore
                seen <- newIORef []
                calls <- newIORef (0 :: Int)
                reached <- newEmptyMVar
                release <- newEmptyMVar
                armed <- newIORef True -- only the first (cancelled) leader parks
                let fetch = Right <$> countingFetch calls "raw"
                    afterClaim = do
                        wasArmed <- atomicModifyIORef' armed (False,)
                        when wasArmed $ do
                            putMVar reached () -- claimed the slot, parked at the handoff
                            takeMVar release -- block interruptibly so the cancel lands here
                leader <- async (resolveWithRequests seen afterClaim sf "wedge" fetch)
                takeMVar reached
                follower <- async (try (resolveWithRequests seen (pure ()) sf "wedge" fetch) :: IO (Either SomeException (Either StoreFault Text)))
                threadDelay 30000 -- give the follower time to register on the marker
                cancel leader -- cancel in the handoff window: the follower must re-resolve
                recovered <- wait follower
                recorded <- readIORef seen
                pure (recovered, recorded)
            case result of
                Nothing -> expectationFailure "wedged: a cancelled leader orphaned the in-flight slot"
                Just (Left _, _) -> expectationFailure "follower failed instead of recovering"
                Just (Right recovered, recorded) -> do
                    recovered `shouldBe` Right "raw" -- the follower recovered by re-leading
                    recorded `shouldBe` [Metric.Miss, Metric.Miss] -- leader + follower, never a third for the retry
    describe "the entry-count bound" $ do
        it "never exceeds the configured maximum entry count" $ do
            seen <- newIORef Nothing
            sf <- newStore 60 4 (1000 * flatWeight)
            for_ [1 .. 20 :: Int] $ \i ->
                resolveOkRecording seen sf (show i) (pure "raw")
            occ <- readIORef seen
            fmap occEntries occ `shouldSatisfy` maybe False (<= 4)

        it "keeps serving fresh resolutions even under eviction pressure" $ do
            sf <- newStore 60 2 (1000 * flatWeight)
            for_ [1 .. 10 :: Int] $ \i ->
                resolveOk sf (show i) (pure "raw")
            resolveOk sf "final" (pure "raw") `shouldReturn` "raw"

    describe "the resident-byte budget" $ do
        it "evicts to keep the resident estimate under the byte budget" $ do
            let held = 3
            seen <- newIORef Nothing
            sf <- newStore 60 1000 (held * flatWeight + flatWeight `div` 2)
            for_ [1 .. 20 :: Int] $ \i ->
                resolveOkRecording seen sf (show i) (pure "raw")
            occ <- readIORef seen
            fmap occBytes occ `shouldSatisfy` maybe False (<= held * flatWeight + flatWeight `div` 2)
            fmap occEntries occ `shouldSatisfy` maybe False (<= held)

        it "retains a repeatedly-accessed entry while evicting the one-shot tail" $ do
            let held = 3
            sf <- newStore 60 1000 (held * flatWeight + flatWeight `div` 2)
            _ <- resolveOk sf "hot" (pure "raw")
            for_ [1 .. 30 :: Int] $ \i -> do
                _ <- resolveOk sf "hot" (pure "unused")
                resolveOk sf ("cold-" <> show i) (pure "raw")
            lookupStore sf "hot" `shouldReturn` Just "raw"
            lookupStore sf "cold-1" `shouldReturn` Nothing

    describe "read recency -- the touching vs read-only views" $ do
        it "a touching read bumps recency, so eviction sheds an untouched entry, not the touched one" $ do
            sf <- newStore 60 2 (100 * flatWeight)
            _ <- resolveOk sf "old" (pure "raw")
            _ <- resolveOk sf "recent" (pure "raw")
            lookupStoreTouching sf "old" `shouldReturn` Just "raw"
            _ <- resolveOk sf "new" (pure "raw")
            lookupStore sf "old" `shouldReturn` Just "raw"
            lookupStore sf "recent" `shouldReturn` Nothing
            lookupStore sf "new" `shouldReturn` Just "raw"

        it "a read-only lookup leaves recency unchanged, so the insert-order-oldest entry still evicts" $ do
            sf <- newStore 60 2 (100 * flatWeight)
            _ <- resolveOk sf "old" (pure "raw")
            _ <- resolveOk sf "recent" (pure "raw")
            lookupStore sf "old" `shouldReturn` Just "raw"
            _ <- resolveOk sf "new" (pure "raw")
            lookupStore sf "old" `shouldReturn` Nothing
            lookupStore sf "recent" `shouldReturn` Just "raw"
            lookupStore sf "new" `shouldReturn` Just "raw"

    describe "the oversized pass-through" $ do
        it "never retains the saturated weight even with a maxBound budget" $ do
            sf <- newSingleFlight 60 100 maxBound (const maxBound) :: IO (SingleFlight StoreFault Text Text)
            resolveOk sf "overflow" (pure "value") `shouldReturn` "value"
            lookupStore sf "overflow" `shouldReturn` Nothing

        it "evicts before adding weights whose sum would overflow Int" $ do
            seen <- newIORef Nothing
            sf <- newSingleFlight 60 100 maxBound (const (maxBound - 1)) :: IO (SingleFlight StoreFault Text Text)
            _ <- resolveOkRecording seen sf "first" (pure "a")
            _ <- resolveOkRecording seen sf "second" (pure "b")
            lookupStore sf "first" `shouldReturn` Nothing
            lookupStore sf "second" `shouldReturn` Just "b"
            (fmap (\occ -> (occEntries occ, occBytes occ)) <$> readIORef seen) `shouldReturn` Just (1, maxBound - 1)

        it "serves a value larger than the whole byte budget without retaining it" $ do
            sf <- newStore 60 100 (flatWeight - 1)
            calls <- newIORef (0 :: Int)
            resolveOk sf "big" (countingFetch calls "huge") `shouldReturn` "huge"

            lookupStore sf "big" `shouldReturn` Nothing
            resolveOk sf "big" (countingFetch calls "huge") `shouldReturn` "huge"
            readIORef calls `shouldReturn` 2

        it "evicts nothing resident to make room that cannot exist" $ do
            let weigh v = if v == "pathological" then 3 * flatWeight else flatWeight
            sf <- newSingleFlight 60 100 (2 * flatWeight) weigh :: IO (SingleFlight StoreFault Text Text)
            _ <- resolveOk sf "a" (pure "resident")
            _ <- resolveOk sf "b" (pure "resident")
            _ <- resolveOk sf "big" (pure "pathological")
            lookupStore sf "a" `shouldReturn` Just "resident"
            lookupStore sf "b" `shouldReturn` Just "resident"
            lookupStore sf "big" `shouldReturn` Nothing

        it "reports no occupancy for a pass-through (the gauges describe the store, not the serve)" $ do
            seen <- newIORef Nothing
            sf <- newStore 60 100 (flatWeight - 1)
            _ <- resolveOkRecording seen sf "big" (pure "huge")
            (isNothing <$> readIORef seen) `shouldReturn` True

    describe "concurrent different-key leaders under the byte budget" $ do
        it "never lands the resident sum past the budget (the insert lock)" $ do
            let budget = 3 * flatWeight
            seen <- newIORef []
            sf <- newStore 60 1000 budget
            barrier <- newEmptyMVar
            leaders <- traverse (\(i :: Int) -> async (resolveOkAccumulating seen sf (show i) (readMVar barrier $> "v"))) [1 .. 8]
            putMVar barrier ()
            traverse_ wait leaders
            byteReadings <- map occBytes <$> readIORef seen
            byteReadings `shouldSatisfy` (not . null)
            byteReadings `shouldSatisfy` all (<= budget)
