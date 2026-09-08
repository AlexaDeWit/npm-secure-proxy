-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | TTL stores with single-flight fetches and bounded accounted bytes.
Each store serialises eviction and insertion while followers share the leader's result.
-}
module Ecluse.Core.Server.Cache.Store (
    -- * The store
    SingleFlight,
    newSingleFlight,

    -- * Resolution
    resolveSingleFlight,

    -- * Reads
    lookupStore,
    lookupStoreTouching,

    -- * Occupancy
    CacheOccupancy (..),
) where

import Data.Cache (Cache)
import Data.Cache qualified as Cache
import Data.Map.Strict qualified as Map
import Data.Time (NominalDiffTime)
import System.Clock (Clock (Monotonic), TimeSpec, fromNanoSecs, getTime)
import UnliftIO.Exception (SomeAsyncException, mask, throwIO)
import UnliftIO.MVar (withMVar)

import Ecluse.Core.InFlight (guardInFlight)
import Ecluse.Core.Telemetry.Metrics qualified as Metric

data Weighted v = Weighted
    { wValue :: v
    -- ^ The cached value.
    , wWeight :: Int
    -- ^ The value's estimated resident footprint in bytes, fixed at insert.
    , wStamp :: IORef Word64
    -- ^ The value's last-access stamp, bumped on every hit and read by eviction.
    }

-- | A bounded store whose concurrent misses share one fetch per key.
data SingleFlight e k v = SingleFlight
    { sfStore :: Cache k (Weighted v)
    -- ^ The TTL- and STM-backed store (the @cache@ library), holding weighted values.
    , sfMaxEntries :: Int
    -- ^ The entry-count bound enforced on insert.
    , sfMaxBytes :: Int
    -- ^ The resident-byte budget enforced on insert.
    , sfWeigh :: v -> Int
    -- ^ Estimate a value's resident footprint in bytes, fixed into its 'Weighted' at insert.
    , sfClock :: IORef Word64
    , sfInsertLock :: MVar ()
    , sfInFlight :: TVar (Map k (TMVar (FlightOutcome e v)))
    }

data FlightOutcome e v
    = FlightValue v
    | FlightFault e
    | FlightOrphaned SomeException

-- | Build a store with positive bounds. A weight of 'maxBound' means uncacheable.
newSingleFlight :: NominalDiffTime -> Int -> Int -> (v -> Int) -> IO (SingleFlight e k v)
newSingleFlight ttl maxEntries maxBytes weigh = do
    store <- Cache.newCache (Just (toTimeSpec ttl))
    clock <- newIORef 0
    inFlight <- newTVarIO Map.empty
    insertLock <- newMVar ()
    pure
        SingleFlight
            { sfStore = store
            , sfMaxEntries = max 1 maxEntries
            , sfMaxBytes = max 1 maxBytes
            , sfWeigh = weigh
            , sfClock = clock
            , sfInsertLock = insertLock
            , sfInFlight = inFlight
            }

-- | Share a fetch across concurrent misses. Failed and cancelled leaders release their waiters.
resolveSingleFlight ::
    (Hashable k, Ord k) =>
    IO () ->
    (Metric.CacheResult -> IO ()) ->
    (CacheOccupancy -> IO ()) ->
    SingleFlight e k v ->
    k ->
    IO (Either e v) ->
    IO (Either e v)
resolveSingleFlight afterClaim recordRequest recordInsert sf key fetch = mask $ \restore -> do
    nowT <- getTime Monotonic
    -- One atomic decision point under the enclosing 'mask'. A 'Lead' must reach
    -- 'guardInFlight' with no interruptible point between, or the claimed slot leaks.
    decision <- atomically (decideSingleFlight sf key nowT)
    case decision of
        Hit weighted -> do
            recordRequest Metric.Hit
            -- Bump recency outside the STM transaction: a hit updates the per-entry stamp
            -- without writing the shared store, and the eviction still sees it.
            touch sf weighted
            pure (Right (wValue weighted))
        Follow marker -> do
            -- A follower coalesced onto an in-flight fetch is a miss for this caller
            -- (no fresh entry was present), exactly as the leader's miss is.
            recordRequest Metric.Miss
            outcome <- restore (atomically (readTMVar marker))
            case outcome of
                FlightValue fetched -> pure (Right fetched)
                -- The typed hand-off: the leader's fetch reported a failure value, so
                -- every waiter receives the same 'Left', and nothing was cached.
                FlightFault fault -> pure (Left fault)
                FlightOrphaned err -> case fromException err of
                    Just (_ :: SomeAsyncException) ->
                        -- Restore cancellation during retries. Keep the original miss count.
                        restore (resolveSingleFlight afterClaim (const pass) recordInsert sf key fetch)
                    -- A synchronous escape broke the fetch's total contract. Re-raise it
                    -- as an invariant break, never laundered into the typed channel.
                    Nothing -> throwIO err
        Lead marker -> do
            recordRequest Metric.Miss
            -- Mask publication and insertion so cancellation cannot strand followers.
            (outcome, occupancy) <- guardInFlight id (orphan marker) (atomically deregister) $ do
                fetched <- restore (afterClaim >> fetch)
                atomically (putTMVar marker (either FlightFault FlightValue fetched))
                -- The join collapses "nothing fetched" and "fetched but oversized,
                -- served uncached" into one no-insert outcome for the telemetry.
                inserted <- join <$> traverse (insertBounded sf key) (rightToMaybe fetched)
                pure (fetched, inserted)
            -- The leader inserted, so refresh the occupancy gauges (a follower never does).
            traverse_ recordInsert occupancy
            pure outcome
  where
    deregister :: STM ()
    deregister = do
        inFlight <- readTVar (sfInFlight sf)
        writeTVar (sfInFlight sf) (Map.delete key inFlight)

insertBounded :: (Hashable k) => SingleFlight e k v -> k -> v -> IO (Maybe CacheOccupancy)
insertBounded sf key value
    | weight == maxBound || weight > sfMaxBytes sf = pure Nothing
    | otherwise = withMVar (sfInsertLock sf) $ \() -> do
        Cache.purgeExpired (sfStore sf)
        evictToBudget sf weight
        stamp <- nextStamp sf
        stampRef <- newIORef stamp
        Cache.insert (sfStore sf) key (Weighted{wValue = value, wWeight = weight, wStamp = stampRef})
        Just <$> occupancyOf sf
  where
    weight = sfWeigh sf value

evictToBudget :: (Hashable k) => SingleFlight e k v -> Int -> IO ()
evictToBudget sf incoming = do
    held <- Cache.toList (sfStore sf)
    stamped <- traverse stampOf held
    let resident = sum [wWeight w | (_, w, _) <- held]
        oldestFirst = sortOn (\(stamp, _, _) -> stamp) stamped
    go oldestFirst resident (length held)
  where
    stampOf (k, w, _) = do
        s <- readIORef (wStamp w)
        pure (s, k, wWeight w)

    fits resident count = resident <= sfMaxBytes sf - incoming && count < sfMaxEntries sf

    go victims resident count
        | fits resident count = pass
        | otherwise = case victims of
            [] -> pass
            ((_, k, weight) : rest) -> do
                Cache.delete (sfStore sf) k
                go rest (resident - weight) (count - 1)

-- The store's occupancy after an insert: the entry count and the summed resident weight
-- of the held entries, the values the residency telemetry reports.
occupancyOf :: SingleFlight e k v -> IO CacheOccupancy
occupancyOf sf = do
    held <- Cache.toList (sfStore sf)
    pure CacheOccupancy{occEntries = length held, occBytes = sum [wWeight w | (_, w, _) <- held]}

-- Issue the next logical access stamp from the store's clock: a strictly increasing
-- 'Word64', so a larger stamp is more recent.
nextStamp :: SingleFlight e k v -> IO Word64
nextStamp sf = atomicModifyIORef' (sfClock sf) (\n -> let n' = n + 1 in (n', n'))

-- Bump a held entry's recency to the current logical time, marking it most-recently-used.
-- Runs in plain 'IO' (never STM), so a hit refreshes recency without writing the store.
touch :: SingleFlight e k v -> Weighted v -> IO ()
touch sf weighted = nextStamp sf >>= writeIORef (wStamp weighted)

-- | Read without fetching or refreshing recency.
lookupStore :: (Hashable k) => SingleFlight e k v -> k -> IO (Maybe v)
lookupStore sf key = fmap wValue <$> Cache.lookup (sfStore sf) key

-- | Read without fetching and refresh recency on a hit.
lookupStoreTouching :: (Hashable k) => SingleFlight e k v -> k -> IO (Maybe v)
lookupStoreTouching sf key =
    Cache.lookup (sfStore sf) key >>= traverse (\weighted -> wValue weighted <$ touch sf weighted)

-- The one atomic resolve decision: a fresh hit, follow an in-flight fetch, or lead a new
-- one. A hit carries the weighted entry so the caller can bump its recency.
data Decision e v
    = Hit (Weighted v)
    | Follow (TMVar (FlightOutcome e v))
    | Lead (TMVar (FlightOutcome e v))

-- The one atomic resolve decision for a key: a fresh hit wins, else follow the key's
-- in-flight fetch, else install a marker and lead. Runs inside 'resolveSingleFlight''s mask.
decideSingleFlight :: (Hashable k, Ord k) => SingleFlight e k v -> k -> TimeSpec -> STM (Decision e v)
decideSingleFlight sf key nowT = do
    hit <- Cache.lookupSTM False key (sfStore sf) nowT
    case hit of
        Just weighted -> pure (Hit weighted)
        Nothing -> do
            inFlight <- readTVar (sfInFlight sf)
            case Map.lookup key inFlight of
                Just marker -> pure (Follow marker)
                Nothing -> do
                    marker <- newEmptyTMVar
                    writeTVar (sfInFlight sf) (Map.insert key marker inFlight)
                    pure (Lead marker)

-- Hand the escaping error to blocked followers so they unblock rather than park forever.
-- Fills only when empty, so an escape after a successful publish never clobbers the result.
orphan :: TMVar (FlightOutcome e v) -> SomeException -> IO ()
orphan marker err =
    atomically $ do
        unfilled <- isEmptyTMVar marker
        when unfilled (putTMVar marker (FlightOrphaned err))

-- | Entry count and summed accounted bytes after a retaining insert.
data CacheOccupancy = CacheOccupancy
    { occEntries :: Int
    , occBytes :: Int
    }

-- Convert a 'NominalDiffTime' (seconds) to the @cache@ library's monotonic
-- 'TimeSpec' via 'fromNanoSecs', clamping a negative TTL to zero.
toTimeSpec :: NominalDiffTime -> TimeSpec
toTimeSpec ttl = fromNanoSecs (max 0 (round (realToFrac ttl * 1e9 :: Double) :: Integer))
