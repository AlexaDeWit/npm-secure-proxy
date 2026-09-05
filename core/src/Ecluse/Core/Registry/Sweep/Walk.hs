-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Walking a store's whole name space, bucket by bucket, and remembering where the walk got to.

No store this build reaches documents a listing order, and none offers a start-after cursor, so a
walk cannot resume at a name. What every store does offer is a name-prefix filter, so the walk
partitions the name space into prefix buckets and resumes at a bucket boundary. A bucket whose
listing outgrows the memory budget is replaced by the narrower buckets that cover it, down to a
depth bound past which narrowing has stopped helping.
-}
module Ecluse.Core.Registry.Sweep.Walk (
    bucketNameBudget,
    bucketDepthLimit,
    walkBuckets,
    resumeAfter,
    BucketNames (..),
    collectBucket,
) where

import Data.Conduit (ConduitT, await, fuseBothMaybe, runConduit)
import Data.Conduit.List qualified as CL
import Data.Text qualified as T

import Ecluse.Core.Package (PackageName)
import Ecluse.Core.Registry.Maintenance (
    NameAlphabet,
    NamePrefix,
    StoreFault,
    extendBucket,
    initialBuckets,
    renderNamePrefix,
 )

{- | How many names one bucket may hold before it is split. A held name costs about 96 bytes, so
this is roughly a megabyte.
-}
bucketNameBudget :: Int
bucketNameBudget = 10000

{- | How far a bucket may be narrowed. Past it the names share a prefix this long and narrowing
has stopped dividing them, so the walk reports rather than descending without end.
-}
bucketDepthLimit :: Int
bucketDepthLimit = 4

-- | The buckets a walk covers, in the order it covers them.
walkBuckets :: NameAlphabet -> [NamePrefix]
walkBuckets = toList . initialBuckets

{- | The buckets still to cover, given the one last completed. A bucket the record falls inside is
kept, because the walk stopped part way through that bucket's own split.
-}
resumeAfter :: Maybe NamePrefix -> [NamePrefix] -> [NamePrefix]
resumeAfter = maybe id (filter . stillToDo)

{- A bucket is done when it sorts at or before the record without containing it. Containing it
means the record is a narrower bucket inside this one, so this one is only part done. -}
stillToDo :: NamePrefix -> NamePrefix -> Bool
stillToDo done bucket = bucket > done || properlyCovers bucket done

properlyCovers :: NamePrefix -> NamePrefix -> Bool
properlyCovers bucket done = raw /= renderNamePrefix done && raw `T.isPrefixOf` renderNamePrefix done
  where
    raw = renderNamePrefix bucket

-- | What reading one bucket's listing produced.
data BucketNames
    = -- | The bucket was read whole, its names sorted.
      BucketRead [PackageName]
    | -- | The bucket outgrew the budget, so these narrower ones cover it instead.
      BucketOverflowed (NonEmpty NamePrefix)
    | -- | The bucket outgrew the budget and nothing narrows it further.
      BucketUnsplittable
    | -- | The listing stopped on a fault, and nothing was read.
      BucketFaulted StoreFault

{- | Read one bucket's names, sorted, or report that it must be split. The stream is abandoned as
soon as the budget is crossed, so an oversized bucket costs a partial listing and never the whole.
-}
collectBucket ::
    NameAlphabet ->
    NamePrefix ->
    ConduitT () [PackageName] IO (Maybe StoreFault) ->
    IO BucketNames
collectBucket alphabet prefix source = case narrowerBuckets alphabet prefix of
    -- A store whose listing carries no filter to partition by, and a bucket already at the depth
    -- bound, both have no split to fall back on, so neither takes the budget.
    Nothing -> unbudgeted <$> runConduit (fuseBothMaybe source CL.consume)
    Just narrower -> outcome narrower <$> runConduit (fuseBothMaybe source takeToBudget)
  where
    unbudgeted = \case
        (Just (Just fault), _) -> BucketFaulted fault
        (_, pages) -> BucketRead (sort (concat pages))

    -- The budget is read first: it is the arm that abandons the stream, so the listing has no
    -- result of its own to report when it fires.
    outcome narrower = \case
        (_, Nothing) -> overflowed narrower
        (Just (Just fault), _) -> BucketFaulted fault
        (_, Just names) -> BucketRead (sort names)

    overflowed = maybe BucketUnsplittable BucketOverflowed . nonEmpty

{- The buckets covering this one, or nothing where none can. An alphabet with no characters can
narrow nothing, and past the depth bound a further character has stopped dividing the names. -}
narrowerBuckets :: NameAlphabet -> NamePrefix -> Maybe [NamePrefix]
narrowerBuckets alphabet prefix
    | T.length (renderNamePrefix prefix) >= bucketDepthLimit = Just []
    | null narrower = Nothing
    | otherwise = Just narrower
  where
    narrower = extendBucket alphabet prefix

{- Fold the pages until the bucket is read or the budget is crossed. 'Nothing' means the budget
went first, which abandons the stream where it stands. -}
takeToBudget :: ConduitT [PackageName] o IO (Maybe [PackageName])
takeToBudget = go 0 []
  where
    go held pages =
        await >>= \case
            Nothing -> pure (Just (concat (reverse pages)))
            Just page
                | held + length page > bucketNameBudget -> pure Nothing
                | otherwise -> go (held + length page) (page : pages)
