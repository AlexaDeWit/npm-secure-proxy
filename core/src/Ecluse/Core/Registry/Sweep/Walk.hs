-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Walking a store's whole name space, bucket by bucket, and remembering where the walk got to.

No store this build reaches documents a listing order, and none offers a start-after cursor, so
a walk cannot resume at a name. What every store does offer is a name-prefix filter, so the walk
partitions the name space into prefix buckets and resumes at a bucket boundary: a restart re-does
at most the bucket that was in flight. A bucket whose listing outgrows the memory budget is
replaced by the narrower buckets that cover it.
-}
module Ecluse.Core.Registry.Sweep.Walk (
    bucketNameBudget,
    walkBuckets,
    resumeAfter,
    BucketNames (..),
    collectBucket,
) where

import Data.Conduit (ConduitT, await, fuseBothMaybe, runConduit)

import Ecluse.Core.Package (PackageName)
import Ecluse.Core.Registry.Maintenance (
    NameAlphabet,
    NamePrefix,
    StoreFault,
    extendBucket,
    initialBuckets,
 )

{- | How many names one bucket may hold before it is split. A held name costs about 96 bytes, so
this is roughly a megabyte, and a store that outgrows it is walked in narrower buckets instead.
-}
bucketNameBudget :: Int
bucketNameBudget = 10000

{- | The buckets a walk covers, in the order it covers them. A bucket that overflowed is replaced
in place by the narrower buckets covering it, so the sequence stays lexicographically ordered and
the cursor's own ordering still decides what a resumption has already done.
-}
walkBuckets :: NameAlphabet -> [NamePrefix]
walkBuckets alphabet = toList (initialBuckets alphabet)

{- | The buckets still to do after a recorded one. The sequence is lexicographically ordered and
a split only ever refines a prefix in place, so dropping every bucket at or before the record is
correct whether or not the recorded bucket was itself a split one.
-}
resumeAfter :: Maybe NamePrefix -> [NamePrefix] -> [NamePrefix]
resumeAfter = maybe id (\done -> dropWhile (<= done))

-- | What reading one bucket's listing produced.
data BucketNames
    = -- | The bucket was read whole, its names sorted.
      BucketRead [PackageName]
    | -- | The bucket holds more names than the budget, so these narrower ones cover it instead.
      BucketOverflowed [NamePrefix]
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
collectBucket alphabet prefix source = outcome <$> runConduit (fuseBothMaybe source takeToBudget)
  where
    -- The budget is read first: it is the arm that abandons the stream, so the listing has no
    -- result of its own to report when it fires.
    outcome = \case
        (_, Nothing) -> BucketOverflowed (extendBucket alphabet prefix)
        (Just (Just fault), _) -> BucketFaulted fault
        (_, Just names) -> BucketRead (sort names)

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
