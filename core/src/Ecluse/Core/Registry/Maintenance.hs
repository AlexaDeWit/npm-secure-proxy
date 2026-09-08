-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The store maintenance handle: enumerate what a mirror store holds, and delete versions
from it. Enumeration and deletion are backend operations rather than ecosystem ones, because a
package protocol may spell no enumeration at all and a managed registry deletes through its own
control plane. So the handle sits beside "Ecluse.Core.Registry.Adapter" instead of inside it,
one value per backend, resolved at the Dredger's composition root. Every backend-varying fact
is a value the handle supplies rather than a branch a sweep takes, so a new backend is one more
handle and no change here.
-}
module Ecluse.Core.Registry.Maintenance (
    -- * The handle
    StoreMaintenance (..),

    -- * What the backend does
    StoreFacts (..),
    DeleteCeiling (..),
    RefillPosture (..),
    CompletionNotion (..),

    -- * Enumeration
    StoredVersion (..),
    VersionPresence (..),

    -- * The name space, walked in buckets
    NameAlphabet,
    mkNameAlphabet,
    noNameAlphabet,
    NamePrefix,
    wholeNameSpace,
    renderNamePrefix,
    parseNamePrefix,
    initialBuckets,
    extendBucket,
    inBucket,

    -- * Walk resumption
    StoreCursor (..),

    -- * Reading a package's metadata from the store
    StoreManifestRead,
    storeFaultOfFetch,
    storeFaultOfMetadata,
    protocolFault,
    unformableFault,

    -- * Deletion
    VersionOutcome (..),
    StoreRefusal,
    storeRefusal,
    refusalCode,
    refusalDetail,
    unreachedBatch,

    -- * Backend-neutral drives
    pageSource,
    collectPages,
    pageAll,
    chunksOfCeiling,
    deleteAll,

    -- * Verdicts
    ConsentVerdict (..),
    StoreClass (..),

    -- * Faults
    StoreFault (..),
    RetryAdvice (..),
) where

import Data.Conduit (ConduitT, fuseBoth, runConduit, yield)
import Data.Conduit.List qualified as CL
import Data.Set qualified as Set
import Data.Text qualified as T

import Ecluse.Core.Fault (
    RetryAfter,
    TransportCause (TransportProtocol),
    TransportFault,
    boundedDetail,
    tfCause,
    transportFault,
    transportRetryable,
 )
import Ecluse.Core.Package (PackageName, unscopedName)
import Ecluse.Core.Registry (
    FetchFault (FetchBoundExceeded, FetchTransport, FetchUrlUnformable),
    UrlFormationError,
    renderUrlFormationError,
 )
import Ecluse.Core.Registry.Metadata (
    Manifest,
    MetadataError (MetadataAuthorisationFailure, MetadataBoundExceeded, MetadataFetch, MetadataNameMismatch, MetadataUndecodable),
 )
import Ecluse.Core.Version (Version)

-- | The maintenance capabilities of one mirror store. Like the other handles, the effectful fields return __'IO', not @App@__, so an adapter never imports the proxy's @Env@.
data StoreMaintenance = StoreMaintenance
    { storeFacts :: StoreFacts
    -- ^ What the backend does, readable without a call.
    , listPackagesIn :: NamePrefix -> ConduitT () [PackageName] IO (Maybe StoreFault)
    -- ^ The packages in one bucket of the name space, a page at a time. The stream ends with the fault that stopped it, or 'Nothing' when the bucket was walked to its end.
    , enumerateVersions :: PackageName -> IO (Either StoreFault [StoredVersion])
    -- ^ Every version the store holds for one package, paged to exhaustion.
    , readStoreManifest :: StoreManifestRead
    -- ^ One package's metadata as this store serves it, through the ecosystem's own codec and the store's own credential. Every stored version is projected out of this one read.
    , deleteVersions :: PackageName -> [Version] -> IO [(Version, VersionOutcome)]
    -- ^ Delete versions of one package. The adapter splits the batch to its own ceiling, so any size is accepted and every version handed over gets exactly one outcome back.
    , rehearseDelete :: Maybe (PackageName -> [Version] -> IO [(Version, VersionOutcome)])
    -- ^ The backend's own dry run, where it has one: the outcomes a delete would report, with nothing deleted. 'Nothing' where a rehearsal has to stop short of the call.
    , verifyConsent :: IO (Either StoreFault ConsentVerdict)
    -- ^ Whether the operator has marked this store for deletion.
    , classifyStore :: IO (Either StoreFault StoreClass)
    -- ^ Whether deleting from this store destroys anything.
    , storeCursor :: Maybe StoreCursor
    -- ^ Where a full walk resumes after a restart, for a backend with somewhere to keep it. 'Nothing' starts every walk from the first bucket.
    }

-- | The backend's standing behaviour, fixed for the life of the handle. A sweep reads these rather than asking which backend it is talking to.
data StoreFacts = StoreFacts
    { factBackend :: Text
    -- ^ The backend's name, for the boot line that puts the Dredger's blast radius on record.
    , factDeleteCeiling :: DeleteCeiling
    -- ^ How many versions one destructive call accepts.
    , factRefill :: RefillPosture
    -- ^ What the backend does with a re-publication of a deleted version.
    , factCompletion :: CompletionNotion
    -- ^ When a delete is finished relative to the call that asked for it.
    , factNameAlphabet :: NameAlphabet
    -- ^ The characters this store's name space is partitioned into buckets by.
    }
    deriving stock (Eq, Show)

-- | Whether a version can come back under the same name after a delete. Recorded from the backend's own documentation, never enforced here, so a sweep warns and never promises.
data RefillPosture
    = -- | The backend accepts a re-publication of a version it deleted (CodeArtifact).
      RefillPermitted
    | -- | The backend refuses one, so a delete also retires the name for good (GCP Artifact Registry, for the npm format).
      RefillRefused
    deriving stock (Eq, Show)

-- | How many versions one destructive call accepts. A store with no control plane, an object store walked by prefix for one, deletes an object at a time or a listing at once.
data DeleteCeiling
    = -- | The backend takes a batch of any size, so a caller never splits one.
      NoCeiling
    | -- | The backend refuses a call carrying more than this many versions.
      AtMost Int
    deriving stock (Eq, Show)

-- | When a delete is finished, relative to the call that asked for it.
data CompletionNotion
    = -- | The delete is done by the time the call answers.
      CompletesOnCall
    | -- | The call starts a long-running operation, and the outcome names it.
      CompletesLater
    deriving stock (Eq, Show)

-- | One version an enumeration found, with what the store does with it now.
data StoredVersion = StoredVersion
    { storedVersion :: Version
    , storedPresence :: VersionPresence
    }
    deriving stock (Eq, Show)

-- | Whether the store still serves a version it holds. A backend lists a deleted version too, so a sweep blind to this would re-issue a destructive call for it on every cycle.
data VersionPresence
    = -- | The store serves the version, so deleting it removes something.
      VersionServed
    | -- | The store lists the version but no longer serves it.
      VersionWithdrawn
    deriving stock (Eq, Show)

-- | The characters a bucket prefix is built from: the leading characters of the names the mount's ecosystem admits, which the composition root reads off that ecosystem's adapter.
newtype NameAlphabet = NameAlphabet [Char]
    deriving stock (Eq, Show)

-- | Build an alphabet, dropping repeats and keeping the order given.
mkNameAlphabet :: [Char] -> NameAlphabet
mkNameAlphabet = NameAlphabet . ordNub

-- | The alphabet of a store whose listing carries no filter to partition it by. Such a store is walked as the one bucket that covers everything, rather than as a special case.
noNameAlphabet :: NameAlphabet
noNameAlphabet = NameAlphabet []

-- | One bucket of a store's name space: a prefix of a package name's __base component__, the part after any namespace, because that is the component a store's own listing filters on.
newtype NamePrefix = NamePrefix Text
    deriving stock (Eq, Ord, Show)

-- | The bucket that covers a whole store: the empty prefix, which filters nothing. It is the one bucket an alphabet with no characters offers.
wholeNameSpace :: NamePrefix
wholeNameSpace = NamePrefix ""

-- | The prefix as a store filter and a walk cursor spell it. Empty stands for no filter at all.
renderNamePrefix :: NamePrefix -> Text
renderNamePrefix (NamePrefix raw) = raw

-- | Read a prefix back, 'Nothing' for one this alphabet cannot spell. A cursor written under a different alphabet then reads as none, and the walk restarts rather than resuming out of reach.
parseNamePrefix :: NameAlphabet -> Text -> Maybe NamePrefix
parseNamePrefix (NameAlphabet chars) raw
    | T.all (`elem` chars) raw = Just (NamePrefix raw)
    | otherwise = Nothing

-- | The buckets a full walk covers. They are disjoint and their union is the whole store, so a walk that completes every one of them has seen every package.
initialBuckets :: NameAlphabet -> NonEmpty NamePrefix
initialBuckets (NameAlphabet chars) =
    maybe (wholeNameSpace :| []) (fmap (NamePrefix . T.singleton)) (nonEmpty chars)

-- | The narrower buckets that cover one bucket, for a listing that outgrew its budget. An alphabet with no characters can narrow nothing, so it yields none.
extendBucket :: NameAlphabet -> NamePrefix -> [NamePrefix]
extendBucket (NameAlphabet chars) (NamePrefix raw) =
    [NamePrefix (raw <> T.singleton ch) | ch <- chars]

-- | Whether a name falls in a bucket, for a store whose listing has no prefix filter of its own.
inBucket :: NamePrefix -> PackageName -> Bool
inBucket (NamePrefix raw) name = raw `T.isPrefixOf` unscopedName name

-- | Where a full walk resumes: the last bucket it completed, kept in whatever the backend has to keep it in. A restart re-does at most the bucket that was in flight.
data StoreCursor = StoreCursor
    { readCursor :: IO (Either StoreFault (Maybe NamePrefix))
    -- ^ The bucket the last run completed, 'Nothing' when no walk is under way.
    , writeCursor :: NamePrefix -> IO (Either StoreFault ())
    -- ^ Record a completed bucket, replacing whatever was recorded before.
    , clearCursor :: IO (Either StoreFault ())
    -- ^ Forget the walk, which a completed one does so the next starts from the first bucket.
    }

-- | What became of one version a caller asked to delete.
data VersionOutcome
    = -- | The backend removed it before answering.
      VersionRemoved
    | -- | The backend accepted the removal and carries on, named by the reference an operator follows the work with.
      VersionRemoving Text
    | -- | The backend refused this one version and said why.
      VersionRefused StoreRefusal
    | -- | The call carrying this version did not reach the backend.
      VersionUnreached StoreFault
    deriving stock (Eq, Show)

-- | A backend's refusal of one version. Build it with 'storeRefusal' so the detail stays bounded.
data StoreRefusal = StoreRefusal
    { refusalCode :: Text
    -- ^ The backend's own code, which an operator looks up in its documentation.
    , refusalDetail :: Text
    -- ^ The backend's message, bounded to the shared log-line budget and never parsed.
    }
    deriving stock (Eq, Show)

-- | Build a 'StoreRefusal', truncating the detail to the log-line budget.
storeRefusal :: Text -> Text -> StoreRefusal
storeRefusal code detail = StoreRefusal code (boundedDetail detail)

-- | Mark a whole batch unreached, for when the call carrying it faulted. An adapter uses this so a caller reads one outcome per version whether the call landed or not.
unreachedBatch :: StoreFault -> [Version] -> [(Version, VersionOutcome)]
unreachedBatch fault versions = [(version, VersionUnreached fault) | version <- versions]

-- | Whether the operator has consented to deletion from this store.
data ConsentVerdict
    = -- | The store carries the consent marker.
      ConsentGranted
    | -- | It does not. The text is the backend's own how-to-attach descriptor, logged verbatim, because the marker is a tag on one backend and an object on another.
      ConsentWithheld Text
    deriving stock (Eq, Show)

-- | Whether deleting from this store destroys anything.
data StoreClass
    = -- | A private store that holds only what was published to it, so a delete is final.
      StoreDestroyable
    | -- | A store that refills itself from somewhere else, carrying why. A pull-through cache serves a deleted version again, so sweeping one changes nothing.
      StorePreserved Text
    deriving stock (Eq, Show)

-- | A maintenance call that produced no answer, classified once at the adapter edge. The transport half is "Ecluse.Core.Fault"'s vocabulary, and the advice half is what to do next.
data StoreFault = StoreFault
    { faultTransport :: TransportFault
    , faultRetry :: RetryAdvice
    }
    deriving stock (Eq, Show)

-- | What a caller does after a fault.
data RetryAdvice
    = -- | Another attempt fails the same way, so the caller stops.
      RetryFutile
    | -- | Worth another attempt, with no delay the backend asked for.
      RetryWorthwhile
    | -- | Worth another attempt, no sooner than the delay the backend itself asked for.
      RetryDelayed RetryAfter
    deriving stock (Eq, Show)

-- | Walk a paged listing a page at a time, ending with the fault that stopped it. A store that returns a page token it has already handed out would page forever, so that ends the walk too.
pageSource ::
    (Monad m) =>
    (Maybe Text -> m (Either StoreFault (Maybe Text, [a]))) ->
    ConduitT i [a] m (Maybe StoreFault)
pageSource fetch = go Set.empty Nothing
  where
    go seen token =
        lift (fetch token) >>= \case
            Left fault -> pure (Just fault)
            Right (next, page) -> do
                yield page
                case next of
                    Nothing -> pure Nothing
                    Just following
                        | Set.member following seen -> pure (Just (repeatedTokenFault following))
                        | otherwise -> go (Set.insert following seen) (Just following)

-- | Collect a page stream whole, for a listing one caller can hold. A store's packages go through 'pageSource' a page at a time instead, so nothing downstream holds a store listing whole.
collectPages :: (Monad m) => ConduitT () [a] m (Maybe StoreFault) -> m (Either StoreFault [a])
collectPages source = outcome <$> runConduit (fuseBoth source CL.consume)
  where
    outcome (mFault, pages) = maybe (Right (concat pages)) Left mFault

-- | Walk a paged listing to exhaustion, for a listing one caller can hold: a package's versions, never a store's packages. A faulted walk yields the fault alone, never the pages before it.
pageAll ::
    (Monad m) =>
    (Maybe Text -> m (Either StoreFault (Maybe Text, [a]))) ->
    m (Either StoreFault [a])
pageAll = collectPages . pageSource

-- A cycle in the store's own paging, which the next attempt reproduces.
repeatedTokenFault :: Text -> StoreFault
repeatedTokenFault token =
    StoreFault
        { faultTransport =
            transportFault TransportProtocol ("the store handed back a page token it had already given: " <> token)
        , faultRetry = RetryFutile
        }

-- | Reading one package's metadata from a store. The composition root assembles it from the mount's ecosystem and the store's endpoint, so no backend leaf speaks a package protocol.
type StoreManifestRead = PackageName -> IO (Either StoreFault Manifest)

-- | Fold a data-plane read fault into the maintenance vocabulary. A malformed answer, an oversized body, and an unformable URL all read the same way next cycle, so none is worth another try.
storeFaultOfFetch :: FetchFault -> StoreFault
storeFaultOfFetch = \case
    FetchTransport fault ->
        StoreFault
            { faultTransport = fault
            , faultRetry = if transportRetryable (tfCause fault) then RetryWorthwhile else RetryFutile
            }
    FetchBoundExceeded _ -> protocolFault "the store's answer crossed the response-size bound"
    FetchUrlUnformable err -> unformableFault err

-- | Fold a manifest read's failure into the maintenance vocabulary. Only the transport half can clear on its own: a document that did not decode decodes the same way on the next attempt.
storeFaultOfMetadata :: MetadataError -> StoreFault
storeFaultOfMetadata = \case
    MetadataAuthorisationFailure _ -> protocolFault "the store refused metadata access"
    MetadataFetch fault -> storeFaultOfFetch fault
    MetadataBoundExceeded _ -> protocolFault "the store's metadata crossed a structural bound"
    MetadataUndecodable -> protocolFault "the store's metadata did not decode into a manifest"
    MetadataNameMismatch reported ->
        protocolFault ("the store's metadata reported another package's name: " <> reported)

-- | A URL the store's own coordinates could not form, reduced to its authority.
unformableFault :: UrlFormationError -> StoreFault
unformableFault err =
    protocolFault ("the store's request could not be formed: " <> renderUrlFormationError err)

-- | A fault in the store's own answer, which the next attempt reproduces.
protocolFault :: Text -> StoreFault
protocolFault detail =
    StoreFault{faultTransport = transportFault TransportProtocol detail, faultRetry = RetryFutile}

-- | Split a batch into chunks the backend's destructive call accepts. A ceiling below one would divide the batch forever, so it takes one item at a time instead.
chunksOfCeiling :: DeleteCeiling -> [a] -> [[a]]
chunksOfCeiling ceiling' items = case ceiling' of
    NoCeiling -> [items | not (null items)]
    AtMost limit -> go (max 1 limit) items
  where
    go _ [] = []
    go size batch = let (chunk, rest) = splitAt size batch in chunk : go size rest

-- | Send each chunk in turn and collect one outcome per version. A faulted chunk stops the run, because the fault carries the backend's own retry advice.
deleteAll ::
    (Monad m) =>
    ([Version] -> m (Either StoreFault [(Version, VersionOutcome)])) ->
    [[Version]] ->
    m [(Version, VersionOutcome)]
deleteAll send = go []
  where
    go sent [] = pure (concat (reverse sent))
    go sent (chunk : rest) =
        send chunk >>= \case
            Left fault -> pure (concat (reverse sent) <> concatMap (unreachedBatch fault) (chunk : rest))
            Right outcomes -> go (outcomes : sent) rest
