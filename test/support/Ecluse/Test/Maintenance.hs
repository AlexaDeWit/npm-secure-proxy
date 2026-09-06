-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | An in-memory 'Ecluse.Core.Registry.Maintenance.StoreMaintenance', the third
implementation of the handle. It answers from a seeded map that its own deletes mutate, so a
sweep driven against it observes the store changing, and it keeps a walk cursor in an 'IORef'.
Its defaults take the opposite arm of every backend-varying fact from the CodeArtifact leaf,
which is what shows that a fact is a value the handle supplies rather than a branch a caller takes.
-}
module Ecluse.Test.Maintenance (
    FakeStore (..),
    FakeStoreConfig (..),
    defaultFakeStoreConfig,
    newFakeStore,
    withBucket,

    -- * The manifest read a listing case does not wire
    unwiredRead,
) where

import Data.Conduit (ConduitT, (.|))
import Data.Conduit.List qualified as CL
import Data.Map.Strict qualified as Map

import Ecluse.Core.Package (PackageName)
import Ecluse.Core.Registry.Maintenance (
    CompletionNotion (CompletesLater),
    ConsentVerdict (ConsentGranted),
    DeleteCeiling (AtMost),
    NamePrefix,
    RefillPosture (RefillRefused),
    StoreClass (StoreDestroyable),
    StoreCursor (..),
    StoreFacts (..),
    StoreFault,
    StoreMaintenance (..),
    StoreManifestRead,
    StoredVersion (..),
    VersionOutcome (VersionRefused, VersionRemoving),
    inBucket,
    mkNameAlphabet,
    noNameAlphabet,
    parseNamePrefix,
    protocolFault,
    storeFaultOfMetadata,
    storeRefusal,
    unreachedBatch,
 )
import Ecluse.Core.Registry.Metadata (Manifest, MetadataError (MetadataUndecodable))
import Ecluse.Core.Version (Version)

-- | What a fake store holds and answers with.
data FakeStoreConfig = FakeStoreConfig
    { fakeContents :: Map PackageName [StoredVersion]
    -- ^ The packages and versions the store starts with.
    , fakeConsent :: ConsentVerdict
    , fakeClass :: StoreClass
    , fakeFacts :: StoreFacts
    , fakeFault :: Maybe StoreFault
    -- ^ When set, every call faults with it, so a caller's fault path is drivable.
    , fakePageSize :: Int
    -- ^ How many names one listing page carries, so a caller's paging is drivable.
    , fakeKeepsCursor :: Bool
    -- ^ Whether the store offers a walk cursor, the arm a protocol-only store does not take.
    , fakeManifests :: Map PackageName Manifest
    -- ^ The metadata the store serves per package. A package absent here reads as undecodable.
    }

{- | A consenting, destroyable, empty store whose facts take the arm CodeArtifact does not: a small
ceiling, no re-publication, a late-finishing delete, and a name space its listing cannot partition.
-}
defaultFakeStoreConfig :: FakeStoreConfig
defaultFakeStoreConfig =
    FakeStoreConfig
        { fakeContents = Map.empty
        , fakeConsent = ConsentGranted
        , fakeClass = StoreDestroyable
        , fakeFacts =
            StoreFacts
                { factBackend = "fake"
                , factDeleteCeiling = AtMost 2
                , factRefill = RefillRefused
                , factCompletion = CompletesLater
                , factNameAlphabet = noNameAlphabet
                }
        , fakeFault = Nothing
        , fakePageSize = 2
        , fakeKeepsCursor = True
        , fakeManifests = Map.empty
        }

-- | A fake store: the handle a caller drives, and the state a test asserts against.
data FakeStore = FakeStore
    { fakeMaintenance :: StoreMaintenance
    , readFakeContents :: IO (Map PackageName [StoredVersion])
    , readFakeCursor :: IO (Maybe NamePrefix)
    }

-- | Build a fake store over its seeded contents, with no walk in progress.
newFakeStore :: FakeStoreConfig -> IO FakeStore
newFakeStore config = do
    contents <- newIORef (fakeContents config)
    cursor <- newIORef Nothing
    pure
        FakeStore
            { fakeMaintenance =
                StoreMaintenance
                    { storeFacts = fakeFacts config
                    , listPackagesIn = listBucket config contents
                    , enumerateVersions = \name ->
                        orFault config (Map.findWithDefault [] name <$> readIORef contents)
                    , readStoreManifest = pure . readSeededManifest config
                    , deleteVersions = \name versions -> case fakeFault config of
                        Just fault -> pure (unreachedBatch fault versions)
                        Nothing -> atomicModifyIORef' contents (removeVersions name versions)
                    , rehearseDelete = Just $ \name versions ->
                        snd . removeVersions name versions <$> readIORef contents
                    , verifyConsent = orFault config (pure (fakeConsent config))
                    , classifyStore = orFault config (pure (fakeClass config))
                    , storeCursor = fakeStoreCursor config cursor
                    }
            , readFakeContents = readIORef contents
            , readFakeCursor = readIORef cursor
            }

{- The names in one bucket, cut into pages of the configured size. A configured fault ends the
stream before its first page, which is the shape a store that never answered takes. -}
listBucket ::
    FakeStoreConfig ->
    IORef (Map PackageName [StoredVersion]) ->
    NamePrefix ->
    ConduitT () [PackageName] IO (Maybe StoreFault)
listBucket config contents prefix = case fakeFault config of
    Just fault -> pure (Just fault)
    Nothing -> do
        names <- lift (filter (inBucket prefix) . Map.keys <$> readIORef contents)
        Nothing <$ (CL.sourceList names .| CL.chunksOf (max 1 (fakePageSize config)))

{- The walk cursor, kept in memory. A store configured to keep none takes the arm a store with
nowhere to write one takes, where a walk resumes from the first bucket every time. -}
fakeStoreCursor :: FakeStoreConfig -> IORef (Maybe NamePrefix) -> Maybe StoreCursor
fakeStoreCursor config cursor
    | not (fakeKeepsCursor config) = Nothing
    | otherwise =
        Just
            StoreCursor
                { readCursor = orFault config (readIORef cursor)
                , writeCursor = orFault config . writeIORef cursor . Just
                , clearCursor = orFault config (writeIORef cursor Nothing)
                }

{- The metadata the store was seeded with. A package it holds no manifest for reads as a store
that answered with something no manifest could be projected from, which keeps every version. -}
readSeededManifest :: FakeStoreConfig -> PackageName -> Either StoreFault Manifest
readSeededManifest config name =
    case fakeFault config of
        Just fault -> Left fault
        Nothing ->
            maybeToRight
                (storeFaultOfMetadata MetadataUndecodable)
                (Map.lookup name (fakeManifests config))

-- Every read answers the configured fault instead, when there is one.
orFault :: FakeStoreConfig -> IO a -> IO (Either StoreFault a)
orFault config action = maybe (Right <$> action) (pure . Left) (fakeFault config)

{- | The manifest read for a case that drives enumeration alone: the composition root wires the
real one, so a case that never reads metadata faults with a message instead of reaching a store.
-}
unwiredRead :: StoreManifestRead
unwiredRead _ = pure (Left (protocolFault "the spec wired no manifest read"))

{- | Run an assertion over the bucket one spelling names, through the parser a cursor read uses.
The alphabet carries the spelling, so a refusal means the prefix vocabulary changed under the spec.
-}
withBucket :: Text -> (NamePrefix -> IO a) -> IO a
withBucket raw act = case parseNamePrefix (mkNameAlphabet (toString raw)) raw of
    Nothing -> fail ("no bucket spells " <> toString raw)
    Just prefix -> act prefix

{- Drop the named versions and report one outcome each. A version the store does not hold
is refused rather than reported gone, so a caller cannot mistake a miss for a delete. -}
removeVersions ::
    PackageName ->
    [Version] ->
    Map PackageName [StoredVersion] ->
    (Map PackageName [StoredVersion], [(Version, VersionOutcome)])
removeVersions name versions contents =
    (Map.adjust (filter kept) name contents, map outcome versions)
  where
    held = map storedVersion (Map.findWithDefault [] name contents)
    kept stored = storedVersion stored `notElem` versions
    outcome version
        | version `elem` held = (version, VersionRemoving "fake-operation")
        | otherwise =
            (version, VersionRefused (storeRefusal "NOT_FOUND" "the store holds no such version"))
