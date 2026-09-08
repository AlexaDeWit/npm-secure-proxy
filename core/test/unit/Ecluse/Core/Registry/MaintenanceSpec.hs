-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Core.Registry.MaintenanceSpec (spec) where

import Data.Conduit (fuseUpstream, runConduit, (.|))
import Data.Conduit.List qualified as CL
import Data.Text qualified as T
import Test.Hspec

import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.Fault (TransportCause (TransportProtocol, TransportTimeout), tfCause, tfDetail, transportFault)
import Ecluse.Core.Package (PackageName, mkPackageName, mkScope)
import Ecluse.Core.Registry (FetchFault (FetchTransport))
import Ecluse.Core.Registry.Maintenance (
    DeleteCeiling (AtMost, NoCeiling),
    RetryAdvice (RetryFutile, RetryWorthwhile),
    StoreFault (..),
    VersionOutcome (VersionRemoved, VersionUnreached),
    chunksOfCeiling,
    collectPages,
    deleteAll,
    extendBucket,
    inBucket,
    initialBuckets,
    mkNameAlphabet,
    noNameAlphabet,
    pageAll,
    pageSource,
    parseNamePrefix,
    refusalCode,
    refusalDetail,
    renderNamePrefix,
    storeFaultOfFetch,
    storeFaultOfMetadata,
    storeRefusal,
    unreachedBatch,
    wholeNameSpace,
 )
import Ecluse.Core.Registry.Metadata (
    MetadataError (MetadataAuthorisationFailure, MetadataBoundExceeded, MetadataFetch, MetadataNameMismatch, MetadataUndecodable),
 )
import Ecluse.Core.Security (LimitError (TooManyVersions))
import Ecluse.Core.Version (Version, mkVersion, renderVersion)
import Ecluse.Test.Maintenance (withBucket)

spec :: Spec
spec = do
    vocabularySpec
    readFaultSpec
    bucketSpec
    pagingSpec
    chunkingSpec
    deleteDriveSpec

bucketSpec :: Spec
bucketSpec = do
    describe "initialBuckets" $ do
        it "gives one bucket per character of the alphabet, in the order it was built with" $
            map renderNamePrefix (toList (initialBuckets (mkNameAlphabet "abc")))
                `shouldBe` ["a", "b", "c"]

        it "drops a repeated character, so no name lands in two buckets" $
            length (initialBuckets (mkNameAlphabet "aab")) `shouldBe` 2

        it "gives the one bucket that covers everything when the alphabet has no characters" $
            initialBuckets noNameAlphabet `shouldBe` wholeNameSpace :| []

        it "puts every name the alphabet leads into exactly one of its buckets" $
            map bucketsHolding names `shouldBe` replicate (length names) 1

    describe "extendBucket" $ do
        it "narrows a bucket by one character of the alphabet at a time" $
            withBucket "a" $ \a ->
                map renderNamePrefix (extendBucket (mkNameAlphabet "ab") a) `shouldBe` ["aa", "ab"]

        it "narrows nothing under an alphabet with no characters" $
            withBucket "a" $
                \a -> extendBucket noNameAlphabet a `shouldBe` []

        it "keeps the narrower buckets inside the one they came from" $
            withBucket "a" $ \a ->
                all (\narrower -> renderNamePrefix a `T.isPrefixOf` renderNamePrefix narrower) (extendBucket alphabet a)
                    `shouldBe` True

    describe "parseNamePrefix" $ do
        it "reads back a prefix the alphabet spells" $
            fmap renderNamePrefix (parseNamePrefix (mkNameAlphabet "abc") "ab") `shouldBe` Just "ab"

        it "reads no prefix from a spelling the alphabet does not carry" $
            parseNamePrefix (mkNameAlphabet "abc") "az" `shouldBe` Nothing

        it "still reads a prefix after a repeated character was dropped" $
            fmap renderNamePrefix (parseNamePrefix (mkNameAlphabet "aab") "ab") `shouldBe` Just "ab"

        it "reads the empty prefix under any alphabet, because it filters nothing" $ do
            fmap renderNamePrefix (parseNamePrefix (mkNameAlphabet "abc") "") `shouldBe` Just ""
            fmap renderNamePrefix (parseNamePrefix noNameAlphabet "") `shouldBe` Just ""

    describe "inBucket" $ do
        it "reads a name by its base component, so a namespace never decides the bucket" $
            withBucket "c" $ \prefix -> do
                inBucket prefix scopedName `shouldBe` True
                inBucket prefix (unscoped "banana") `shouldBe` False

        it "puts a name under exactly one of two buckets that do not overlap" $
            withBucket "a" $ \a -> withBucket "b" $ \b ->
                map (\name -> (inBucket a name, inBucket b name)) names
                    `shouldBe` [(True, False), (False, True), (False, False)]

        it "holds every name in the bucket that covers a whole store" $
            withBucket "" $ \everything ->
                map (inBucket everything) names `shouldBe` replicate (length names) True
  where
    names = [unscoped "apple", unscoped "banana", scopedName]

    -- The alphabet leads every one of those names, so the buckets it gives partition them.
    alphabet = mkNameAlphabet "abc"

    bucketsHolding name = length [() | b <- toList (initialBuckets alphabet), inBucket b name]

{- The two folds a store's reads go through. Only the transport half of either clears on its own,
so everything else advises against a second attempt in the same cycle. -}
readFaultSpec :: Spec
readFaultSpec = do
    describe "storeFaultOfFetch" $ do
        it "keeps a retryable transport cause worth another attempt" $
            faultRetry (storeFaultOfFetch (FetchTransport (transportFault TransportTimeout "no answer")))
                `shouldBe` RetryWorthwhile

        it "stops on a transport cause the next attempt reproduces" $
            faultRetry (storeFaultOfFetch (FetchTransport (transportFault TransportProtocol "malformed")))
                `shouldBe` RetryFutile

    describe "storeFaultOfMetadata" $ do
        for_ [401, 403] $ \code ->
            it ("does not retry explicit metadata access refusal " <> show code) $ do
                let fault = storeFaultOfMetadata (MetadataAuthorisationFailure code)
                faultRetry fault `shouldBe` RetryFutile
                tfDetail (faultTransport fault) `shouldBe` "the store refused metadata access"

        it "carries the transport half's own advice through" $
            faultRetry (storeFaultOfMetadata (MetadataFetch (FetchTransport (transportFault TransportTimeout "no answer"))))
                `shouldBe` RetryWorthwhile

        it "stops on a document that did not decode, whatever the store answers next" $
            map (faultRetry . storeFaultOfMetadata) undecodableArms
                `shouldBe` replicate (length undecodableArms) RetryFutile

        it "names the package a mismatched document reported, for the audit line" $
            tfDetail (faultTransport (storeFaultOfMetadata (MetadataNameMismatch "other")))
                `shouldSatisfy` T.isInfixOf "other"
  where
    undecodableArms =
        [MetadataUndecodable, MetadataNameMismatch "other", MetadataBoundExceeded (TooManyVersions 9 4)]

vocabularySpec :: Spec
vocabularySpec = do
    describe "storeRefusal" $ do
        it "keeps the backend's code and message" $ do
            let refusal = storeRefusal "NOT_FOUND" "no such version"
            refusalCode refusal `shouldBe` "NOT_FOUND"
            refusalDetail refusal `shouldBe` "no such version"

        it "bounds a pathological message to the shared log-line budget" $
            T.compareLength (refusalDetail (storeRefusal "X" (T.replicate 4000 "a"))) 512 `shouldBe` EQ

    describe "unreachedBatch" $ do
        it "gives every version in the batch one outcome" $ do
            let outcomes = unreachedBatch aFault (map version ["1.0.0", "1.1.0", "1.2.0"])
            map (renderVersion . fst) outcomes `shouldBe` ["1.0.0", "1.1.0", "1.2.0"]
            map snd outcomes `shouldBe` replicate 3 (VersionUnreached aFault)

        it "reports nothing for an empty batch" $
            unreachedBatch aFault [] `shouldBe` []

pagingSpec :: Spec
pagingSpec = do
    pageSourceSpec
    pageAllSpec

pageSourceSpec :: Spec
pageSourceSpec = describe "pageSource" $ do
    it "hands each page out as it arrives rather than the listing whole" $ do
        fetch <- pagesFrom [(Just "p2", ["a"]), (Nothing, ["b", "c"])]
        pagesOf fetch `shouldReturn` [["a"], ["b", "c"]]

    it "ends with no fault when the store walked the listing to its end" $ do
        fetch <- pagesFrom [(Nothing, ["a"])]
        faultEnding fetch `shouldReturn` Nothing

    it "hands out the pages that did arrive, then ends with the fault that stopped it" $ do
        -- A fresh fetch per walk, because the fixture hands each page out once.
        let faulting = do
                fetch <- pagesFrom [(Just "p2", ["a"])]
                pure $ \token -> if isJust token then pure (Left aFault) else fetch token
        (faulting >>= pagesOf) `shouldReturn` [["a"]]
        (faulting >>= faultEnding) `shouldReturn` Just aFault

    it "ends with a fault on a store that hands back a token it already gave" $ do
        fetch <- pagesFrom [(Just "p2", ["a"]), (Just "p2", ["b"])]
        outcome <- faultEnding fetch
        fmap faultRetry outcome `shouldBe` Just RetryFutile

pageAllSpec :: Spec
pageAllSpec = describe "pageAll" $ do
    it "is the page source collected whole, so the two share one fold" $ do
        walked <- pagesFrom [(Just "p2", ["a"]), (Nothing, ["b"])]
        collected <- pagesFrom [(Just "p2", ["a"]), (Nothing, ["b"])]
        outcome <- pageAll walked
        collectedPages collected `shouldReturn` outcome

    it "walks every page in order and returns one listing" $ do
        fetch <- pagesFrom [(Just "p2", ["a"]), (Just "p3", ["b"]), (Nothing, ["c"])]
        pageAll fetch `shouldReturn` Right ["a", "b", "c"]

    it "sends the token the previous page returned" $ do
        seen <- newIORef []
        fetch <- pagesFrom [(Just "p2", ["a"]), (Nothing, ["b"])]
        _ <- pageAll (\token -> modifyIORef' seen (<> [token]) >> fetch token)
        readIORef seen `shouldReturn` [Nothing, Just "p2"]

    it "reports the fault a page returned rather than a short listing" $ do
        fetch <- pagesFrom [(Just "p2", ["a"])]
        outcome <- pageAll (\token -> if isJust token then pure (Left aFault) else fetch token)
        outcome `shouldBe` Left aFault

    it "refuses a store that hands back the token it was just given" $ do
        fetch <- pagesFrom [(Just "p2", ["a"]), (Just "p2", ["b"])]
        outcome <- pageAll fetch
        outcome `shouldSatisfy` isLeft
        either (tfCause . faultTransport) (const TransportTimeout) outcome `shouldBe` TransportProtocol
        either faultRetry (const RetryWorthwhile) outcome `shouldBe` RetryFutile

    it "refuses a cycle through two tokens, which no single-step check would catch" $ do
        fetch <- pagesFrom [(Just "p2", ["a"]), (Just "p3", ["b"]), (Just "p2", ["c"])]
        outcome <- pageAll fetch
        outcome `shouldSatisfy` isLeft

    it "refuses a store that reopens a token several pages later" $ do
        fetch <-
            pagesFrom
                [(Just "p2", ["a"]), (Just "p3", ["b"]), (Just "p4", ["c"]), (Just "p3", ["d"])]
        outcome <- pageAll fetch
        outcome `shouldSatisfy` isLeft

chunkingSpec :: Spec
chunkingSpec = describe "chunksOfCeiling" $ do
    it "splits a batch at the ceiling and keeps the remainder" $ do
        let chunks = chunksOfCeiling (AtMost 100) [1 :: Int .. 250]
        map length chunks `shouldBe` [100, 100, 50]
        concat chunks `shouldBe` [1 .. 250]

    it "leaves a batch inside the ceiling whole, and an empty one empty" $ do
        chunksOfCeiling (AtMost 100) [1 :: Int .. 3] `shouldBe` [[1, 2, 3]]
        chunksOfCeiling (AtMost 100) ([] :: [Int]) `shouldBe` []

    it "takes one item at a time rather than divide forever on a ceiling below one" $
        chunksOfCeiling (AtMost 0) [1 :: Int .. 3] `shouldBe` [[1], [2], [3]]

    it "sends a batch of any size in one call to a backend with no ceiling" $ do
        chunksOfCeiling NoCeiling [1 :: Int .. 250] `shouldBe` [[1 .. 250]]
        chunksOfCeiling NoCeiling ([] :: [Int]) `shouldBe` []

deleteDriveSpec :: Spec
deleteDriveSpec = describe "deleteAll" $ do
    it "sends every chunk and collects the outcomes in order" $ do
        sent <- newIORef []
        outcomes <- deleteAll (recordingSender sent Nothing) chunks
        map (renderVersion . fst) outcomes `shouldBe` ["1.0.0", "1.1.0", "1.2.0"]
        map (map renderVersion) <$> readIORef sent `shouldReturn` [["1.0.0", "1.1.0"], ["1.2.0"]]

    it "stops sending once a chunk faults, because the fault carries the backend's advice" $ do
        sent <- newIORef []
        _ <- deleteAll (recordingSender sent (Just (version "1.0.0"))) chunks
        map (map renderVersion) <$> readIORef sent `shouldReturn` [["1.0.0", "1.1.0"]]

    it "marks the faulted chunk and every chunk it never sent unreached" $ do
        sent <- newIORef []
        outcomes <- deleteAll (recordingSender sent (Just (version "1.0.0"))) chunks
        map (renderVersion . fst) outcomes `shouldBe` ["1.0.0", "1.1.0", "1.2.0"]
        map snd outcomes `shouldBe` replicate 3 (VersionUnreached aFault)

    it "keeps the outcomes of the chunks that landed before the fault" $ do
        sent <- newIORef []
        outcomes <- deleteAll (recordingSender sent (Just (version "1.2.0"))) chunks
        map snd outcomes
            `shouldBe` [VersionRemoved, VersionRemoved, VersionUnreached aFault]

    it "reports nothing when there is no chunk to send" $ do
        sent <- newIORef []
        deleteAll (recordingSender sent Nothing) [] `shouldReturn` []
  where
    chunks = [[version "1.0.0", version "1.1.0"], [version "1.2.0"]]

{- A sender that records the chunks it was handed and faults on the chunk carrying the
named version, so a spec can place the fault at any point in the run. -}
recordingSender ::
    IORef [[Version]] ->
    Maybe Version ->
    [Version] ->
    IO (Either StoreFault [(Version, VersionOutcome)])
recordingSender sent faultOn batch = do
    modifyIORef' sent (<> [batch])
    pure $
        if maybe False (`elem` batch) faultOn
            then Left aFault
            else Right [(v, VersionRemoved) | v <- batch]

-- A fetch that answers from a fixed page sequence, so a listing walk is drivable in IO.
-- Every page a source handed out, discarding the fault the stream ended with.
pagesOf :: (Maybe Text -> IO (Either StoreFault (Maybe Text, [Text]))) -> IO [[Text]]
pagesOf fetch = runConduit (void (pageSource fetch) .| CL.consume)

-- | 'collectPages' over a page source, which is what 'pageAll' folds a paged fetch through.
collectedPages :: (Maybe Text -> IO (Either StoreFault (Maybe Text, [Text]))) -> IO (Either StoreFault [Text])
collectedPages = collectPages . pageSource

-- The fault a source ended with, discarding the pages it handed out on the way.
faultEnding :: (Maybe Text -> IO (Either StoreFault (Maybe Text, [Text]))) -> IO (Maybe StoreFault)
faultEnding fetch = runConduit (fuseUpstream (pageSource fetch) CL.sinkNull)

unscoped :: Text -> PackageName
unscoped = mkPackageName Npm Nothing

scopedName :: PackageName
scopedName = mkPackageName Npm (Just (mkScope "babel")) "core"

pagesFrom :: [(Maybe Text, [Text])] -> IO (Maybe Text -> IO (Either StoreFault (Maybe Text, [Text])))
pagesFrom pages = do
    remaining <- newIORef pages
    pure $ \_ ->
        atomicModifyIORef' remaining $ \case
            [] -> ([], Right (Nothing, []))
            (page : rest) -> (rest, Right page)

version :: Text -> Version
version = mkVersion Npm

aFault :: StoreFault
aFault =
    StoreFault
        { faultTransport = transportFault TransportTimeout "the store did not answer"
        , faultRetry = RetryWorthwhile
        }
