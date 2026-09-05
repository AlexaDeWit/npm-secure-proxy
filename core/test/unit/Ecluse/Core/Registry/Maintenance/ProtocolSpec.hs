-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The protocol leaf driven against an in-process upstream that records what Écluse sent.
The upstream implements none of a store's behaviour: it answers by path and method, so the
leaf's sequencing, fault mapping, and verdicts are what the assertions read.
-}
module Ecluse.Core.Registry.Maintenance.ProtocolSpec (spec) where

import Data.Aeson (Object, Value (Object), decodeStrict, encode, object, (.=))
import Data.Aeson.Key qualified as Key
import Data.Aeson.KeyMap qualified as KeyMap
import Data.ByteString.Lazy qualified as LBS
import Data.Map.Strict qualified as Map
import Data.Text qualified as T
import Network.HTTP.Client (Manager, defaultManagerSettings, newManager)
import Network.HTTP.Types.Status (Status, status200, status201, status404, status500, status503)
import Test.Hspec

import Ecluse.Core.Credential (bareCredential, mkSecret)
import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.Fault (TransportCause (TransportUnreachable), tfCause, tfDetail)
import Ecluse.Core.Package (PackageInfo (infoVersions), PackageName)
import Ecluse.Core.Registry.Adapter.Capability (
    AdapterMaintenance (maintenanceListing, maintenanceVersionDelete),
 )
import Ecluse.Core.Registry.Maintenance (
    CompletionNotion (CompletesOnCall),
    ConsentVerdict (ConsentGranted, ConsentWithheld),
    DeleteCeiling (AtMost),
    RefillPosture (RefillPermitted),
    RetryAdvice (RetryFutile, RetryWorthwhile),
    StoreClass (StoreDestroyable, StorePreserved),
    StoreFacts (..),
    StoreFault (faultRetry, faultTransport),
    StoreMaintenance (..),
    StoreManifestRead,
    StoredVersion (storedPresence, storedVersion),
    VersionOutcome (VersionRefused, VersionRemoved, VersionUnreached),
    VersionPresence (VersionServed),
    collectPages,
    noNameAlphabet,
    refusalCode,
    storeFaultOfMetadata,
 )
import Ecluse.Core.Registry.Maintenance.Protocol (ProtocolStore (..), newProtocolMaintenance)
import Ecluse.Core.Registry.Metadata (Manifest (manifestInfo))
import Ecluse.Core.Registry.Npm.Maintenance (npmMaintenance)
import Ecluse.Core.Registry.Npm.Metadata (fetchNpmManifest)
import Ecluse.Core.Registry.Npm.Publish (npmPublishCodec)
import Ecluse.Core.Registry.Origin (OriginClient (OriginClient, ocBaseUrl, ocLimits, ocManager, ocToken))
import Ecluse.Core.Security (Limits (maxBodyBytes), defaultLimits)
import Ecluse.Core.Security.Egress.DevHttp (loopbackRegistryUrl)
import Ecluse.Core.Version (Version, mkVersion)
import Ecluse.Test.Maintenance (withBucket)
import Ecluse.Test.Package (unscopedNpm)
import Ecluse.Test.Port (passthroughTracingPort)
import Ecluse.Test.Stub (
    Captured (capBody, capHeaders, capMethod, capPath),
    Stub,
    allCaptured,
    headerValue,
    stubLocalhostUrl,
    withRoutedStub,
 )
import Ecluse.Test.Wai (freePort, localhost)

spec :: Spec
spec = do
    factsSpec
    enumerationSpec
    deletionSpec

factsSpec :: Spec
factsSpec = describe "what the backend supplies without a call" $ do
    it "reports the backend name it was built under, and the one-version delete ceiling" $
        withStore True answerNothing $ \handle _ -> do
            let facts = storeFacts handle
            factBackend facts `shouldBe` "verdaccio"
            factDeleteCeiling facts `shouldBe` AtMost 1
            factRefill facts `shouldBe` RefillPermitted
            factCompletion facts `shouldBe` CompletesOnCall

    it "partitions its name space into nothing, because one read answers the whole listing" $
        withStore True answerNothing $ \handle _ ->
            factNameAlphabet (storeFacts handle) `shouldBe` noNameAlphabet

    it "keeps no walk cursor, because the protocol writes nothing but a publish" $
        withStore True answerNothing $ \handle _ ->
            isNothing (storeCursor handle) `shouldBe` True

    it "offers no rehearsal, because the protocol spells no dry-run request" $
        withStore True answerNothing $ \handle _ ->
            isNothing (rehearseDelete handle) `shouldBe` True

    it "reads consent and classification off the operator's key, with no call" $
        withStore True answerNothing $ \handle _ -> do
            verifyConsent handle `shouldReturn` Right ConsentGranted
            classifyStore handle `shouldReturn` Right StoreDestroyable

    it "withholds consent, naming the key, when the store carries none" $
        withStore False answerNothing $ \handle _ -> do
            verifyConsent handle `shouldReturn` Right (ConsentWithheld consentKey)
            classifyStore handle `shouldReturn` Right (StorePreserved consentKey)

enumerationSpec :: Spec
enumerationSpec = describe "enumeration over the protocol's own reads" $ do
    it "reads the store's packages from the listing it answers 200 to" $
        withStore True answerStore $ \handle stub -> do
            listWholeStore handle `shouldReturn` Right [unscopedNpm "leftpad", unscopedNpm "rightpad"]
            calls stub `shouldReturn` [("GET", "/-/all")]

    it "answers a bucket with the names under it, filtering what the listing brought back" $
        withStore True answerStore $ \handle _ -> do
            listBucketOf handle "l" `shouldReturn` Right [unscopedNpm "leftpad"]
            listBucketOf handle "r" `shouldReturn` Right [unscopedNpm "rightpad"]

    it "faults with RetryFutile on a store that does not answer the listing" $
        withStore True answerNothing $ \handle _ ->
            (fmap faultRetry . leftToMaybe <$> listWholeStore handle)
                `shouldReturn` Just RetryFutile

    it "reads a package's versions through the presence probe, all served" $
        withStore True answerStore $ \handle _ -> do
            stored <- enumerateVersions handle leftpad
            fmap (map storedVersion) stored `shouldBe` Right [version "1.0.0", version "2.0.0"]
            fmap (map storedPresence) stored `shouldBe` Right [VersionServed, VersionServed]

    it "reads the store's own manifest for a package, projected through the ecosystem's codec" $
        withStore True answerStore $ \handle stub -> do
            outcome <- readStoreManifest handle leftpad
            fmap (Map.keys . infoVersions . manifestInfo) outcome `shouldBe` Right ["1.0.0", "2.0.0"]
            calls stub `shouldReturn` [("GET", "/leftpad")]

    it "carries the store's own write credential on the manifest read" $
        withStore True answerStore $ \handle stub -> do
            _ <- readStoreManifest handle leftpad
            sent <- allCaptured stub
            map (headerValue "Authorization") sent `shouldBe` [Just "Bearer write-token"]

    it "reads every answer it cannot project as one fault, because the read keeps no status" $ do
        -- The shared metadata read drops the status, so an absent package and a server-side
        -- failure both arrive as a document that did not project. Either way the version keeps.
        withStore True answerNothing $ \handle _ ->
            (fmap faultRetry . leftToMaybe <$> readStoreManifest handle leftpad)
                `shouldReturn` Just RetryFutile
        withStore True (answerAll status503 "{}") $ \handle _ ->
            (fmap faultRetry . leftToMaybe <$> readStoreManifest handle leftpad)
                `shouldReturn` Just RetryFutile

    it "advises another attempt when the store never answered the manifest read at all" $ do
        handle <- unreachableStore
        outcome <- readStoreManifest handle leftpad
        fmap (tfCause . faultTransport) (leftToMaybe outcome) `shouldBe` Just TransportUnreachable
        fmap faultRetry (leftToMaybe outcome) `shouldBe` Just RetryWorthwhile

    it "reads a package the store no longer holds as holding no versions" $
        withStore True answerNothing $ \handle _ ->
            enumerateVersions handle leftpad `shouldReturn` Right []

    it "faults when a listing answers 200 with a body that is no listing at all" $
        withStore True (answerAll status200 "[\"leftpad\"]") $ \handle _ ->
            faultDetail <$> listWholeStore handle
                `shouldReturn` Just "the store's package listing did not parse"

    it "faults with RetryFutile when the listing crosses the origin's response bound" $
        withBoundedStore tinyBodyBound answerStore $ \handle _ ->
            (fmap faultRetry . leftToMaybe <$> listWholeStore handle)
                `shouldReturn` Just RetryFutile

    it "reports an unreachable store as a transport fault, with the advice that cause carries" $ do
        handle <- unreachableStore
        outcome <- listWholeStore handle
        fmap (tfCause . faultTransport) (leftToMaybe outcome) `shouldBe` Just TransportUnreachable
        fmap faultRetry (leftToMaybe outcome) `shouldBe` Just RetryWorthwhile

    it "advises another attempt when a read fails server-side, unlike an absent listing" $
        withStore True (answerAll status503 "{}") $ \handle _ ->
            (fmap faultRetry . leftToMaybe <$> enumerateVersions handle leftpad)
                `shouldReturn` Just RetryWorthwhile

deletionSpec :: Spec
deletionSpec = describe "deletion over the protocol's own request sequence" $ do
    it "reads the document, edits it, then deletes the tarball, in that order" $
        withStore True answerStore $ \handle stub -> do
            deleteVersions handle leftpad [version "1.0.0"]
                `shouldReturn` [(version "1.0.0", VersionRemoved)]
            calls stub
                `shouldReturn` [ ("GET", "/leftpad")
                               , ("PUT", "/leftpad/-rev/3-abc")
                               , ("DELETE", "/leftpad/-/leftpad-1.0.0.tgz/-rev/3-abc")
                               ]

    it "carries the store's write credential on every call of the sequence" $
        withStore True answerStore $ \handle stub -> do
            _ <- deleteVersions handle leftpad [version "1.0.0"]
            sent <- allCaptured stub
            map (headerValue "Authorization") sent `shouldBe` replicate 3 (Just "Bearer write-token")

    it "sends a packument edit with the deleted version gone and the rest intact" $
        withStore True answerStore $ \handle stub -> do
            _ <- deleteVersions handle leftpad [version "1.0.0"]
            edited <- editedPackument stub
            keysUnder "versions" edited `shouldBe` ["2.0.0"]
            keysUnder "time" edited `shouldBe` ["2.0.0"]

    it "re-reads the document for every version, because the edit addresses its revision" $
        withStore True answerStore $ \handle stub -> do
            _ <- deleteVersions handle leftpad [version "1.0.0", version "2.0.0"]
            documentReads <- filter ((== "GET") . capMethod) <$> allCaptured stub
            length documentReads `shouldBe` 2

    it "refuses the version, and sends no tarball delete, when the store refuses the edit" $
        withStore True answerRefusingEdit $ \handle stub -> do
            outcomes <- deleteVersions handle leftpad [version "1.0.0"]
            map (refusedAs . snd) outcomes `shouldBe` [Just "HTTP 500"]
            calls stub `shouldReturn` [("GET", "/leftpad"), ("PUT", "/leftpad/-rev/3-abc")]

    it "refuses the version when the store holds no document for the package" $
        withStore True answerNothing $ \handle _ -> do
            outcomes <- deleteVersions handle leftpad [version "1.0.0"]
            map (refusedAs . snd) outcomes `shouldBe` [Just "NOT_FOUND"]

    it "carries the verb's own refusal out, sending neither write" $
        withStore True answerStore $ \handle stub -> do
            outcomes <- deleteVersions handle leftpad [version "9.9.9"]
            map (refusedAs . snd) outcomes `shouldBe` [Just "VERSION_ABSENT"]
            calls stub `shouldReturn` [("GET", "/leftpad")]

    it "leaves a version unreached, never removed, when a fault stops the sequence part-way" $
        -- The bound admits the document and the edit and refuses the answer to the tarball
        -- delete, which is the one fault a caller must not read as a completed removal.
        withBoundedStore midSequenceBound answerOversizedDelete $ \handle stub -> do
            outcomes <- deleteVersions handle leftpad [version "1.0.0"]
            map (unreachedRetry . snd) outcomes `shouldBe` [Just RetryFutile]
            map fst <$> calls stub `shouldReturn` ["GET", "PUT", "DELETE"]

-- Build the handle over a stub and run the assertion against both.
withStore ::
    Bool ->
    (Captured -> (Status, LBS.ByteString)) ->
    (StoreMaintenance -> Stub -> IO a) ->
    IO a
withStore permitted = withStoreUnder permitted defaultLimits

withStoreUnder ::
    Bool ->
    Limits ->
    (Captured -> (Status, LBS.ByteString)) ->
    (StoreMaintenance -> Stub -> IO a) ->
    IO a
withStoreUnder permitted limits answer action =
    withRoutedStub reply $ \stub -> do
        manager <- newManager defaultManagerSettings
        store <- protocolStore permitted (originAt manager limits (stubLocalhostUrl stub))
        action (newProtocolMaintenance store) stub
  where
    reply captured = let (status, body) = answer captured in (status, [], body)

originAt :: Manager -> Limits -> Text -> OriginClient
originAt manager limits baseUrl =
    OriginClient
        { ocBaseUrl = loopbackRegistryUrl baseUrl
        , ocManager = manager
        , ocToken = Just (bareCredential (mkSecret "write-token"))
        , ocLimits = limits
        }

{- npm fills the maintenance slice, so an empty verb here is a wiring fault the case reports
rather than works around. -}
protocolStore :: Bool -> OriginClient -> IO ProtocolStore
protocolStore permitted origin = do
    listing <- required "listing" (maintenanceListing npmMaintenance)
    delete <- required "version delete" (maintenanceVersionDelete npmMaintenance)
    pure
        ProtocolStore
            { psOrigin = origin
            , psReadManifest = readManifestOver origin
            , psListing = listing
            , psDelete = delete
            , psCodec = npmPublishCodec
            , psBackendName = "verdaccio"
            , psPermitDeletion = permitted
            , psConsentDescriptor = consentKey
            }
  where
    required verb = maybe (fail ("npm fills no " <> verb <> " verb")) pure

{- The read the composition root assembles for a protocol store: the ecosystem's own manifest
fetch over the store's endpoint, with its failures folded into the maintenance vocabulary. -}
readManifestOver :: OriginClient -> StoreManifestRead
readManifestOver origin name =
    first storeFaultOfMetadata <$> fetchNpmManifest passthroughTracingPort origin name

{- | 'withStore' under a caller-chosen response bound, for the fail-closed read that refuses a
body larger than the origin admits.
-}
withBoundedStore ::
    Limits ->
    (Captured -> (Status, LBS.ByteString)) ->
    (StoreMaintenance -> Stub -> IO a) ->
    IO a
withBoundedStore = withStoreUnder True

-- | A handle whose origin addresses a port nothing is listening on.
unreachableStore :: IO StoreMaintenance
unreachableStore = do
    port <- freePort
    manager <- newManager defaultManagerSettings
    newProtocolMaintenance <$> protocolStore True (originAt manager defaultLimits (localhost port))

{- The listing body is larger than this, so the bounded read refuses it rather than truncating
what the sweep would then act on. -}
tinyBodyBound :: Limits
tinyBodyBound = defaultLimits{maxBodyBytes = 8}

-- Wide enough for the packument and the edit's answer, narrower than the tarball delete's.
midSequenceBound :: Limits
midSequenceBound = defaultLimits{maxBodyBytes = 4096}

consentKey :: Text
consentKey = "set mounts.npm.mirrorTarget.verdaccio.permitDeletion to true"

leftpad :: PackageName
leftpad = unscopedNpm "leftpad"

-- The one bucket a leaf with no alphabet offers, which covers everything the store holds.
listWholeStore :: StoreMaintenance -> IO (Either StoreFault [PackageName])
listWholeStore handle = listBucketOf handle ""

{- One bucket by the spelling a store filter would carry, so the filter the leaf applies is
drivable even though it advertises no alphabet of its own. -}
listBucketOf :: StoreMaintenance -> Text -> IO (Either StoreFault [PackageName])
listBucketOf handle raw = withBucket raw (collectPages . listPackagesIn handle)

version :: Text -> Version
version = mkVersion Npm

-- A store answering the listing, the packument, and both writes of the delete sequence.
answerStore :: Captured -> (Status, LBS.ByteString)
answerStore captured = case (capMethod captured, capPath captured) of
    ("GET", "/-/all") -> (status200, encode listingDocument)
    ("GET", _) -> (status200, encode (packumentDocumentOn (capAuthority captured)))
    _ -> (status201, "{\"ok\":true}")

{- The store answers the tarball delete with a body past the bound. The delete reached it, so
the version's fate is unknown, which is what the sequence's fault arm must report.  -}
answerOversizedDelete :: Captured -> (Status, LBS.ByteString)
answerOversizedDelete captured = case capMethod captured of
    "GET" -> (status200, encode (packumentDocumentOn (capAuthority captured)))
    "DELETE" -> (status201, LBS.replicate 20000 0x61)
    _ -> (status201, "{\"ok\":true}")

-- The store refuses the packument edit, so the tarball delete must never be sent.
answerRefusingEdit :: Captured -> (Status, LBS.ByteString)
answerRefusingEdit captured = case capMethod captured of
    "GET" -> (status200, encode (packumentDocumentOn (capAuthority captured)))
    _ -> (status500, "{\"error\":\"refused\"}")

-- A store holding nothing: the listing, the packument, and every read answer 404.
answerNothing :: Captured -> (Status, LBS.ByteString)
answerNothing = answerAll status404 "{}"

answerAll :: Status -> LBS.ByteString -> Captured -> (Status, LBS.ByteString)
answerAll status body = const (status, body)

listingDocument :: Value
listingDocument =
    object ["_updated" .= (1 :: Int), "leftpad" .= object [], "rightpad" .= object []]

packumentDocumentOn :: Text -> Value
packumentDocumentOn authority =
    object
        [ "_id" .= ("leftpad" :: Text)
        , "_rev" .= ("3-abc" :: Text)
        , "name" .= ("leftpad" :: Text)
        , "dist-tags" .= object ["latest" .= ("2.0.0" :: Text)]
        , "versions" .= object [Key.fromText raw .= manifest raw | raw <- held]
        , "time" .= object [Key.fromText raw .= ("2020-01-01T00:00:00.000Z" :: Text) | raw <- held]
        ]
  where
    held = ["1.0.0", "2.0.0"] :: [Text]
    manifest raw =
        object
            [ "name" .= ("leftpad" :: Text)
            , "version" .= raw
            , -- The store serves its own tarball bytes, so the location names the authority
              -- that served the document. A foreign one would drop the version at projection.
              "dist" .= object ["tarball" .= (authority <> "/leftpad/-/leftpad-" <> raw <> ".tgz")]
            ]

{- The authority a captured request reached the stub on, so a fixture can name locations the
store itself serves rather than a foreign host the projection would drop. -}
capAuthority :: Captured -> Text
capAuthority captured = "http://" <> maybe "127.0.0.1" (decodeUtf8 . snd) (find ((== "host") . fst) (capHeaders captured))

-- The document the store's first packument edit carried.
editedPackument :: Stub -> IO Object
editedPackument stub = do
    sent <- filter ((== "PUT") . capMethod) <$> allCaptured stub
    case sent of
        edit : _ -> maybe (fail "the packument edit did not decode") pure (decodeStrict (capBody edit))
        [] -> fail "the store was sent no packument edit"

calls :: Stub -> IO [(ByteString, ByteString)]
calls stub = map (\captured -> (capMethod captured, capPath captured)) <$> allCaptured stub

keysUnder :: Key.Key -> Object -> [Text]
keysUnder key document = case KeyMap.lookup key document of
    Just value -> maybe [] (map Key.toText . KeyMap.keys) (asObject value)
    Nothing -> []
  where
    asObject = \case
        Object inner -> Just inner
        _ -> Nothing

-- The fault's diagnostic text, cut at the store's own message so the assertion reads the subject.
faultDetail :: Either StoreFault a -> Maybe Text
faultDetail outcome =
    T.takeWhile (/= ':') . tfDetail . faultTransport <$> leftToMaybe outcome

refusedAs :: VersionOutcome -> Maybe Text
refusedAs = \case
    VersionRefused refusal -> Just (refusalCode refusal)
    _ -> Nothing

unreachedRetry :: VersionOutcome -> Maybe RetryAdvice
unreachedRetry = \case
    VersionUnreached fault -> Just (faultRetry fault)
    _ -> Nothing
