-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

-- | Request formation and refusal contracts for npm store maintenance.
module Ecluse.Core.Registry.Npm.MaintenanceSpec (spec) where

import Data.Aeson (Object, Value (Object, String), decodeStrict, encode, object, (.=))
import Data.Aeson.Key qualified as Key
import Data.Aeson.KeyMap qualified as KeyMap
import Data.Aeson.Types (Pair)
import Data.List (lookup)
import Network.HTTP.Client (Manager, Request, RequestBody (RequestBodyBS), defaultManagerSettings, newManager)
import Network.HTTP.Client qualified as Client
import Test.Hspec

import Ecluse.Core.Credential (bareCredential, mkSecret)
import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.Package (PackageName, mkPackageName, mkScope)
import Ecluse.Core.Registry (RegistryResponse (RegistryResponse))
import Ecluse.Core.Registry.Maintenance (refusalCode)
import Ecluse.Core.Registry.Npm.Maintenance (
    listingRequestFor,
    packumentRequestFor,
    parsePackageListing,
    versionDeleteRequestsFor,
 )
import Ecluse.Core.Registry.Origin (OriginClient (OriginClient, ocBaseUrl, ocLimits, ocManager, ocToken))
import Ecluse.Core.Security (defaultLimits)
import Ecluse.Core.Security.Egress.DevHttp (loopbackRegistryUrl)
import Ecluse.Core.Version (Version, mkVersion)
import Ecluse.Test.Package (unscopedNpm)

-- | Verify that deletion addresses only versions present in the fetched document.
spec :: Spec
spec = do
    listingSpec
    packumentReadSpec
    deleteSequenceSpec

listingSpec :: Spec
listingSpec = describe "the package listing verb" $ do
    it "forms the listing read under the origin's base URL, carrying its credential" $ do
        request <- formed (listingRequestFor <$> storeOrigin)
        Client.method request `shouldBe` "GET"
        Client.path request `shouldBe` "/-/all"
        headerOf "Accept" request `shouldBe` Just "application/json"
        headerOf "Authorization" request `shouldBe` Just "Bearer write-token"

    it "reads every package key the listing holds" $
        parsePackageListing (listingBody ["leftpad", "rightpad"])
            `shouldBe` Right [leftpad, unscopedNpm "rightpad"]

    it "drops the listing's own bookkeeping key" $
        parsePackageListing (listingBody ["_updated", "leftpad"]) `shouldBe` Right [leftpad]

    it "drops a key this ecosystem cannot read as a name, keeping the rest" $
        parsePackageListing (listingBody ["@foo", "leftpad"]) `shouldBe` Right [leftpad]

    it "refuses a listing body that is not a JSON object" $
        parsePackageListing "[\"leftpad\"]" `shouldSatisfy` isLeft

packumentReadSpec :: Spec
packumentReadSpec = describe "the delete verb's document read" $ do
    it "asks for the full packument, which is the form carrying _rev" $ do
        request <- formed (flip packumentRequestFor leftpad <$> storeOrigin)
        Client.path request `shouldBe` "/leftpad"
        headerOf "Accept" request `shouldBe` Just "application/json"

    it "encodes a scoped name as one path segment" $ do
        request <- formed (flip packumentRequestFor acmeTool <$> storeOrigin)
        Client.path request `shouldBe` "/@acme%2Ftool"

deleteSequenceSpec :: Spec
deleteSequenceSpec = describe "the version delete verb" $ do
    it "forms the packument edit and then the tarball delete, both at the read revision" $ do
        (edit, tarball) <- deletePair twoVersions leftpad (version "1.0.0")
        Client.method edit `shouldBe` "PUT"
        Client.path edit `shouldBe` "/leftpad/-rev/3-abc"
        headerOf "Content-Type" edit `shouldBe` Just "application/json"
        Client.method tarball `shouldBe` "DELETE"
        Client.path tarball `shouldBe` "/leftpad/-/leftpad-1.0.0.tgz/-rev/3-abc"

    it "carries the origin's credential on both requests" $ do
        (edit, tarball) <- deletePair twoVersions leftpad (version "1.0.0")
        headerOf "Authorization" edit `shouldBe` Just "Bearer write-token"
        headerOf "Authorization" tarball `shouldBe` Just "Bearer write-token"

    it "removes the version from versions, time, and dist-tags" $ do
        edited <- editedPackument twoVersions leftpad (version "1.0.0")
        keysUnder "versions" edited `shouldBe` ["2.0.0"]
        keysUnder "time" edited `shouldBe` ["2.0.0"]
        KeyMap.lookup "old" (objectUnder "dist-tags" edited) `shouldBe` Nothing

    it "repoints latest at the greatest surviving version" $ do
        edited <- editedPackument latestOnDeleted leftpad (version "2.0.0")
        KeyMap.lookup "latest" (objectUnder "dist-tags" edited) `shouldBe` Just (String "10.0.0")

    forM_ [(leftpad, "/leftpad/-rev/3-abc"), (acmeTool, "/@acme%2Ftool/-rev/3-abc")] $ \(name, path) ->
        it ("deletes the whole package for its only version at " <> decodeUtf8 path) $ do
            origin <- storeOrigin
            requests <-
                either (fail . show) pure $
                    versionDeleteRequestsFor origin name (version "1.0.0") (RegistryResponse 200 (encoded onlyVersion))
            case requests of
                request :| [] -> do
                    Client.method request `shouldBe` "DELETE"
                    Client.path request `shouldBe` path
                    headerOf "Authorization" request `shouldBe` Just "Bearer write-token"
                    headerOf "Accept" request `shouldBe` Just "application/json"
                other -> expectationFailure ("expected one request, got " <> show (length other))

    it "keeps a malformed survivor instead of deleting the whole package" $ do
        let document = packument "leftpad" [] [("1.0.0", withTarball "leftpad-1.0.0.tgz"), ("broken", String "invalid")]
        edited <- editedPackument document leftpad (version "1.0.0")
        KeyMap.lookup "broken" (objectUnder "versions" edited) `shouldBe` Just (String "invalid")

    it "refuses an absent version even when the package holds only one other version" $
        refusalOf (encoded onlyVersion) (version "9.9.9") `shouldReturn` Just "VERSION_ABSENT"

    it "leaves every other top-level key the store wrote" $ do
        edited <- editedPackument twoVersions leftpad (version "1.0.0")
        KeyMap.lookup "_id" edited `shouldBe` Just (String "leftpad")
        KeyMap.lookup "_rev" edited `shouldBe` Just (String "3-abc")

    it "addresses the tarball the store itself serves the version from" $ do
        (_, tarball) <- deletePair renamedTarball leftpad (version "1.0.0")
        Client.path tarball `shouldBe` "/leftpad/-/leftpad-1.0.0-rc.tgz/-rev/3-abc"

    it "falls back to npm's conventional unscoped filename when the manifest names none" $ do
        (_, tarball) <- deletePair (noDist "@acme/tool") acmeTool (version "1.0.0")
        Client.path tarball `shouldBe` "/@acme%2Ftool/-/tool-1.0.0.tgz/-rev/3-abc"

    it "refuses a document that is not a JSON object" $
        refusalOf "not a packument" (version "1.0.0") `shouldReturn` Just "UNREADABLE_DOCUMENT"

    it "refuses a packument carrying no revision to address the edit at" $
        refusalOf (encoded (without "_rev" twoVersions)) (version "1.0.0")
            `shouldReturn` Just "NO_REVISION"

    it "refuses a packument carrying no versions object" $
        refusalOf (encoded (without "versions" twoVersions)) (version "1.0.0")
            `shouldReturn` Just "UNREADABLE_DOCUMENT"

    it "refuses a version the packument does not hold" $
        refusalOf (encoded twoVersions) (version "9.9.9") `shouldReturn` Just "VERSION_ABSENT"

    it "ignores a dist.tarball segment that is a traversal, addressing the conventional name" $ do
        -- The store chose this string. A bare @..@ would address the package itself once a
        -- normalising hop in front of the store collapsed the path.
        (_, tarball) <- deletePair (tarballAt "http://store.test/leftpad/-/..") leftpad (version "1.0.0")
        Client.path tarball `shouldBe` "/leftpad/-/leftpad-1.0.0.tgz/-rev/3-abc"

    it "ignores a dist.tarball segment carrying a control character" $ do
        (_, tarball) <- deletePair (tarballAt "http://store.test/leftpad/-/a\rb.tgz") leftpad (version "1.0.0")
        Client.path tarball `shouldBe` "/leftpad/-/leftpad-1.0.0.tgz/-rev/3-abc"

    it "neutralises a percent-encoded separator on the way out rather than at the gate" $ do
        -- The gate is structural, so a live escape survives it. Encode-on-build is what makes
        -- the segment inert, and this pins that the two together leave nothing addressable.
        (_, tarball) <- deletePair (tarballAt "http://store.test/leftpad/-/..%2Fx") leftpad (version "1.0.0")
        Client.path tarball `shouldBe` "/leftpad/-/..%252Fx/-rev/3-abc"

    it "reads the filename off a tarball URL carrying a query or fragment" $ do
        (_, tarball) <- deletePair (tarballAt "http://store.test/leftpad/-/leftpad-1.0.0.tgz?sig=abc") leftpad (version "1.0.0")
        Client.path tarball `shouldBe` "/leftpad/-/leftpad-1.0.0.tgz/-rev/3-abc"

    it "refuses a revision that is no safe path component" $
        refusalOf (encoded (withRevision ".." twoVersions)) (version "1.0.0")
            `shouldReturn` Just "NO_REVISION"

storeOrigin :: IO OriginClient
storeOrigin = originOver <$> newManager defaultManagerSettings

originOver :: Manager -> OriginClient
originOver manager =
    OriginClient
        { ocBaseUrl = loopbackRegistryUrl "http://store.test"
        , ocManager = manager
        , ocToken = Just (bareCredential (mkSecret "write-token"))
        , ocLimits = defaultLimits
        }

formed :: (Show e) => IO (Either e Request) -> IO Request
formed action = action >>= either (fail . show) pure

headerOf :: ByteString -> Request -> Maybe ByteString
headerOf header = lookup (fromString (decodeUtf8 header)) . Client.requestHeaders

leftpad :: PackageName
leftpad = unscopedNpm "leftpad"

acmeTool :: PackageName
acmeTool = mkPackageName Npm (Just (mkScope "acme")) "tool"

version :: Text -> Version
version = mkVersion Npm

deletePair :: Value -> PackageName -> Version -> IO (Request, Request)
deletePair document name subject = do
    origin <- storeOrigin
    case versionDeleteRequestsFor origin name subject (RegistryResponse 200 (encoded document)) of
        Left refusal -> fail ("the delete verb refused: " <> toString (refusalCode refusal))
        Right (edit :| [tarball]) -> pure (edit, tarball)
        Right other -> fail ("expected two requests, got " <> show (length other))

editedPackument :: Value -> PackageName -> Version -> IO Object
editedPackument document name subject = do
    (edit, _) <- deletePair document name subject
    case Client.requestBody edit of
        RequestBodyBS body -> maybe (fail "the edited packument did not decode") pure (decodeStrict body)
        _ -> fail "the packument edit carries no in-memory body"

refusalOf :: ByteString -> Version -> IO (Maybe Text)
refusalOf body subject = do
    origin <- storeOrigin
    pure (refusalCode <$> leftToMaybe (versionDeleteRequestsFor origin leftpad subject (RegistryResponse 200 body)))

listingBody :: [Text] -> ByteString
listingBody names = encoded (object [Key.fromText raw .= object [] | raw <- names])

encoded :: Value -> ByteString
encoded = toStrict . encode

objectUnder :: Key.Key -> Object -> Object
objectUnder key document = case KeyMap.lookup key document of
    Just (Object inner) -> inner
    _ -> KeyMap.empty

keysUnder :: Key.Key -> Object -> [Text]
keysUnder key = map Key.toText . KeyMap.keys . objectUnder key

without :: Key.Key -> Value -> Value
without key = \case
    Object document -> Object (KeyMap.delete key document)
    other -> other

withRevision :: Text -> Value -> Value
withRevision revision = \case
    Object document -> Object (KeyMap.insert "_rev" (String revision) document)
    other -> other

tarballAt :: Text -> Value
tarballAt url =
    packument
        "leftpad"
        ["latest" .= ("1.0.0" :: Text)]
        [("1.0.0", object ["dist" .= object ["tarball" .= url]]), ("2.0.0", withTarball "leftpad-2.0.0.tgz")]

-- Two versions, the deleted one also carrying an @old@ dist-tag beside @latest@.
twoVersions :: Value
twoVersions =
    packument
        "leftpad"
        ["latest" .= ("2.0.0" :: Text), "old" .= ("1.0.0" :: Text)]
        [("1.0.0", withTarball "leftpad-1.0.0.tgz"), ("2.0.0", withTarball "leftpad-2.0.0.tgz")]

-- The deleted version is @latest@, and the survivors order by semver rather than by text.
latestOnDeleted :: Value
latestOnDeleted =
    packument
        "leftpad"
        ["latest" .= ("2.0.0" :: Text)]
        [ ("1.0.0", withTarball "leftpad-1.0.0.tgz")
        , ("2.0.0", withTarball "leftpad-2.0.0.tgz")
        , ("10.0.0", withTarball "leftpad-10.0.0.tgz")
        ]

onlyVersion :: Value
onlyVersion =
    packument "leftpad" ["latest" .= ("1.0.0" :: Text)] [("1.0.0", withTarball "leftpad-1.0.0.tgz")]

-- The store named the file its own way, so the conventional name addresses the wrong tarball.
renamedTarball :: Value
renamedTarball =
    tarballAt "http://store.test/leftpad/-/leftpad-1.0.0-rc.tgz"

noDist :: Text -> Value
noDist raw =
    packument raw ["latest" .= ("1.0.0" :: Text)] [("1.0.0", object []), ("2.0.0", object [])]

packument :: Text -> [Pair] -> [(Text, Value)] -> Value
packument raw tags versions =
    object
        [ "_id" .= raw
        , "_rev" .= ("3-abc" :: Text)
        , "name" .= raw
        , "dist-tags" .= object tags
        , "versions" .= object [Key.fromText key .= value | (key, value) <- versions]
        , "time" .= object [Key.fromText key .= ("2020-01-01T00:00:00.000Z" :: Text) | (key, _) <- versions]
        ]

withTarball :: Text -> Value
withTarball filename =
    object ["dist" .= object ["tarball" .= ("http://store.test/leftpad/-/" <> filename)]]
