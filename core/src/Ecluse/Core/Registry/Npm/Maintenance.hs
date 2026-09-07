-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | npm listing and unpublish requests for the protocol maintenance backend.
The final version requires whole-package deletion, because an empty Verdaccio
packument truncates subsequent store listings.
-}
module Ecluse.Core.Registry.Npm.Maintenance (
    npmMaintenance,

    -- * The listing
    listingRequestFor,
    parsePackageListing,

    -- * The unpublish
    packumentRequestFor,
    versionDeleteRequestsFor,
) where

import Data.Aeson (Object, Value (Object, String), decodeStrict, encode)
import Data.Aeson.Key qualified as Key
import Data.Aeson.KeyMap qualified as KeyMap
import Network.HTTP.Client (Request (method, requestBody, requestHeaders), RequestBody (RequestBodyBS))
import Network.HTTP.Types.Header (hAccept, hContentType)

import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.Package (PackageName, unscopedName)
import Ecluse.Core.Registry (
    ParseError (ParseError),
    RegistryResponse (responseBody),
    UrlFormationError,
    renderUrlFormationError,
 )
import Ecluse.Core.Registry.Adapter.Capability (
    AdapterMaintenance (..),
    StoreListing (..),
    VersionDelete (..),
 )
import Ecluse.Core.Registry.Maintenance (StoreRefusal, mkNameAlphabet, storeRefusal)
import Ecluse.Core.Registry.Npm.Project (npmNameLeadChars, projectName)
import Ecluse.Core.Registry.Npm.Request (
    MetadataForm (Full),
    artifactFileUrl,
    metadataRequest,
    packageUrl,
    parseRequestEither,
    withToken,
 )
import Ecluse.Core.Registry.Origin (OriginClient (ocBaseUrl, ocToken))
import Ecluse.Core.Registry.Request (joinPath, noValidators)
import Ecluse.Core.Security.Egress (registryUrlText)
import Ecluse.Core.Server.Path (encodeComponent, isSafeComponent)
import Ecluse.Core.Text (nonBlank, urlFilename)
import Ecluse.Core.Version (Version, compareVersions, mkVersion, renderVersion)

-- | npm's maintenance slice. It fills both verbs, so an npm mount is sweepable.
npmMaintenance :: AdapterMaintenance
npmMaintenance =
    AdapterMaintenance
        { maintenanceListing =
            Just
                StoreListing
                    { listingRequest = listingRequestFor
                    , listingParse = parsePackageListing
                    }
        , maintenanceVersionDelete =
            Just
                VersionDelete
                    { deleteDocumentRequest = packumentRequestFor
                    , deleteRequests = versionDeleteRequestsFor
                    }
        , maintenanceAlphabet = mkNameAlphabet npmNameLeadChars
        }

-- | Read the store listing. The caller classifies any response other than @200@.
listingRequestFor :: OriginClient -> Either UrlFormationError Request
listingRequestFor origin = do
    url <- joinPath (originBase origin) "-/all"
    base <- parseRequestEither url
    pure . withToken (ocToken origin) $
        base{requestHeaders = (hAccept, "application/json") : requestHeaders base}

-- | Ignore the @_updated@ bookkeeping key and keys that are not npm package names.
parsePackageListing :: ByteString -> Either ParseError [PackageName]
parsePackageListing body = case decodeStrict body :: Maybe Object of
    Nothing -> Left (ParseError "the store's package listing is not a JSON object")
    Just listing ->
        Right
            [ name
            | key <- KeyMap.keys listing
            , let raw = Key.toText key
            , raw /= "_updated"
            , Right name <- [projectName raw]
            ]

-- | Read the full packument, because the install view omits @_rev@ and @time@.
packumentRequestFor :: OriginClient -> PackageName -> Either UrlFormationError Request
packumentRequestFor origin =
    metadataRequest (originBase origin) (ocToken origin) Full noValidators

-- | Refuse absent versions and unreadable revisions. Delete the whole package only for its last version.
versionDeleteRequestsFor ::
    OriginClient ->
    PackageName ->
    Version ->
    RegistryResponse ->
    Either StoreRefusal (NonEmpty Request)
versionDeleteRequestsFor origin name version response = do
    packument <- decodePackument (responseBody response)
    revision <- revisionOf packument
    versions <- versionsOf packument
    manifest <-
        maybeToRight
            (storeRefusal "VERSION_ABSENT" "the store's packument holds no such version")
            (KeyMap.lookup (Key.fromText raw) versions)
    if KeyMap.size versions == 1
        then do
            request <- unformable (packageUrl (originBase origin) name >>= deleteAtRevision origin revision)
            pure (request :| [])
        else do
            let filename = tarballFilename name version manifest
                edited = removeVersion raw versions packument
            editRequest <- unformable (packumentPutRequest origin name revision edited)
            tarballRequest <- unformable (artifactFileUrl (originBase origin) name filename >>= deleteAtRevision origin revision)
            pure (editRequest :| [tarballRequest])
  where
    raw = renderVersion version

originBase :: OriginClient -> Text
originBase = registryUrlText . ocBaseUrl

-- A URL that will not form is this one version's refusal, with the URL reduced to its authority.
unformable :: Either UrlFormationError a -> Either StoreRefusal a
unformable = first (storeRefusal "UNFORMABLE_URL" . renderUrlFormationError)

decodePackument :: ByteString -> Either StoreRefusal Object
decodePackument body =
    maybeToRight
        (storeRefusal "UNREADABLE_DOCUMENT" "the store's packument is not a JSON object")
        (decodeStrict body)

-- Verdaccio does not enforce revision matching, so concurrent publishes can be lost.
revisionOf :: Object -> Either StoreRefusal Text
revisionOf packument = case KeyMap.lookup "_rev" packument of
    Just (String revision) | isSafeComponent revision -> Right revision
    _ ->
        Left (storeRefusal "NO_REVISION" "the store's packument carries no _rev an edit can address")

versionsOf :: Object -> Either StoreRefusal Object
versionsOf packument = case KeyMap.lookup "versions" packument of
    Just (Object versions) -> Right versions
    _ ->
        Left (storeRefusal "UNREADABLE_DOCUMENT" "the store's packument carries no versions object")

-- A spec-compliant registry answers 415 unless the edited body is declared application/json.
packumentPutRequest :: OriginClient -> PackageName -> Text -> Object -> Either UrlFormationError Request
packumentPutRequest origin name revision packument = do
    url <- atRevision revision <$> packageUrl (originBase origin) name
    base <- parseRequestEither url
    pure
        . withToken (ocToken origin)
        $ base
            { method = "PUT"
            , requestBody = RequestBodyBS (toStrict (encode packument))
            , requestHeaders =
                (hContentType, "application/json")
                    : (hAccept, "application/json")
                    : requestHeaders base
            }

deleteAtRevision :: OriginClient -> Text -> Text -> Either UrlFormationError Request
deleteAtRevision origin revision url = do
    base <- parseRequestEither (atRevision revision url)
    pure
        . withToken (ocToken origin)
        $ base
            { method = "DELETE"
            , requestHeaders = (hAccept, "application/json") : requestHeaders base
            }

atRevision :: Text -> Text -> Text
atRevision revision url = url <> "/-rev/" <> encodeComponent revision

{- A @latest@ that pointed at the removed version moves to the greatest survivor, because a
packument without one leaves an unqualified install with no version to resolve. -}
removeVersion :: Text -> Object -> Object -> Object
removeVersion raw versions packument =
    KeyMap.insert "versions" (Object remaining) (adjustObject "dist-tags" retag prunedTime)
  where
    key = Key.fromText raw
    remaining = KeyMap.delete key versions
    prunedTime = adjustObject "time" (KeyMap.delete key) packument
    retag tags = maybe kept (\latest -> KeyMap.insert "latest" (String latest) kept) restoredLatest
      where
        kept = KeyMap.filter (/= String raw) tags
        restoredLatest = do
            guard (KeyMap.lookup "latest" tags == Just (String raw))
            greatestVersion (map Key.toText (KeyMap.keys remaining))

adjustObject :: Key.Key -> (Object -> Object) -> Object -> Object
adjustObject key edit document = case KeyMap.lookup key document of
    Just (Object inner) -> KeyMap.insert key (Object (edit inner)) document
    _ -> document

-- Non-semver pairs use text ordering to keep the choice deterministic.
greatestVersion :: [Text] -> Maybe Text
greatestVersion = foldl' keepGreater Nothing
  where
    keepGreater held candidate = Just (maybe candidate (greater candidate) held)
    greater a b = if ordering a b == GT then a else b
    ordering a b = fromMaybe (compare a b) (compareVersions (mkVersion Npm a) (mkVersion Npm b))

tarballFilename :: PackageName -> Version -> Value -> Text
tarballFilename name version manifest =
    fromMaybe conventional (mfilter isSafeComponent (nonBlank =<< distTarballSegment manifest))
  where
    conventional = unscopedName name <> "-" <> renderVersion version <> ".tgz"

distTarballSegment :: Value -> Maybe Text
distTarballSegment manifest = urlFilename =<< tarballUrl manifest

tarballUrl :: Value -> Maybe Text
tarballUrl = \case
    Object manifest -> case KeyMap.lookup "dist" manifest of
        Just (Object dist) -> case KeyMap.lookup "tarball" dist of
            Just (String url) -> Just url
            _ -> Nothing
        _ -> Nothing
    _ -> Nothing
