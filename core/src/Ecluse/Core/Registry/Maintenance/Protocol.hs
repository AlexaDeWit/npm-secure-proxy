-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The store maintenance leaf for a store whose only control plane is the ecosystem protocol
it already speaks. It drives the adapter's own verbs over one origin, so it serves every
ecosystem that fills the maintenance slice and names none of them. Reads go through the bounded
exchange rather than a metadata client, because the delete edit needs the store's raw document,
revision marker included, and the serve path's version-count bound is no bound on a store
listing. Consent and classification read the operator's own key, because no protocol read can
tell whether such a store refills itself from an uplink.
-}
module Ecluse.Core.Registry.Maintenance.Protocol (
    ProtocolStore (..),
    newProtocolMaintenance,
) where

import Data.Conduit (ConduitT, yield)
import Network.HTTP.Client (Request)

import Ecluse.Core.Credential (ClientCredential (credSecret), Secret)
import Ecluse.Core.Fault (
    TransportCause (TransportProtocol),
    transportFault,
 )
import Ecluse.Core.Package (PackageName)
import Ecluse.Core.Registry (
    ParseError (parseErrorMessage),
    RegistryResponse (RegistryResponse),
    UrlFormationError,
 )
import Ecluse.Core.Registry.Adapter.Capability (
    StoreListing (listingParse, listingRequest),
    VersionDelete (deleteDocumentRequest, deleteRequests),
 )
import Ecluse.Core.Registry.Exchange (boundedExchange, formThen)
import Ecluse.Core.Registry.Maintenance (
    CompletionNotion (CompletesOnCall),
    ConsentVerdict (ConsentGranted, ConsentWithheld),
    DeleteCeiling (AtMost),
    NamePrefix,
    RefillPosture (RefillPermitted),
    RetryAdvice (RetryFutile, RetryWorthwhile),
    StoreClass (StoreDestroyable, StorePreserved),
    StoreFacts (..),
    StoreFault (..),
    StoreMaintenance (..),
    StoreManifestRead,
    StoreRefusal,
    StoredVersion (StoredVersion, storedPresence, storedVersion),
    VersionOutcome (VersionRefused, VersionRemoved),
    VersionPresence (VersionServed),
    chunksOfCeiling,
    deleteAll,
    inBucket,
    noNameAlphabet,
    protocolFault,
    storeFaultOfFetch,
    storeRefusal,
    unformableFault,
 )
import Ecluse.Core.Registry.Origin (OriginClient (ocBaseUrl, ocLimits, ocManager, ocToken))
import Ecluse.Core.Registry.Publish (PublishCodec (pcParseVersionList, pcProbeRequest))
import Ecluse.Core.Security.Egress (registryUrlText)
import Ecluse.Core.Version (Version)

-- | One protocol-only store: where it is, what its protocol does to it, and the consent it carries.
data ProtocolStore = ProtocolStore
    { psOrigin :: OriginClient
    -- ^ The store's coordinates, its write credential, and the bound every read is held to.
    , psListing :: StoreListing
    -- ^ The ecosystem's package listing verb.
    , psDelete :: VersionDelete
    -- ^ The ecosystem's version-delete verb.
    , psCodec :: PublishCodec
    -- ^ The ecosystem's publish codec, whose presence probe already reads a store's version list for the mirror worker.
    , psReadManifest :: StoreManifestRead
    -- ^ One package's metadata as this store serves it, assembled at the composition root.
    , psBackendName :: Text
    -- ^ The store backend's name, which the boot line records the Dredger's blast radius as.
    , psPermitDeletion :: Bool
    -- ^ Whether the operator marked this store for deletion.
    , psConsentDescriptor :: Text
    -- ^ How an operator marks it, logged verbatim when consent is withheld.
    }

-- | Build the maintenance handle for one protocol-only store. Every version deletes on its own call, because the delete edit addresses a document revision the previous delete changed.
newProtocolMaintenance :: ProtocolStore -> StoreMaintenance
newProtocolMaintenance store =
    StoreMaintenance
        { storeFacts = protocolFacts (psBackendName store)
        , listPackagesIn = listBucket store
        , enumerateVersions = listVersions store
        , readStoreManifest = psReadManifest store
        , deleteVersions = deleteStoredVersions store
        , -- The protocol spells no request that reports what a delete would do without doing it.
          rehearseDelete = Nothing
        , verifyConsent = pure (Right (consentVerdict store))
        , classifyStore = pure (Right (storeClass store))
        , -- The protocol writes nothing but a publish, so a walk over this store keeps no cursor.
          storeCursor = Nothing
        }

{- The store re-admits a version published again after a delete, and has applied it by the time it
answers. It reports no alphabet: the listing below reads one document whole, bucket or no bucket. -}
protocolFacts :: Text -> StoreFacts
protocolFacts backend =
    StoreFacts
        { factBackend = backend
        , factDeleteCeiling = deleteCeiling
        , factRefill = RefillPermitted
        , factCompletion = CompletesOnCall
        , factNameAlphabet = noNameAlphabet
        }

{- The delete edit addresses the document revision it was formed from, and applying one changes
that revision, so a batch of two would send the second against a revision that no longer exists. -}
deleteCeiling :: DeleteCeiling
deleteCeiling = AtMost 1

consentVerdict :: ProtocolStore -> ConsentVerdict
consentVerdict store
    | psPermitDeletion store = ConsentGranted
    | otherwise = ConsentWithheld (psConsentDescriptor store)

{- No protocol read can see whether this store refills itself from an uplink, so the operator's
own key is the only evidence either way. -}
storeClass :: ProtocolStore -> StoreClass
storeClass store
    | psPermitDeletion store = StoreDestroyable
    | otherwise = StorePreserved (psConsentDescriptor store)

{- One bucket of the store's names, as the single page its one listing document holds. The
protocol spells no prefix filter, so the bucket is applied to what came back. -}
listBucket :: ProtocolStore -> NamePrefix -> ConduitT () [PackageName] IO (Maybe StoreFault)
listBucket store prefix =
    lift (listPackages store) >>= \case
        Left fault -> pure (Just fault)
        Right names -> Nothing <$ yield (filter (inBucket prefix) names)

listPackages :: ProtocolStore -> IO (Either StoreFault [PackageName])
listPackages store =
    sendFormed store (listingRequest (psListing store) (psOrigin store)) <&> \case
        Left fault -> Left fault
        Right (status, body)
            | status == 200 -> first (parseFault "package listing") (listingParse (psListing store) body)
            | otherwise -> Left (listingUnavailable status)

{- A store that answers the listing with anything but 200 implements no enumeration, and the
next cycle reads the same, so the sweep stops rather than retrying. -}
listingUnavailable :: Int -> StoreFault
listingUnavailable status =
    protocolFault
        ( "the store answered the package listing with HTTP "
            <> show status
            <> ": it serves no enumeration this sweep can walk"
        )

{- The presence probe's read, which already projects a store's version list for the mirror
worker. A store that holds no document for a package holds no versions of it either. -}
listVersions :: ProtocolStore -> PackageName -> IO (Either StoreFault [StoredVersion])
listVersions store name =
    sendFormed store (pcProbeRequest (psCodec store) (originBase store) (originToken store) name) <&> \case
        Left fault -> Left fault
        Right (status, body)
            | status == 404 -> Right []
            | isApplied status -> first (parseFault "version list") (served status body)
            | otherwise -> Left (readFault "version list" status)
  where
    served status body = map stored <$> pcParseVersionList (psCodec store) (RegistryResponse status body)
    stored version = StoredVersion{storedVersion = version, storedPresence = VersionServed}

deleteStoredVersions :: ProtocolStore -> PackageName -> [Version] -> IO [(Version, VersionOutcome)]
deleteStoredVersions store name versions =
    deleteAll (deleteChunk store name) (chunksOfCeiling deleteCeiling versions)

{- One version at a time: re-read the document, form the protocol's request sequence over it,
and send each in turn. A refusal is this version's alone, and a fault ends the whole run. -}
deleteChunk :: ProtocolStore -> PackageName -> [Version] -> IO (Either StoreFault [(Version, VersionOutcome)])
deleteChunk store name = \case
    [version] ->
        sendFormed store (deleteDocumentRequest (psDelete store) (psOrigin store) name) >>= \case
            Left fault -> pure (Left fault)
            Right (status, body)
                | status == 404 -> pure (refused version absentDocument)
                | not (isApplied status) -> pure (Left (readFault "document" status))
                | otherwise -> applyDelete store name version status body
    -- 'deleteCeiling' splits to one, so a wider chunk refuses whole rather than losing its tail.
    chunk -> pure (Right [(version, VersionRefused oversizedChunk) | version <- chunk])
  where
    absentDocument = storeRefusal "NOT_FOUND" "the store holds no document for this package"
    oversizedChunk = storeRefusal "CEILING_EXCEEDED" "this protocol deletes one version per call"

-- Form the version's request sequence over the fetched document, then send it.
applyDelete :: ProtocolStore -> PackageName -> Version -> Int -> ByteString -> IO (Either StoreFault [(Version, VersionOutcome)])
applyDelete store name version status body =
    case deleteRequests (psDelete store) (psOrigin store) name version (RegistryResponse status body) of
        Left refusal -> pure (refused version refusal)
        Right requests ->
            sendSequence store (toList requests) <&> fmap outcomeOf
  where
    outcomeOf = \case
        Nothing -> [(version, VersionRemoved)]
        Just refusal -> [(version, VersionRefused refusal)]

{- Send each request in order, stopping at the first refusal. That can leave the version
half-removed, so the code an operator looks up names which call stopped. -}
sendSequence :: ProtocolStore -> [Request] -> IO (Either StoreFault (Maybe StoreRefusal))
sendSequence store = go (1 :: Int)
  where
    go _ [] = pure (Right Nothing)
    go position (request : rest) =
        send store request >>= \case
            Left fault -> pure (Left fault)
            Right (status, _)
                | isApplied status -> go (position + 1) rest
                | otherwise -> pure (Right (Just (refusedAt position status)))

    refusedAt position status =
        storeRefusal
            ("HTTP " <> show status)
            ("the store refused request " <> show position <> " of the delete sequence")

refused :: Version -> StoreRefusal -> Either StoreFault [(Version, VersionOutcome)]
refused version refusal = Right [(version, VersionRefused refusal)]

-- Everything the store answers is read bounded, with the status kept beside the body.
send :: ProtocolStore -> Request -> IO (Either StoreFault (Int, ByteString))
send store request =
    first storeFaultOfFetch
        <$> boundedExchange (,) (ocManager origin) (ocLimits origin) request
  where
    origin = psOrigin store

-- Send a request the adapter formed, folding a formation failure into the same channel.
sendFormed :: ProtocolStore -> Either UrlFormationError Request -> IO (Either StoreFault (Int, ByteString))
sendFormed store = formThen unformableFault (send store)

originBase :: ProtocolStore -> Text
originBase = registryUrlText . ocBaseUrl . psOrigin

originToken :: ProtocolStore -> Maybe Secret
originToken = fmap credSecret . ocToken . psOrigin

-- A store applied what was asked when it answered in the 2xx class, whichever code it chose.
isApplied :: Int -> Bool
isApplied status = status >= 200 && status < 300

parseFault :: Text -> ParseError -> StoreFault
parseFault subject err =
    protocolFault ("the store's " <> subject <> " did not parse: " <> parseErrorMessage err)

{- A read the store answered outside the applied class. A server-side failure clears on its
own, and every other status reads the same way on the next cycle. -}
readFault :: Text -> Int -> StoreFault
readFault subject status =
    StoreFault
        { faultTransport =
            transportFault TransportProtocol ("the store answered the " <> subject <> " read with HTTP " <> show status)
        , faultRetry = if status >= 500 then RetryWorthwhile else RetryFutile
        }
