-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The composition root's store maintenance build, split across the boot's two tiers. The pure
half reads each mount's resolved store backend ("Ecluse.Config.Target") and its ecosystem adapter
as one rule in the vetting pass, so @ecluse dredger@ refuses a store this build cannot sweep and
@ecluse check-config@ names that refusal. Only that pass issues a 'ClearedBackend', and the
effectful half, in the pruner's arm of the planning phase ("Ecluse.Composition.Executable"),
builds a handle from that witness alone.
-}
module Ecluse.Composition.Maintenance (
    -- * The config-decidable half
    ClearedBackend (..),
    ClearedControl (..),
    ClearedProtocolStore (..),
    ResolveMaintenanceAdapter,
    vetStoreBackends,

    -- * The environment-dependent half
    StorePorts (..),
    BuildStoreMaintenance,
    buildStoreMaintenance,
    planStoreMaintenance,
) where

import Data.Map.Strict qualified as Map
import Network.HTTP.Client (Manager)
import Network.HTTP.Client.TLS (tlsManagerSettings)
import Validation (eitherToValidation, validationToEither)

import Ecluse.Composition.BootError (
    BootError (StoreMaintenanceUnavailable),
    StoreMaintenanceReason (ClientBuildFailed, DeletionNotPermitted, NoControlPlane, NoProtocolMaintenance),
    refuseOnThrow,
 )
import Ecluse.Composition.Credential (CredentialProviders, lookupProvider)
import Ecluse.Composition.Sizing (newPooledManager)
import Ecluse.Composition.Types (RegistryRole (MirrorPruner, MirrorWriter))
import Ecluse.Composition.Vet (Severity (Ignore, Refuse), Vet, rule, vetRole)
import Ecluse.Config (
    ControlPlane (ControlCodeArtifact, ControlNone, ControlProtocol),
    DeletionConsent (DeletionPermitted, DeletionWithheld),
    MirrorTarget (mtBackend, mtUrl),
    Mount (mountRegistries),
    MountMap,
    StoreBackend,
    StoreTag,
    regMirrorTarget,
    sbControl,
    sbTag,
    storeTagName,
 )
import Ecluse.Config.Resolve (mountKeyRef)
import Ecluse.Core.Credential (ClientCredential, CredentialProvider, Secret, bareCredential, mintSecret)
import Ecluse.Core.Ecosystem (Ecosystem)
import Ecluse.Core.Fault (TransportCause (TransportProtocol), transportFault)
import Ecluse.Core.Registry (FetchFault (FetchTransport))
import Ecluse.Core.Registry.Adapter (
    RegistryAdapter,
    adapterMaintenance,
    adapterMetadata,
    adapterPublish,
    publishCodec,
 )
import Ecluse.Core.Registry.Adapter.Capability (
    AdapterMaintenance (maintenanceAlphabet, maintenanceListing, maintenanceVersionDelete),
    AdapterMetadata (metadataFetchManifest),
    ManifestFetch,
    StoreListing,
    VersionDelete,
 )
import Ecluse.Core.Registry.Maintenance (
    NameAlphabet,
    StoreMaintenance,
    StoreManifestRead,
    noNameAlphabet,
    storeFaultOfMetadata,
 )
import Ecluse.Core.Registry.Maintenance.Protocol (ProtocolStore (..), newProtocolMaintenance)
import Ecluse.Core.Registry.Metadata (MetadataError (MetadataFetch))
import Ecluse.Core.Registry.Origin (OriginClient, originClient)
import Ecluse.Core.Registry.Publish (PublishCodec)
import Ecluse.Core.Security (Limits)
import Ecluse.Core.Security.Egress (RegistryUrl)
import Ecluse.Core.Telemetry.Span (TracingPort)
import Ecluse.Runtime.Maintenance.CodeArtifact (newCodeArtifactMaintenance)
import Ecluse.Runtime.Maintenance.CodeArtifact.Decide (CodeArtifactStore)

{- | A store the deleting role's pass cleared, one arm per backend kind. Only 'vetStoreBackends'
issues one, so a handle that can delete is built for no store that pass did not clear.
-}
data ClearedBackend = ClearedBackend
    { cbUrl :: RegistryUrl
    -- ^ Where the store answers, which is both what a sweep reads and what it deletes from.
    , cbAlphabet :: NameAlphabet
    -- ^ The characters a full walk partitions this store's names by.
    , cbFetchManifest :: ManifestFetch
    {- ^ The mount ecosystem's own manifest read, which the root leads over the store's endpoint
    rather than over the public upstream.
    -}
    , cbControl :: ClearedControl
    -- ^ The control plane a delete goes through.
    }

-- | The control plane a cleared store offers, one arm per backend kind.
data ClearedControl
    = -- | A CodeArtifact repository, deleted through the vendor's own control plane.
      ClearedCodeArtifact CodeArtifactStore
    | -- | A store with no vendor control plane, deleted through the ecosystem protocol.
      ClearedProtocol ClearedProtocolStore

{- | Everything the protocol leaf needs but the live environment: the endpoint, its write
credential, the operator's consent, and the ecosystem verbs the pass proved present.
-}
data ClearedProtocolStore = ClearedProtocolStore
    { cpsToken :: Secret
    , cpsTag :: StoreTag
    -- ^ The tag the store was declared under, which names the backend and its consent key.
    , cpsConsent :: DeletionConsent
    -- ^ What the operator wrote under that key, which the handle's own verdict reads.
    , cpsEcosystem :: Ecosystem
    , cpsListing :: StoreListing
    , cpsDelete :: VersionDelete
    , cpsCodec :: PublishCodec
    }

{- | How the pass resolves a mount's ecosystem to the adapter this build ships, injected so a
spec drives the protocol rule over an adapter that fills no maintenance slice.
-}
type ResolveMaintenanceAdapter = Ecosystem -> Maybe RegistryAdapter

{- | The rule every declared mirror target meets: its resolved backend offers a control plane this
build can sweep. The deleting role refuses a target that fails it, and a writing role ignores it.
-}
vetStoreBackends :: ResolveMaintenanceAdapter -> MountMap -> Vet (Map Ecosystem ClearedBackend)
vetStoreBackends resolveAdapter mounts = clearedFor <$> vetRole <* traverse_ (rule severity unmaintained) resolved
  where
    resolved =
        [ (eco, sweepableStore (resolveAdapter eco) eco target)
        | (eco, mount) <- Map.toAscList mounts
        , Just target <- [regMirrorTarget (mountRegistries mount)]
        ]

    severity = \case
        MirrorPruner -> Refuse (uncurry StoreMaintenanceUnavailable)
        MirrorWriter -> Ignore

    unmaintained (eco, outcome) = (eco,) <$> leftToMaybe outcome

    -- A refused pass yields no plan, so a target the rule refused never reaches this map.
    clearedFor = \case
        MirrorWriter -> Map.empty
        MirrorPruner -> Map.fromList [(eco, backend) | (eco, Right backend) <- resolved]

-- The store a resolved backend lets the Dredger delete from, or why this build reaches none.
sweepableStore :: Maybe RegistryAdapter -> Ecosystem -> MirrorTarget -> Either StoreMaintenanceReason ClearedBackend
sweepableStore mAdapter eco target = cleared <$> control
  where
    cleared c =
        ClearedBackend
            { cbUrl = mtUrl target
            , cbAlphabet = alphabet
            , cbFetchManifest = fetchManifest
            , cbControl = c
            }

    backend :: StoreBackend
    backend = mtBackend target

    {- The same pass refuses an ecosystem this build ships no adapter for ('MissingAdapter'), so a
    store cleared without one is unreachable rather than a store swept and read blind. -}
    (alphabet, fetchManifest) = maybe (noNameAlphabet, absentManifestRead) ecosystemFacing mAdapter

    ecosystemFacing adapter =
        ( maintenanceAlphabet (adapterMaintenance adapter)
        , metadataFetchManifest (adapterMetadata adapter)
        )

    control = case sbControl backend of
        ControlCodeArtifact store -> Right (ClearedCodeArtifact store)
        ControlNone -> Left (NoControlPlane (sbTag backend))
        ControlProtocol token consent -> protocolControl token consent

    protocolControl token consent = do
        -- Consent is the operator's own key, so it is reported ahead of what this build ships.
        when (consent == DeletionWithheld) (Left (DeletionNotPermitted (sbTag backend)))
        adapter <- maybeToRight NoProtocolMaintenance mAdapter
        listing <- maybeToRight NoProtocolMaintenance (maintenanceListing (adapterMaintenance adapter))
        delete <- maybeToRight NoProtocolMaintenance (maintenanceVersionDelete (adapterMaintenance adapter))
        Right
            ( ClearedProtocol
                ClearedProtocolStore
                    { cpsToken = token
                    , cpsTag = sbTag backend
                    , cpsConsent = consent
                    , cpsEcosystem = eco
                    , cpsListing = listing
                    , cpsDelete = delete
                    , cpsCodec = publishCodec (adapterPublish adapter)
                    }
            )

-- The read a store cleared without an adapter would make, which no boot reaches.
absentManifestRead :: ManifestFetch
absentManifestRead _ _ _ =
    pure (Left (MetadataFetch (FetchTransport (transportFault TransportProtocol absentAdapterDetail))))

absentAdapterDetail :: Text
absentAdapterDetail = "this build serves the mount's ecosystem no metadata read"

{- | What a store's handle needs from the live process: where its reads are traced, and the
credential its endpoint answers to. One value per mount, resolved before the handles are built.
-}
data StorePorts = StorePorts
    { spTracing :: TracingPort
    -- ^ The tracing port the manifest read is bracketed by.
    , spCredential :: Maybe CredentialProvider
    {- ^ The mirror-write credential, which the read presents too, so the store cannot answer a
    sweep and a mirror write under different identities.
    -}
    }

{- | How a boot builds one store's maintenance handle, under the response bound the plan resolved.
Injected, as the queue builder is, so a spec drives the pruner's arm without an AWS identity.
-}
type BuildStoreMaintenance = StorePorts -> Limits -> ClearedBackend -> IO StoreMaintenance

{- | The live handle for a cleared store. CodeArtifact discovers its credentials the standard AWS
way, and both arms read and dial over one manager of the store's own.
-}
buildStoreMaintenance :: BuildStoreMaintenance
buildStoreMaintenance ports limits cleared = do
    manager <- storeManager
    let readManifest = storeManifestRead ports limits cleared manager
    case cbControl cleared of
        ClearedCodeArtifact store -> newCodeArtifactMaintenance (cbAlphabet cleared) readManifest store
        ClearedProtocol store ->
            pure (newProtocolMaintenance (protocolStore limits cleared store readManifest manager))

{- One package's metadata as the store serves it, through the ecosystem's own codec. The token is
minted per read, because a store that mints its own hands out a short-lived one. -}
storeManifestRead :: StorePorts -> Limits -> ClearedBackend -> Manager -> StoreManifestRead
storeManifestRead ports limits cleared manager name = do
    token <- traverse mintSecret (spCredential ports)
    -- A minted store token carries no username: the store's own control plane, not a caller's.
    first storeFaultOfMetadata
        <$> cbFetchManifest cleared (spTracing ports) (storeOrigin limits cleared manager (bareCredential <$> token)) name

storeOrigin :: Limits -> ClearedBackend -> Manager -> Maybe ClientCredential -> OriginClient
storeOrigin limits cleared manager = originClient limits manager (cbUrl cleared)

{- The maintenance calls are not the proxy's data plane, so this manager carries none of its
tracing, exactly as the vendor client's own does not. -}
storeManager :: IO Manager
storeManager = newPooledManager storeConnections tlsManagerSettings

-- One store, swept package by package, so the pool holds what one in-flight request needs.
storeConnections :: Int
storeConnections = 4

protocolStore :: Limits -> ClearedBackend -> ClearedProtocolStore -> StoreManifestRead -> Manager -> ProtocolStore
protocolStore limits cleared store readManifest manager =
    ProtocolStore
        { psOrigin = storeOrigin limits cleared manager (Just (bareCredential (cpsToken store)))
        , psReadManifest = readManifest
        , psListing = cpsListing store
        , psDelete = cpsDelete store
        , psCodec = cpsCodec store
        , psBackendName = storeTagName (cpsTag store)
        , psPermitDeletion = cpsConsent store == DeletionPermitted
        , psConsentDescriptor = consentDescriptor (cpsEcosystem store) (cpsTag store)
        }

{- The key an operator sets, which the handle's own withheld verdict names. A handle this root
built always carries consent, because the pass above refuses the store that does not. -}
consentDescriptor :: Ecosystem -> StoreTag -> Text
consentDescriptor eco tag =
    "set "
        <> mountKeyRef eco ("mirrorTarget." <> storeTagName tag <> ".permitDeletion")
        <> " to true: the Dredger deletes nothing from a store that does not carry it"

{- | Build one handle per cleared store, or every refusal the live environment earns. The builds
accumulate, so one launch reports every store whose client cannot be built.
-}
planStoreMaintenance ::
    BuildStoreMaintenance ->
    TracingPort ->
    CredentialProviders ->
    Limits ->
    Map Ecosystem ClearedBackend ->
    IO (Either [BootError] (Map Ecosystem StoreMaintenance))
planStoreMaintenance build tracing credentials limits backends =
    validationToEither . traverse eitherToValidation <$> Map.traverseWithKey planOne backends
  where
    -- Both maps derive from the same declared mirror targets, so a cleared store finds its own.
    planOne eco backend =
        refuseOnThrow
            (StoreMaintenanceUnavailable eco . ClientBuildFailed)
            (build (portsFor eco) limits backend)

    portsFor eco = StorePorts{spTracing = tracing, spCredential = lookupProvider eco credentials}
