-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The ecosystem capability slices a consuming pipeline's dependency record __embeds__: the
metadata read and assembly, the artifact request formation, the publish path, and the store
maintenance verbs. Nothing here holds a URL, a credential, a limit, or a policy.

They sit below the serve surface because the deps records carry them as fields, while
'Ecluse.Core.Registry.Adapter.Types.AdapterServe' names the routing knot defined over those
same records. The split is what makes both directions typeable.
-}
module Ecluse.Core.Registry.Adapter.Capability (
    -- * Metadata
    AdapterMetadata (..),
    ManifestFetch,

    -- * Artifact requests
    AdapterArtifact (..),

    -- * Publish
    AdapterPublish (..),

    -- * Names
    ProjectName,

    -- * Store maintenance
    AdapterMaintenance (..),
    StoreListing (..),
    VersionDelete (..),
) where

import Network.HTTP.Client (Request)

import Ecluse.Core.Credential (ClientCredential)
import Ecluse.Core.Package (InvalidEntry, PackageName)
import Ecluse.Core.Package.Merge (MergePlan, SourceId)
import Ecluse.Core.Registry (
    FetchFault,
    ParseError,
    PublishRelayResponse,
    RegistryResponse,
    UrlFormationError,
 )
import Ecluse.Core.Registry.CachedDocument (CachedDoc)
import Ecluse.Core.Registry.Maintenance (NameAlphabet, StoreRefusal)
import Ecluse.Core.Registry.Metadata (Manifest, MetadataClient, MetadataError)
import Ecluse.Core.Registry.Origin (OriginClient)
import Ecluse.Core.Registry.Publish (PublishCodec)
import Ecluse.Core.Server.Metadata (ManifestCaching)
import Ecluse.Core.Telemetry.Metrics qualified as Metric
import Ecluse.Core.Telemetry.Record (MetricsPort)
import Ecluse.Core.Telemetry.Span (TracingPort)
import Ecluse.Core.Version (Version)

{- | Canonicalise a raw package-name string under one ecosystem's own grammar, 'Nothing' for
a string that grammar refuses. It is the one parser every caller reaches a 'PackageName' through.
-}
type ProjectName = Text -> Maybe PackageName

{- | The ecosystem's metadata capability: reading a package's metadata from an origin,
assembling the served document, and encoding it ('Ecluse.Core.Server.Context.pdMetadata').
-}
data AdapterMetadata = AdapterMetadata
    { metadataNewClient ::
        TracingPort ->
        MetricsPort ->
        Metric.Upstream ->
        ManifestCaching ->
        (PackageName -> MetadataError -> IO ()) ->
        (PackageName -> [InvalidEntry] -> IO ()) ->
        (PackageName -> IO ()) ->
        OriginClient ->
        MetadataClient
    {- ^ Build a per-request metadata client for one origin. The adapter closes over the
    ecosystem's raw fetch primitives, and the caller names the origin and the observers.
    -}
    , metadataAssemble :: Text -> Map SourceId CachedDoc -> MergePlan -> Maybe CachedDoc -> CachedDoc
    {- ^ Assemble the served document from a merge plan, the raw source documents, and the
    precedence-winning base document ('Nothing' when there is none), rewriting each surviving
    version's artifact URL under the given mount base.
    -}
    , metadataSerialise :: CachedDoc -> LByteString
    -- ^ Encode an assembled served document ('CachedDoc') to its wire bytes.
    , metadataFetchManifest :: ManifestFetch
    -- ^ The raw read under 'metadataNewClient', without its caching and metrics, for a store sweep.
    }

{- | Fetching and projecting one package's full manifest from an origin. Every failure is a
'MetadataError' value, as it is through the client built over it.
-}
type ManifestFetch = TracingPort -> OriginClient -> PackageName -> IO (Either MetadataError Manifest)

{- | The ecosystem's artifact request formation, by conventional filename or authoritative URL.
The serve deps and the worker bundle share it ('Ecluse.Core.Server.Context.pdArtifact').
-}
data AdapterArtifact = AdapterArtifact
    { artifactByFile :: OriginClient -> PackageName -> Text -> Either UrlFormationError Request
    {- ^ Build an artifact request by conventional filename path under the origin's base URL:
    how the proxy addresses a trusted origin.
    -}
    , artifactByUrl :: Maybe ClientCredential -> Text -> Either UrlFormationError Request
    {- ^ Build an artifact request at its authoritative upstream URL. It names no origin: the
    URL is complete on its own, and the mirror worker's fetch has none to give.
    -}
    , artifactHosts :: [Text]
    {- ^ The ecosystem's canonical artifact hosts, whose authorities feed the tarball-host gate.
    The secure-default same-host policy admits them (PyPI's is @https://files.pythonhosted.org@)
    without the operator naming hostnames. Empty for npm, whose artifacts ride the registry host.
    -}
    }

{- | The ecosystem's publish capability: the first-party relay, the name canonicaliser, the
declared-name extractor, and the mirror write's protocol codec. The composition root marries
the codec to the shared publish transport per mounted ecosystem
('Ecluse.Core.Registry.Publish.newMirrorPublish').
-}
data AdapterPublish = AdapterPublish
    { publishRelay :: OriginClient -> PackageName -> ByteString -> IO (Either FetchFault PublishRelayResponse)
    {- ^ Relay a client's publish document to the publication target, named as the origin to
    write through, and return the target's own response.
    -}
    , publishDeclaredNames :: LByteString -> [Text]
    {- ^ Extract every package name a publish body declares as its own identity. The
    anti-shadowing guard refuses any declared name that disagrees with the URL-path name. A body
    that declares no readable name yields @[]@.
    -}
    , publishCodec :: PublishCodec
    {- ^ The mirror write's protocol codec: publish document assembly, request formation, the
    probe's request and version-list projection, and the status semantics. Protocol only: the
    manager, credential mint, and fault classification belong to the shared transport.
    -}
    }

{- | The ecosystem's store maintenance verbs, which "Ecluse.Core.Registry.Maintenance.Protocol"
drives. Each is 'Nothing' for a protocol that spells no such verb, and the Dredger then refuses.
-}
data AdapterMaintenance = AdapterMaintenance
    { maintenanceListing :: Maybe StoreListing
    -- ^ How the protocol enumerates a store's packages, where it can.
    , maintenanceVersionDelete :: Maybe VersionDelete
    -- ^ How the protocol deletes one version, where it can.
    , maintenanceAlphabet :: NameAlphabet
    {- ^ The characters a name may begin with under this ecosystem's own grammar, which is what
    partitions a store's name space into the buckets a full walk covers one at a time.
    -}
    }

{- | Reading every package a store holds. The protocol's own listing endpoint, which a public
registry may well refuse: a listing that does not answer @200@ is the caller's fault to report.
-}
data StoreListing = StoreListing
    { listingRequest :: OriginClient -> Either UrlFormationError Request
    -- ^ Form the listing read against the store.
    , listingParse :: ByteString -> Either ParseError [PackageName]
    {- ^ Project a listing body onto the names it holds. An entry this ecosystem cannot parse
    as a name is dropped, because Écluse could serve it no better than it can sweep it.
    -}
    }

{- | Deleting one version, as the request sequence the protocol spells it with. It names its own
document read, because an install-optimised metadata read may omit the revision the edit needs.
-}
data VersionDelete = VersionDelete
    { deleteDocumentRequest :: OriginClient -> PackageName -> Either UrlFormationError Request
    -- ^ Form the read of the document the delete requests are built from.
    , deleteRequests ::
        OriginClient ->
        PackageName ->
        Version ->
        RegistryResponse ->
        Either StoreRefusal (NonEmpty Request)
    {- ^ Form the ordered requests that remove one version, or say why the fetched document
    admits none. Every request must be sent, in this order, for the version to be gone.
    -}
    }
