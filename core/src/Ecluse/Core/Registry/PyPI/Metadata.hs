-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The PyPI realisation of the serve-path read operations: fetch a project's Simple index and
project it into the domain manifest. Every failure comes back as a typed 'MetadataError'.

One endpoint answers both serve-path needs. The Simple index carries each file's own
@upload-time@, so the age signal a quarantine reads needs no second document, and the pypi.org
JSON API is not fetched at all. This module owns the PyPI side of both operations and the
constructor ('newPyPIMetadataClient') that leads them into the serve layer's agnostic caching,
metrics, and failure-log policy ("Ecluse.Core.Server.Metadata").

  * 'fetchPyPIManifest' \/ 'projectPyPIIndex' back the full-manifest operation. The projection
    runs one sequence over a fetched index: decode, bound the nesting depth, project and
    validate the self-reported name, then bound the release and file counts. It is a total
    'Either', so the serve path maps each cause onto a response rather than catching a throw.

  * 'projectPyPIVersion' backs the single-version operation. It parses the same bytes
    __selectively__ ("Ecluse.Core.Registry.PyPI.SelectiveDecode"), materialising only the files
    of the requested release and skipping the rest unallocated. A cold artifact gate therefore
    does not pay a whole-index decode to consult one release. It projects the selected files
    through the /same/ per-release code the full path runs.

The cached document this module injects carries the file-to-version index beside the raw
'Data.Aeson.Value', computed once here at fetch, so the served assembly reaches a flat file
array from a version key without re-parsing a distribution file name.
-}
module Ecluse.Core.Registry.PyPI.Metadata (
    -- * Per-request read handle
    newPyPIMetadataClient,

    -- * PyPI index fetch
    fetchPyPIManifest,

    -- * Pure projection
    projectPyPIIndex,
    projectPyPIVersion,
) where

import Data.Aeson (Value (Array, String), eitherDecodeStrict, object, parseJSON)
import Data.Aeson.Types (parseMaybe)
import Data.Map.Strict qualified as Map

import Ecluse.Core.Package (
    InvalidEntry,
    PackageDetails,
    PackageInfo (infoVersions),
    PackageName,
    artFilename,
    pkgArtifacts,
    renderPackageName,
 )
import Ecluse.Core.Package.Filter (enforceArtifactLocations, enforceArtifactLocationsOf)
import Ecluse.Core.Registry (FetchFault (FetchUrlUnformable), RegistryResponse)
import Ecluse.Core.Registry.CachedDocument (FileVersionIndex, pypiSimpleCached)
import Ecluse.Core.Registry.Exchange (boundedFetch, formThen)
import Ecluse.Core.Registry.Metadata (
    Manifest (Manifest, manifestDigest, manifestInfo, manifestRaw),
    MetadataClient,
    MetadataError (MetadataBoundExceeded, MetadataNameMismatch, MetadataUndecodable),
    digestOf,
    fetchThenProject,
 )
import Ecluse.Core.Registry.Origin (OriginClient (ocBaseUrl, ocLimits, ocManager, ocToken))
import Ecluse.Core.Registry.PyPI.Project (
    fileVersionKey,
    projectName,
    projectSimpleIndexFromValue,
 )
import Ecluse.Core.Registry.PyPI.Request (pypiArtifactHosts, simpleIndexRequest)
import Ecluse.Core.Registry.PyPI.SelectiveDecode (
    SelectedFiles (sfFileCount, sfFiles, sfName),
    SelectiveError (SelectiveTooDeeplyNested, SelectiveUndecodable),
    selectFilesFromIndex,
 )
import Ecluse.Core.Registry.Request (noValidators)
import Ecluse.Core.Registry.WireSupport (Projection (NameMismatch, Projected), checkNameAgreement)
import Ecluse.Core.Security (
    AllowedHostPorts,
    LimitError (TooDeeplyNested),
    Limits,
    checkArtifactCount,
    checkNestingDepth,
    checkVersionCount,
    checkVersionCountOf,
    ecosystemArtifactAuthorities,
    maxNestingDepth,
 )
import Ecluse.Core.Security.Egress (registryUrlText)
import Ecluse.Core.Server.Metadata (ManifestCaching, newMetadataClient)
import Ecluse.Core.Telemetry.Metrics qualified as Metric
import Ecluse.Core.Telemetry.Record (MetricsPort)
import Ecluse.Core.Telemetry.Span (TracingPort)
import Ecluse.Core.Version (Version, renderVersion)

{- | Build a per-request read handle for the PyPI protocol over one origin's fetch
configuration. 'Ecluse.Core.Server.Metadata.newMetadataClient' wires the serve-path caching,
metrics, and logs around these raw fetches.
-}
newPyPIMetadataClient ::
    TracingPort ->
    MetricsPort ->
    Metric.Upstream ->
    ManifestCaching ->
    (PackageName -> MetadataError -> IO ()) ->
    (PackageName -> [InvalidEntry] -> IO ()) ->
    (PackageName -> IO ()) ->
    OriginClient ->
    MetadataClient
newPyPIMetadataClient tracing metrics upstream caching logFailure logInvalid logFetch origin =
    newMetadataClient metrics upstream caching logFailure logInvalid logFetch (fetchPyPIManifest tracing origin) (fetchPyPIVersion tracing origin)

{- The one PyPI metadata read: the Simple index, bounded against the origin's response budget.
Both read operations fetch it and differ only in the projection they run over the bytes. -}
fetchSimpleIndex :: OriginClient -> PackageName -> IO (Either FetchFault RegistryResponse)
fetchSimpleIndex origin name =
    formThen
        FetchUrlUnformable
        (boundedFetch (ocManager origin) (ocLimits origin))
        (simpleIndexRequest (registryUrlText (ocBaseUrl origin)) (ocToken origin) noValidators name)

{- | Fetch a project's Simple index and project it into a 'Manifest': the typed view, the raw
document with its file-to-version index, and the wire bytes' 'ContentDigest'.

The read is bounded against the origin's response budget, so an oversized upstream is refused
fail-closed before anything buffers it whole. The digest is computed here, over the strict body
that read produced, the one place the wire bytes exist.
-}
fetchPyPIManifest :: TracingPort -> OriginClient -> PackageName -> IO (Either MetadataError Manifest)
fetchPyPIManifest tracing origin name =
    fetchThenProject tracing (fetchSimpleIndex origin) name $ \body ->
        manifestOf (digestOf body) . first (enforceArtifactLocations pypiArtifactAuthorities (originBaseUrl origin))
            <$> projectPyPIIndex (ocLimits origin) name body
  where
    {- Inject the raw index and the file-to-version index the projection settled into the opaque
    served-document carrier. The index is computed here, at the fetch, so no served request
    re-parses a distribution file name. -}
    manifestOf digest (info, raw) =
        Manifest
            { manifestInfo = info
            , manifestRaw = fst pypiSimpleCached (raw, fileVersions info)
            , manifestDigest = digest
            }

{- | Project a fetched index's bytes into @(manifest, raw document)@, applying the serve path's
response bounds and name validation. Pure and total.

The raw 'Value' is the nesting-checked document the typed view was projected from, so both
describe one parse. A decode failure or an absent\/undecodable name is 'MetadataUndecodable'. A
self-reported /different/ name is 'MetadataNameMismatch'. A nesting-depth, release-count, or
artifact-count breach is 'MetadataBoundExceeded'.
-}
projectPyPIIndex :: Limits -> PackageName -> ByteString -> Either MetadataError (PackageInfo, Value)
projectPyPIIndex limits name body = do
    value <- first (const MetadataUndecodable) (eitherDecodeStrict body)
    bounded <- first MetadataBoundExceeded (checkNestingDepth limits value)
    info <- case projectSimpleIndexFromValue name bounded of
        Left _ -> Left MetadataUndecodable
        Right (NameMismatch reported) -> Left (MetadataNameMismatch reported)
        Right (Projected projected) -> Right projected
    versionBounded <- first MetadataBoundExceeded (checkVersionCount limits info)
    boundedInfo <- first MetadataBoundExceeded (checkArtifactCount limits versionBounded)
    pure (boundedInfo, bounded)

{- Fetch a project's Simple index and project __only the requested release__ into its
'PackageDetails'. A 'Nothing' is a release genuinely absent from a sound index, a forwarded
miss. -}
fetchPyPIVersion :: TracingPort -> OriginClient -> PackageName -> Version -> IO (Either MetadataError (Maybe PackageDetails))
fetchPyPIVersion tracing origin name version =
    fetchThenProject tracing (fetchSimpleIndex origin) name $
        fmap (>>= enforceArtifactLocationsOf pypiArtifactAuthorities (originBaseUrl origin)) . projectPyPIVersion (ocLimits origin) name version

{- | Project a fetched index's bytes into __one release's__ 'PackageDetails', without decoding
the files of the other releases. Pure and total.

The outcome matches the one the whole-document path reaches for that release. An
absent\/undecodable @name@ is 'MetadataUndecodable' and a self-reported /different/ name is
'MetadataNameMismatch', the anti-shadowing distinction. A breach of
'Ecluse.Core.Security.maxNestingDepth' or of the file-count backstop is 'MetadataBoundExceeded'.
A release the index does not carry yields 'Nothing'.
-}
projectPyPIVersion :: Limits -> PackageName -> Version -> ByteString -> Either MetadataError (Maybe PackageDetails)
projectPyPIVersion limits name version body = do
    decoded <- first (selectiveError limits) (selectFilesFromIndex (maxNestingDepth limits) belongsToRelease body)
    -- The self-reported name is the validation authority (anti-shadowing), checked before the
    -- count backstop, as 'projectPyPIIndex' does.
    reported <- validateReportedName (sfName decoded)
    selected <- case checkNameAgreement name reported decoded of
        NameMismatch other -> Left (MetadataNameMismatch other)
        Projected agreed -> Right agreed
    first MetadataBoundExceeded (checkVersionCountOf limits (sfFileCount selected))
    -- The selected files are projected through the same code the whole-index path runs, over an
    -- index carrying those files alone, so the release resolves identically either way.
    pure (releaseOf (projectSelected reported (sfFiles selected)))
  where
    belongsToRelease filename = fileVersionKey name filename == Just wanted
    wanted = renderVersion version

    projectSelected reported files =
        case projectSimpleIndexFromValue name (indexOf reported files) of
            Right (Projected info) -> Just info
            _ -> Nothing

    releaseOf info = Map.lookup wanted . infoVersions =<< info

-- Rebuild the smallest index that carries the selected files, for the shared projection to read.
indexOf :: PackageName -> [Value] -> Value
indexOf reported files = object [("name", String (renderPackageName reported)), ("files", Array (fromList files))]

-- The document's self-reported name, folded to the same 'MetadataUndecodable' the whole-document
-- decode reaches for an absent, non-string, or malformed name.
validateReportedName :: Maybe Value -> Either MetadataError PackageName
validateReportedName = \case
    Nothing -> Left MetadataUndecodable
    Just nameValue -> case parseMaybe parseJSON nameValue of
        Nothing -> Left MetadataUndecodable
        Just raw -> first (const MetadataUndecodable) (projectName raw)

{- Which release each of a projected index's files belongs to, keyed by file name. The
projection has already read every coordinate, so this reads its result rather than the names. -}
fileVersions :: PackageInfo -> FileVersionIndex
fileVersions info =
    Map.fromList
        [ (artFilename artifact, version)
        | (version, details) <- Map.toList (infoVersions info)
        , artifact <- toList (pkgArtifacts details)
        ]

{- PyPI's declared artifact authorities, derived once from the same list the adapter hands the
tarball-host gate, so the projection and the download gate read one set. -}
pypiArtifactAuthorities :: AllowedHostPorts
pypiArtifactAuthorities = ecosystemArtifactAuthorities pypiArtifactHosts

{- The origin's base URL as characters, for the location reduction that must still recognise a
non-https (dev loopback) upstream and leave its file URLs alone. -}
originBaseUrl :: OriginClient -> Text
originBaseUrl = registryUrlText . ocBaseUrl

-- Map a selective-decode refusal onto the 'MetadataError' the whole-document path raises for
-- the same cause.
selectiveError :: Limits -> SelectiveError -> MetadataError
selectiveError limits = \case
    SelectiveUndecodable -> MetadataUndecodable
    SelectiveTooDeeplyNested -> MetadataBoundExceeded (TooDeeplyNested (maxNestingDepth limits))
