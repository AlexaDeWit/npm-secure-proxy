-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The PyPI realisation of the serve-path read operations, every failure a typed
'MetadataError' value.

One endpoint answers both needs: the Simple index carries each file's own @upload-time@, so the
age signal needs no second document and the pypi.org JSON API is not fetched at all.
'projectPyPIIndex' backs the full manifest, and 'projectPyPIVersion' backs the single-version
read over the same bytes selectively, so a cold artifact gate pays no whole-index decode to
consult one release. The cached document carries the file-to-version index computed once here
at fetch, so the served assembly re-parses no distribution file name.
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

{- | Build a per-request read handle over one origin, with
'Ecluse.Core.Server.Metadata.newMetadataClient' wiring caching, metrics, and logs around it.
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

{- | Fetch a project's Simple index into a 'Manifest', bounded against the origin's response budget.
The digest is computed here, the one place the wire bytes exist.
-}
fetchPyPIManifest :: TracingPort -> OriginClient -> PackageName -> IO (Either MetadataError Manifest)
fetchPyPIManifest tracing origin name =
    fetchThenProject tracing (fetchSimpleIndex origin) name $ \body ->
        manifestOf (digestOf body) . first (enforceArtifactLocations pypiArtifactAuthorities (originBaseUrl origin))
            <$> projectPyPIIndex (ocLimits origin) name body
  where
    -- The file-to-version index is computed here, at the fetch, so no served request re-parses
    -- a distribution file name.
    manifestOf digest (info, raw) =
        Manifest
            { manifestInfo = info
            , manifestRaw = fst pypiSimpleCached (raw, fileVersions info)
            , manifestDigest = digest
            }

{- | Project a fetched index's bytes into @(manifest, raw document)@, both readings of one
nesting-checked parse. Pure and total, with each refusal its own 'MetadataError'.
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

-- 'Nothing' is a release genuinely absent from a sound index, a forwarded miss.
fetchPyPIVersion :: TracingPort -> OriginClient -> PackageName -> Version -> IO (Either MetadataError (Maybe PackageDetails))
fetchPyPIVersion tracing origin name version =
    fetchThenProject tracing (fetchSimpleIndex origin) name $
        fmap (>>= enforceArtifactLocationsOf pypiArtifactAuthorities (originBaseUrl origin)) . projectPyPIVersion (ocLimits origin) name version

{- | Project a fetched index's bytes into one release's 'PackageDetails', without decoding the other
releases' files. Pure, total, and the outcome the whole-document path reaches.
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
