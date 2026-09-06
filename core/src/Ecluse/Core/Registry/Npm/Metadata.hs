-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The npm realisation of the serve-path read operations: fetch a package's full
packument and project it into the domain manifest. Every failure comes back as a typed
'MetadataError'.

npm satisfies both serve-path needs from the /same/ full-packument endpoint. The
publish-age rules require the packument's @time@ map, which npm exposes only in the
full form, so even the single-version need fetches the full bytes. This module owns the
npm side of both serve-path operations, the fetch and the projection. It also owns the
constructor ('newNpmMetadataClient') that leads them into the serve layer's agnostic
caching, metrics, and failure-log policy ("Ecluse.Core.Server.Metadata"). The
cross-cutting caching policy belongs there.

  * 'fetchNpmManifest' \/ 'projectNpmManifest' back the full-manifest operation. The
    projection runs one sequence over a fetched packument: decode, bound the nesting
    depth, project and validate the self-reported name, then bound the version count.
    It is a total 'Either', so the serve path maps each cause onto a response rather
    than catching a typed throw.

  * 'projectNpmVersion' backs the single-version operation. Its fetch still reads the full
    bytes, because npm carries @time@ only in the full form, but it parses them
    __selectively__ ("Ecluse.Core.Registry.Npm.SelectiveDecode"). It
    materialises only the requested version's object and @time@ entry, and skips the
    others unallocated. A cold tarball gate therefore does not pay a whole-packument
    decode to consult one version. It projects the selected version through the /same/
    per-version code the full path runs. Its 'Ecluse.Core.Package.PackageDetails' is
    identical to selecting it out of a full projection.
-}
module Ecluse.Core.Registry.Npm.Metadata (
    -- * Per-request read handle
    newNpmMetadataClient,

    -- * npm full-manifest fetch
    fetchNpmManifest,

    -- * Pure projection
    projectNpmManifest,
    projectNpmVersion,
) where

import Data.Aeson (Value, eitherDecodeStrict, parseJSON)
import Data.Aeson.Types (parseMaybe)
import Data.Time (UTCTime)

import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.Package (
    InvalidEntry,
    PackageDetails,
    PackageInfo,
    PackageName,
 )
import Ecluse.Core.Package.Filter (enforceArtifactLocations, enforceArtifactLocationsOf)
import Ecluse.Core.Registry (FetchFault, RegistryResponse)
import Ecluse.Core.Registry.CachedDocument (npmCached)
import Ecluse.Core.Registry.Metadata (
    Manifest (Manifest, manifestDigest, manifestInfo, manifestRaw),
    MetadataClient,
    MetadataError (MetadataBoundExceeded, MetadataNameMismatch, MetadataUndecodable),
    digestOf,
    fetchThenProject,
 )
import Ecluse.Core.Registry.Npm (fetchMetadataFormBounded)
import Ecluse.Core.Registry.Npm.Project (
    parsePackageInfoFromValue,
    projectName,
    projectVersionEntry,
 )
import Ecluse.Core.Registry.Npm.Request (MetadataForm (Full), npmArtifactHosts)
import Ecluse.Core.Registry.Npm.SelectiveDecode (
    SelectedVersion (svName, svTime, svVersion, svVersionCount),
    SelectiveError (SelectiveTooDeeplyNested, SelectiveUndecodable),
    selectVersionFromPackument,
 )
import Ecluse.Core.Registry.Origin (OriginClient (ocBaseUrl, ocLimits))
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
import Ecluse.Core.Version (Version, mkVersion, renderVersion)

{- | Build a per-request read handle for the npm protocol over one origin's fetch
configuration. 'Ecluse.Core.Server.Metadata.newMetadataClient' wires the serve-path caching,
metrics, and logs around these raw fetches.
-}
newNpmMetadataClient ::
    TracingPort ->
    MetricsPort ->
    Metric.Upstream ->
    ManifestCaching ->
    (PackageName -> MetadataError -> IO ()) ->
    (PackageName -> [InvalidEntry] -> IO ()) ->
    (PackageName -> IO ()) ->
    OriginClient ->
    MetadataClient
newNpmMetadataClient tracing metrics upstream caching logFailure logInvalid logFetch origin =
    newMetadataClient metrics upstream caching logFailure logInvalid logFetch (fetchNpmManifest tracing origin) (fetchNpmVersion tracing origin)

{- The one npm metadata read: the full packument, bounded against the origin's response budget.
Both npm read operations fetch it and differ only in the projection they run over the bytes. -}
fetchNpmPackument :: OriginClient -> PackageName -> IO (Either FetchFault RegistryResponse)
fetchNpmPackument origin = fetchMetadataFormBounded origin Full noValidators

{- | Fetch a package's full packument and project it into a 'Manifest': the typed view, the
raw document, and the wire bytes' 'ContentDigest'.

The read is bounded against the origin's response budget, so an oversized upstream is
refused fail-closed before anything buffers it whole. The digest is computed here, over the
strict body that read produced, the one place the wire bytes exist.
-}
fetchNpmManifest :: TracingPort -> OriginClient -> PackageName -> IO (Either MetadataError Manifest)
fetchNpmManifest tracing origin name =
    fetchThenProject tracing (fetchNpmPackument origin) name $ \body ->
        manifestOf (digestOf body) . first (enforceArtifactLocations npmArtifactAuthorities (originBaseUrl origin))
            <$> projectNpmManifest (ocLimits origin) name body
  where
    -- Inject npm's raw packument 'Value' into the opaque served-document carrier at the
    -- fetch boundary: the neutral pipeline and cache thread it without reading it.
    manifestOf digest (info, raw) = Manifest{manifestInfo = info, manifestRaw = fst npmCached raw, manifestDigest = digest}

{- | Project a fetched packument's bytes into @(manifest, raw document)@, applying the serve
path's response bounds and name validation. Pure and total.

The raw 'Value' is the nesting-checked document the typed view was projected from, so both
describe one parse. A decode failure or an absent\/undecodable name is 'MetadataUndecodable'.
A self-reported /different/ name is 'MetadataNameMismatch'. A nesting-depth, version-count, or
artifact-count breach is 'MetadataBoundExceeded'.
-}
projectNpmManifest :: Limits -> PackageName -> ByteString -> Either MetadataError (PackageInfo, Value)
projectNpmManifest limits name body = do
    value <- first (const MetadataUndecodable) (eitherDecodeStrict body)
    bounded <- first MetadataBoundExceeded (checkNestingDepth limits value)
    info <- case parsePackageInfoFromValue name bounded of
        Left _ -> Left MetadataUndecodable
        Right (NameMismatch reported) -> Left (MetadataNameMismatch reported)
        Right (Projected projected) -> Right projected
    versionBounded <- first MetadataBoundExceeded (checkVersionCount limits info)
    boundedInfo <- first MetadataBoundExceeded (checkArtifactCount limits versionBounded)
    pure (boundedInfo, bounded)

{- Fetch a package's full packument and project __only the requested version__ into its
'PackageDetails'.

npm carries the @time@ map only in the full document, so this still fetches the full bytes.
The win is that 'projectNpmVersion' parses them selectively, materialising one version
rather than every version. A 'Nothing' is a version genuinely absent from a sound document,
a forwarded miss.
-}
fetchNpmVersion :: TracingPort -> OriginClient -> PackageName -> Version -> IO (Either MetadataError (Maybe PackageDetails))
fetchNpmVersion tracing origin name version =
    fetchThenProject tracing (fetchNpmPackument origin) name $
        fmap (>>= enforceArtifactLocationsOf npmArtifactAuthorities (originBaseUrl origin)) . projectNpmVersion (ocLimits origin) name version

-- Derived from the same list the adapter hands the tarball-host gate. It is empty, so an npm
-- artifact is honoured only on the authority that served its packument.
npmArtifactAuthorities :: AllowedHostPorts
npmArtifactAuthorities = ecosystemArtifactAuthorities npmArtifactHosts

{- The origin's base URL as characters, for the scheme normalisation that must still
recognise a non-https (dev loopback) upstream and leave its artifact URLs alone. -}
originBaseUrl :: OriginClient -> Text
originBaseUrl = registryUrlText . ocBaseUrl

{- | Project a fetched packument's bytes into __one version's__ 'PackageDetails', without
decoding the other versions. Pure and total.

The outcome matches the one the whole-document path reaches for that version. An
absent\/undecodable @name@ is 'MetadataUndecodable' and a self-reported /different/ name is
'MetadataNameMismatch', the anti-shadowing distinction. A breach of 'maxNestingDepth' or of
the version-count backstop ('checkVersionCountOf') is 'MetadataBoundExceeded'. An absent or
unprojectable version yields 'Nothing'.
-}
projectNpmVersion :: Limits -> PackageName -> Version -> ByteString -> Either MetadataError (Maybe PackageDetails)
projectNpmVersion limits name version body = do
    decoded <- first (selectiveError limits) (selectVersionFromPackument (maxNestingDepth limits) version body)
    -- The self-reported name is the validation authority (anti-shadowing), checked before the
    -- version-count backstop, as 'projectNpmManifest' does.
    reported <- validateReportedName (svName decoded)
    selected <- case checkNameAgreement name reported decoded of
        NameMismatch other -> Left (MetadataNameMismatch other)
        Projected agreed -> Right agreed
    first MetadataBoundExceeded (checkVersionCountOf limits (svVersionCount selected))
    publishedAt <- parsePublishTime (svTime selected)
    -- 'mkVersion' over the requested version's rendered key matches the whole-document path,
    -- which keys 'projectVersions' by that same string and so projects the version under it.
    pure (svVersion selected >>= projectVersionEntry name (mkVersion Npm (renderVersion version)) publishedAt)

-- The document's self-reported name, folded to the same 'MetadataUndecodable' the
-- whole-document decode reaches for an absent, non-string, or malformed name.
validateReportedName :: Maybe Value -> Either MetadataError PackageName
validateReportedName = \case
    Nothing -> Left MetadataUndecodable
    Just nameValue -> case parseMaybe parseJSON nameValue of
        Nothing -> Left MetadataUndecodable
        Just raw -> first (const MetadataUndecodable) (projectName raw)

-- An absent or undecodable stamp means no known publish time, never a document failure.
-- The whole-document path drops a malformed @time@ entry the same way.
parsePublishTime :: Maybe Value -> Either MetadataError (Maybe UTCTime)
parsePublishTime = \case
    Nothing -> Right Nothing
    Just timeValue -> Right (parseMaybe parseJSON timeValue)

-- Map a selective-decode refusal onto the 'MetadataError' the whole-document path raises
-- for the same cause.
selectiveError :: Limits -> SelectiveError -> MetadataError
selectiveError limits = \case
    SelectiveUndecodable -> MetadataUndecodable
    SelectiveTooDeeplyNested -> MetadataBoundExceeded (TooDeeplyNested (maxNestingDepth limits))
