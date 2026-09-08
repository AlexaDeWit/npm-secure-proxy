-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The per-request metadata handle and typed outcomes shared by registry adapters.
Access refusals retain their upstream status before projection. The serve pipeline owns fallback policy.
-}
module Ecluse.Core.Registry.Metadata (
    -- * The read handle
    MetadataClient (..),

    -- * The full-manifest result
    Manifest (..),
    ContentDigest,
    digestOf,
    digestBytes,

    -- * The fetch-then-project step
    fetchThenProject,

    -- * Errors
    MetadataError (..),

    -- * Single-version resolution
    VersionEvaluation (..),
    fetchVersionDetails,
    versionTransience,
) where

import Crypto.Hash (Digest, SHA256, hash)
import Data.ByteArray qualified as BA

import Ecluse.Core.Package (PackageDetails, PackageInfo, PackageName)
import Ecluse.Core.Registry (FetchFault, RegistryResponse (responseBody, responseStatusCode), isAuthorisationFailure)
import Ecluse.Core.Registry.CachedDocument (CachedDoc)
import Ecluse.Core.Rules.Types (Transience (WillResolve, WontResolve))
import Ecluse.Core.Security (LimitError)
import Ecluse.Core.Telemetry.Span (TracingPort (spanMetadataDecode, spanMetadataFetch))
import Ecluse.Core.Version (Version)

-- | A SHA-256 digest of one origin's wire body: the exact bytes the mount decoded a manifest from. Opaque: built only by 'digestOf', read only by 'digestBytes'.
newtype ContentDigest = ContentDigest ByteString
    deriving stock (Eq, Show)

-- | Digest a strict body: one @O(body)@ pass, paid at fetch time, never per serve.
digestOf :: ByteString -> ContentDigest
digestOf body = ContentDigest (BA.convert (hash body :: Digest SHA256))

-- | The digest's raw 32 bytes, for feeding into a wider fingerprint.
digestBytes :: ContentDigest -> ByteString
digestBytes (ContentDigest bytes) = bytes

-- | A resolved full manifest. The serve path edits the raw document, re-serialises it, and builds its derived ETag over 'manifestDigest' ('Ecluse.Core.Server.Conditional').
data Manifest = Manifest
    { manifestInfo :: PackageInfo
    -- ^ The typed packument view the rules and merge reason over.
    , manifestRaw :: CachedDoc
    -- ^ The raw upstream document ('CachedDoc') the served body is built from.
    , manifestDigest :: ContentDigest
    -- ^ Digest of the wire bytes behind 'manifestInfo' and 'manifestRaw'.
    }

-- | The serve-path read handle over one registry mount. Its closures capture the per-origin fetch configuration and the shared cache, keeping a backend out of the core.
data MetadataClient = MetadataClient
    { fetchFullManifest :: PackageName -> IO (Either MetadataError Manifest)
    -- ^ Fetch and project a package's full manifest, every version included. Every failure comes back as a 'MetadataError' value: fetch, transport, parse, or policy.
    , fetchVersionMetadata :: PackageName -> Version -> IO (Either MetadataError (Maybe PackageDetails))
    -- ^ 'Nothing' means the package resolved without this version. Errors retain the upstream failure.
    }

-- | Fetch one package's metadata document under the fetch span, then project its wire bytes under the decode span. An exchange fault folds to 'MetadataFetch' before the projection runs.
fetchThenProject ::
    TracingPort ->
    (PackageName -> IO (Either FetchFault RegistryResponse)) ->
    PackageName ->
    (ByteString -> Either MetadataError a) ->
    IO (Either MetadataError a)
fetchThenProject tracing fetch name project =
    spanMetadataFetch tracing name (fetch name) >>= \case
        Left fault -> pure (Left (MetadataFetch fault))
        Right response
            | isAuthorisationFailure (responseStatusCode response) -> pure (Left (MetadataAuthorisationFailure (responseStatusCode response)))
            | otherwise -> spanMetadataDecode tracing name (pure (project (responseBody response)))

-- | Why a metadata fetch could not yield a usable result.
data MetadataError
    = -- | The upstream explicitly refused access. Carries the original 401 or 403.
      MetadataAuthorisationFailure Int
    | -- | The upstream exchange never delivered a body, carried as the shared 'Ecluse.Core.Registry.FetchFault' so a config fault and an outage stay distinct.
      MetadataFetch FetchFault
    | -- | The decoded document breached a structural bound (version count, nesting depth), distinct from the exchange's response-size bound, which arrives as 'MetadataFetch'.
      MetadataBoundExceeded LimitError
    | -- | The upstream answered, but its body did not decode into a usable manifest (malformed JSON, or an absent\/undecodable top-level name).
      MetadataUndecodable
    | -- | An invalid package identity, carried for diagnostics and excluded from the requested package.
      MetadataNameMismatch Text
    deriving stock (Eq, Show)

-- | The outcome of resolving one version's metadata for a policy decision. The serve-time gate and the mirror worker share it, so both reach the same outcome from one fetch.
data VersionEvaluation
    = -- | The version resolved and projected. Its 'PackageDetails' is ready for the rules engine.
      VersionPresent PackageDetails
    | -- | The package resolved but does not carry the requested version (a withdrawn or never-published version), a genuine absence distinct from unobtainable metadata.
      VersionMissing
    | -- | Metadata was unavailable. Public admission and workers retain their retry policy.
      VersionMetadataUnavailable
    deriving stock (Eq, Show)

-- | Resolve a single version's metadata through a 'MetadataClient' and classify it. Both the serve-time tarball gate and the mirror worker run this step before the rules engine.
fetchVersionDetails :: MetadataClient -> PackageName -> Version -> IO VersionEvaluation
fetchVersionDetails client name version =
    fetchVersionMetadata client name version <&> \case
        Left _ -> VersionMetadataUnavailable
        Right Nothing -> VersionMissing
        Right (Just details) -> VersionPresent details

-- | The transience of a lookup that yielded no details, and 'Nothing' for a resolved one. The serve gate and the mirror worker both read it, so neither classifies a lookup on its own.
versionTransience :: VersionEvaluation -> Maybe Transience
versionTransience = \case
    VersionMetadataUnavailable -> Just (WillResolve Nothing)
    -- A withdrawn version is gone for good, so no consumer waits for it to come back.
    VersionMissing -> Just WontResolve
    VersionPresent{} -> Nothing
