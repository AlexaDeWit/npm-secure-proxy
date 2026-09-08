-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Registry payloads and typed failures shared by the protocol capabilities.
Read responses retain the HTTP status so metadata projection cannot erase access refusals.
-}
module Ecluse.Core.Registry (
    -- * Fetch payload
    RegistryResponse (..),
    isAuthorisationFailure,

    -- * Publish descriptor
    MirrorArtifact (..),
    firstHashValue,

    -- * Errors
    ParseError (..),
    FetchFault (..),
    PublishError (..),
    PublishFault (..),
    UrlFormationError (..),
    renderUrlFormationError,
    PublishRelayResponse (..),
) where

import Ecluse.Core.Fault (TransportFault)
import Ecluse.Core.Package (Hash, HashAlg, hashAlg, hashValue)
import Ecluse.Core.Security (LimitError, authorityLabel)
import Ecluse.Core.Server.Path (Filename)

-- | A raw response fetched from a registry, the unparsed bytes 'fetchMetadata' returned. The bytes stay opaque here to keep fetching separate from parsing.
data RegistryResponse = RegistryResponse
    { responseStatusCode :: Int
    -- ^ The upstream status, retained before body projection.
    , responseBody :: ByteString
    -- ^ The bounded response body, omitted for explicit access refusals.
    }
    deriving stock (Eq, Show)

-- | Whether an upstream status explicitly refuses authentication or authorisation.
isAuthorisationFailure :: Int -> Bool
isAuthorisationFailure code = code == 401 || code == 403

-- | The artifact descriptor the mirror publish uses.
data MirrorArtifact = MirrorArtifact
    { maFilename :: Filename
    -- ^ The artifact's on-the-wire filename, the @_attachments@ key in the publish document.
    , maHashes :: NonEmpty Hash
    -- ^ The integrity digests, at least one. The tamper gate verified the fetched bytes against this floor-checked set.
    , maSize :: Maybe Int
    -- ^ The registry-declared size, if reported. Not guaranteed to be the tarball byte count: for npm it is the unpacked-tree size (@dist.unpackedSize@).
    }
    deriving stock (Eq, Show)

-- | The digest value of the first 'Hash' with the given 'HashAlg', or 'Nothing' when the artifact carries none.
firstHashValue :: HashAlg -> MirrorArtifact -> Maybe Text
firstHashValue alg artifact =
    fmap hashValue (find ((== alg) . hashAlg) (maHashes artifact))

-- | Why parsing a 'RegistryResponse' into a domain type failed. The parser reports this value rather than throwing, so the caller decides how to respond to untrusted wire data.
newtype ParseError = ParseError
    { parseErrorMessage :: Text
    -- ^ A human-readable description of what could not be parsed.
    }
    deriving stock (Eq, Show)

-- | Why publishing an artifact to a registry failed, the fault 'Ecluse.Core.Registry.Publish.mpPublishArtifact' reports.
newtype PublishError = PublishError
    { publishErrorMessage :: Text
    -- ^ A human-readable description of why the publish failed.
    }
    deriving stock (Eq, Show)

-- | Why an upstream request URL could not be formed from configuration and a parsed 'Ecluse.Core.Package.PackageName'.
data UrlFormationError
    = -- | The configured base URL is empty, so no request URL can be formed.
      EmptyBaseUrl
    | -- | The formed URL string could not be parsed into a request. Carries the offending URL.
      UnparseableUrl Text
    deriving stock (Eq, Show)

-- | Render a URL formation failure with its URL reduced to an authority, excluding userinfo and queries.
renderUrlFormationError :: UrlFormationError -> Text
renderUrlFormationError = \case
    EmptyBaseUrl -> "EmptyBaseUrl"
    UnparseableUrl url -> "UnparseableUrl " <> authorityLabel url

-- | Why a bounded exchange could not produce a usable response, reported as a value. Total over every exchange the proxy runs: no failure rides up outside this type.
data FetchFault
    = -- | The request URL could not be formed from the base URL and the package identity.
      FetchUrlUnformable UrlFormationError
    | -- | The peer's body crossed the response-size bound, and the read refused it fail-closed.
      FetchBoundExceeded LimitError
    | -- | The request never completed (a timeout, an unreachable peer, a TLS refusal), carried as the 'TransportFault' the adapter edge classified.
      FetchTransport TransportFault
    deriving stock (Eq, Show)

-- | The response from the publication target after relaying a publish document.
data PublishRelayResponse = PublishRelayResponse
    { relayStatus :: Int
    -- ^ The HTTP status code the publication target returned.
    , relayBody :: LByteString
    -- ^ The publication target's response body, relayed to the client unchanged.
    }
    deriving stock (Eq, Show)

-- | Why a publish could not complete, surfaced as a value. The cases differ in retryability, so the worker decides retry against drop by an exhaustive match.
data PublishFault
    = -- | The exchange never produced a status to read, carried as the shared 'FetchFault' so the worker reads one retry-versus-drop table for the write and the artifact fetch.
      PublishFetch FetchFault
    | -- | The registry answered and rejected the write (a non-2xx, non-@409@ status). Retryable.
      PublishRejected PublishError
    deriving stock (Eq, Show)
