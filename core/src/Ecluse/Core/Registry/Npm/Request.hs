-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Request shaping and URL building for the npm data plane. The ecosystem-agnostic
mechanics (the outbound seal, conditional-GET validators, URL parsing, the path join, the
opaque-artifact request core) live in "Ecluse.Core.Registry.Request". This module holds
only npm's own protocol facts and composes them through that shared home.

Three details of the wire protocol are load-bearing and handled here:

* __Content negotiation__. Metadata comes in two forms selected by @Accept@. The
  __abbreviated__ install view (@application/vnd.npm.install-v1+json@) is the proxy's
  primary view. A rule that reasons over publish age needs the __full__ packument
  (@application/json@), because the abbreviated form drops the @time@ map.
  'MetadataForm' selects between them. Both request @Accept-Encoding: gzip@, because
  popular packuments are megabytes.
* __Scoped-name path encoding__. The wire form of a scoped name @\@scope/name@ is
  @\@scope%2Fname@: the scope separator is percent-encoded, the leading @\@@ is
  not. 'metadataRequest' builds this from an __already-parsed__ 'PackageName',
  never from raw client path segments.
* __Streaming and buffering__. The artifact builders ('artifactRequestByFile',
  'artifactRequestByUrl') mark their request __non-decompressing__. A @.tgz@ is
  opaque binary that reaches the client byte-for-byte, so its @dist.integrity@ stays
  valid. 'artifactRequestByUrl' forms its request through the shared
  'Ecluse.Core.Registry.Request.artifactRequestByUrl', under npm's own credential
  presentation ("Ecluse.Core.Registry.Npm.Credential").
-}
module Ecluse.Core.Registry.Npm.Request (
    -- * Content negotiation
    MetadataForm (..),

    -- * The ecosystem's artifact hosts
    npmArtifactHosts,

    -- * Request building
    metadataRequest,
    artifactRequestByFile,
    artifactRequestByUrl,
    artifactFileUrl,
    packageUrl,

    -- * Shared internals
    withToken,
    parseRequestEither,
) where

import Network.HTTP.Client (Request (decompress, requestHeaders))
import Network.HTTP.Types.Header (hAccept, hAcceptEncoding)

import Ecluse.Core.Credential (Secret)
import Ecluse.Core.Package (PackageName, pkgNamespace, renderPackageName, unScope, unscopedName)
import Ecluse.Core.Registry (UrlFormationError)
import Ecluse.Core.Registry.Npm.Credential (npmCredential)
import Ecluse.Core.Registry.Request (Validators, addValidators, attachCredential, joinPath, parseRequestEither)
import Ecluse.Core.Registry.Request qualified as Request
import Ecluse.Core.Server.Path (encodeComponent)

{- | Which of npm's two metadata documents to request, selected by the @Accept@
header (see 'metadataAccept').
-}
data MetadataForm
    = {- | The install-optimised __abbreviated__ packument
      (@application/vnd.npm.install-v1+json@). Smaller and the proxy's primary
      view, but it drops the @time@ map.
      -}
      Abbreviated
    | {- | The __full__ packument (@application/json@). Larger, but the only form
      carrying the @time@ map a publish-age rule needs.
      -}
      Full
    deriving stock (Eq, Show)

-- The @Accept@ header value selecting a 'MetadataForm'.
metadataAccept :: MetadataForm -> ByteString
metadataAccept = \case
    Abbreviated -> "application/vnd.npm.install-v1+json"
    Full -> "application/json"

{- | npm's canonical artifact hosts: none, because a registry serves its own tarball bytes.
The adapter declares it to the tarball-host gate, and the projection reads the same list, so
an artifact authority has one meaning on both sides.
-}
npmArtifactHosts :: [Text]
npmArtifactHosts = []

{- | Build the metadata @GET@ request for a package at @{baseUrl}/{encoded-name}@.

Fails with a 'UrlFormationError' only when the URL cannot be formed (an empty base URL).
-}
metadataRequest ::
    Text ->
    Maybe Secret ->
    MetadataForm ->
    Validators ->
    PackageName ->
    Either UrlFormationError Request
metadataRequest baseUrl token form validators name = do
    url <- packageUrl baseUrl name
    base <- parseRequestEither url
    pure
        . withToken token
        . addValidators validators
        $ base
            { requestHeaders =
                (hAccept, metadataAccept form)
                    : (hAcceptEncoding, "gzip")
                    : requestHeaders base
            }

{- | Build the artifact @GET@ request at @{baseUrl}/{encoded-pkg}/-/{filename}@, addressing the
tarball by the filename the client requested and never one rebuilt from @(package, version)@, so
a registry with its own tarball naming still resolves. The @filename@ goes in verbatim, because
the classifier already passed it through the component-safety gate.

Fails with a 'UrlFormationError' only when the URL cannot be formed.
-}
artifactRequestByFile ::
    Text ->
    Maybe Secret ->
    PackageName ->
    Text ->
    Either UrlFormationError Request
artifactRequestByFile baseUrl token name filename = do
    url <- artifactFileUrl baseUrl name filename
    base <- parseRequestEither url
    pure
        . withToken token
        $ base
            { -- Never gunzip a tarball in flight: a @.tgz@ is opaque, already-compressed
              -- binary. It advertises no @Accept-Encoding@ either, because an encoding it then
              -- refuses to decode risks a doubly-gzipped body that fails its @dist.integrity@.
              decompress = const False
            }

{- | Build npm's artifact @GET@ request for the absolute @url@ the projection preserved from the
upstream's @dist.tarball@. The location is absolute, so it names no base URL, and it delegates
the credential, non-decompression, and redirect pinning to
'Ecluse.Core.Registry.Request.artifactRequestByUrl'.

Fails with a 'UrlFormationError' only when the @url@ cannot be parsed into a request.
-}
artifactRequestByUrl ::
    Maybe Secret ->
    Text ->
    Either UrlFormationError Request
artifactRequestByUrl = Request.artifactRequestByUrl npmCredential

{- The metadata and publish URL for a package: @{baseUrl}/{encoded-name}@.
-}
packageUrl :: Text -> PackageName -> Either UrlFormationError Text
packageUrl baseUrl name =
    joinPath baseUrl (encodePackagePath name)

{- | The artifact URL @{baseUrl}/{encoded-name}/-/{encoded-filename}@, where @filename@ is the
exact on-the-wire name. It is percent-encoded as a single component
('Ecluse.Core.Server.Route.encodeComponent'), so a once-decoded escape in it cannot reach the
upstream raw.

Fails with a 'UrlFormationError' only when the URL cannot be formed.
-}
artifactFileUrl :: Text -> PackageName -> Text -> Either UrlFormationError Text
artifactFileUrl baseUrl name filename =
    joinPath baseUrl (encodePackagePath name <> "/-/" <> encodeComponent filename)

{- Encode a package name as its on-the-wire path segment: @\@{enc-scope}%2F{enc-base}@ when
scoped, one encoded component otherwise. This builder writes the @\@@ and the @%2F@ itself and
never derives them from a component, and it percent-encodes every component, so a reserved byte
in a decoded name never reaches the upstream URL raw (@%2e%2e%2f@ becomes @%252e%252e%252f@).
-}
encodePackagePath :: PackageName -> Text
encodePackagePath name = case pkgNamespace name of
    Just scope -> "@" <> encodeComponent (unScope scope) <> "%2F" <> encodeComponent (unscopedName name)
    Nothing -> encodeComponent (renderPackageName name)

-- Attach the injected credential under npm's presentation. The redirect pin and the proxy
-- identity belong to Ecluse.Core.Registry.Request, which seals every request it parses.
withToken :: Maybe Secret -> Request -> Request
withToken = attachCredential npmCredential
