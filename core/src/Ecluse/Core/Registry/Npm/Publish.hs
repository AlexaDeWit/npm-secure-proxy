-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The npm publish-document schema, in two halves. The mirror-write side is
document assembly, request shaping, and the codec that carries them into the shared
publish transport. The read side is 'declaredNames': the identity names the
ecosystem-neutral publish pipeline's anti-shadowing guard reads from a first-party
publish body.

Everything here is pure. 'npmPublishCodec' is npm's
'Ecluse.Core.Registry.Publish.PublishCodec'. The composition root marries it to the
shared transport ('Ecluse.Core.Registry.Publish.newMirrorPublish'), which executes
what this module forms. The first-party publish relay (a different concern: a
client's own document forwarded verbatim) lives in "Ecluse.Core.Registry.Npm".
-}
module Ecluse.Core.Registry.Npm.Publish (
    npmPublishCodec,
    publishRequest,
    npmPublishDocument,
    declaredNames,
    npmPublishAllowed,
) where

import Data.Aeson (Value (String), object, (.=))
import Data.Aeson qualified as Aeson
import Data.Aeson.Key qualified as Key
import Data.Aeson.KeyMap qualified as KeyMap
import Data.ByteArray.Encoding (Base (Base64), convertToBase)
import Data.ByteString qualified as BS

import Lens.Micro ((^?))
import Lens.Micro.Aeson (key, _Object)
import Network.HTTP.Client (Request (method, requestBody, requestHeaders), RequestBody (RequestBodyBS))
import Network.HTTP.Types.Header (hAccept, hContentType)

import Ecluse.Core.Credential (ClientCredential, bareCredential)
import Ecluse.Core.Package (HashAlg (SHA1, SRI), PackageName, Scope, pkgNamespace, renderPackageName)
import Ecluse.Core.Registry (
    MirrorArtifact (maFilename),
    PublishError (PublishError),
    PublishFault (PublishRejected),
    UrlFormationError,
    firstHashValue,
 )
import Ecluse.Core.Registry.Npm.Project qualified as Project
import Ecluse.Core.Registry.Npm.Request (MetadataForm (Abbreviated), metadataRequest, packageUrl, parseRequestEither, withToken)
import Ecluse.Core.Registry.Publish (PublishCodec (..))
import Ecluse.Core.Registry.Request (noValidators)
import Ecluse.Core.Server.Path (unFilename)
import Ecluse.Core.Version (Version, renderVersion)

{- | npm's mirror-write protocol codec. The probe reads the abbreviated packument, and the
publish @PUT@s a single-version packument fragment carrying the artifact's verified digests.
-}
npmPublishCodec :: PublishCodec
npmPublishCodec =
    PublishCodec
        { pcProbeRequest = \targetUrl token -> metadataRequest targetUrl (bareCredential <$> token) Abbreviated noValidators
        , pcParseVersionList = Project.parseVersionList
        , pcPublishRequest = \targetUrl token name version artifact bytes ->
            publishRequest
                targetUrl
                (bareCredential <$> token)
                name
                (npmPublishDocument name version (unFilename (maFilename artifact)) (firstHashValue SRI artifact) (firstHashValue SHA1 artifact) bytes)
        , pcPublishOutcome = classifyPublish
        }

classifyPublish :: Int -> Either PublishFault ()
classifyPublish code
    | code >= 200 && code < 300 = Right ()
    | code == 409 = Right () -- version already present, immutable, so success-equivalent
    | otherwise =
        Left (PublishRejected (PublishError ("publish failed with HTTP status " <> show code)))

{- | Build the publish @PUT /{pkg}@ request from the already-serialised npm publish document,
carrying the bearer token. Fails with a 'UrlFormationError' only when the URL cannot be formed,
never for a write fault, which 'Ecluse.Core.Registry.publishArtifact' reports.
-}
publishRequest ::
    Text ->
    Maybe ClientCredential ->
    PackageName ->
    ByteString ->
    Either UrlFormationError Request
publishRequest baseUrl credential name document = do
    url <- packageUrl baseUrl name
    base <- parseRequestEither url
    pure
        . withToken credential
        $ base
            { method = "PUT"
            , requestBody = RequestBodyBS document
            , -- A spec-compliant registry (e.g. Verdaccio) answers @415@ to a publish
              -- whose body is not declared @application/json@, and the npm publish
              -- protocol requires it. Accept is set too, for the registry's response.
              requestHeaders =
                (hContentType, "application/json")
                    : (hAccept, "application/json")
                    : requestHeaders base
            }

{- | Assemble the npm publish document for one version from its verified tarball bytes.
The @dist@ digests are the caller's verified ones, so the manifest matches the attached bytes.
A managed registry recomputes the served @dist.tarball@, so @dist@ carries only the filename.
-}
npmPublishDocument ::
    -- | The package being published.
    PackageName ->
    -- | The version being published.
    Version ->
    -- | The tarball's filename: the @_attachments@ key and tarball file segment.
    Text ->
    -- | The @dist.integrity@ SRI string, if known (e.g. @"sha512-…"@).
    Maybe Text ->
    -- | The @dist.shasum@ (SHA-1, hex), if known.
    Maybe Text ->
    -- | The verified tarball bytes.
    ByteString ->
    ByteString
npmPublishDocument name version filename integrity shasum tarball =
    toStrict . Aeson.encode $
        object
            [ "_id" .= rendered
            , "name" .= rendered
            , "dist-tags" .= object ["latest" .= versionText]
            , "versions" .= object [Key.fromText versionText .= manifest]
            , "_attachments" .= object [Key.fromText filename .= attachmentObject tarball]
            ]
  where
    versionText = renderVersion version
    rendered = renderPackageName name
    manifest = versionManifestObject rendered versionText (distObject filename integrity shasum)

-- The one-version manifest under @versions.{version}@: the package name, the
-- version, and its @dist@ descriptor.
versionManifestObject :: Text -> Text -> Aeson.Value -> Aeson.Value
versionManifestObject rendered versionText dist =
    object
        [ "name" .= rendered
        , "version" .= versionText
        , "dist" .= dist
        ]

-- The manifest's @dist@ descriptor: the tarball filename plus whichever of the caller's
-- verified digests are known, never a fabricated one.
distObject :: Text -> Maybe Text -> Maybe Text -> Aeson.Value
distObject filename integrity shasum =
    object
        ( ["tarball" .= filename]
            <> maybe [] (\i -> ["integrity" .= i]) integrity
            <> maybe [] (\s -> ["shasum" .= s]) shasum
        )

-- The @_attachments@ entry for the tarball, with the @length@ taken from the
-- actual byte count.
attachmentObject :: ByteString -> Aeson.Value
attachmentObject tarball =
    object
        [ "content_type" .= ("application/octet-stream" :: Text)
        , "data" .= encodedTarball
        , "length" .= BS.length tarball
        ]
  where
    -- The npm attachment carries the raw tarball bytes, standard-base64-encoded.
    encodedTarball :: Text
    encodedTarball = decodeUtf8 (convertToBase Base64 tarball :: ByteString)

{- | Every package name a first-party npm publish body declares as its own identity: @_id@,
@name@, and each @versions.\<v\>.name@. A body that does not decode declares nothing.

The publish pipeline's anti-shadowing guard checks these names, so a crafted body cannot claim
a package the scope guard never authorised.
-}
declaredNames :: LByteString -> [Text]
declaredNames body =
    [ declared
    | document <- maybeToList (Aeson.decode body :: Maybe Value)
    , slot <-
        [document ^? key "_id", document ^? key "name"]
            <> [ versionDoc ^? key "name"
               | versions <- maybeToList (document ^? key "versions" . _Object)
               , versionDoc <- KeyMap.elems versions
               ]
    , Just (String declared) <- [slot]
    ]

{- | Whether npm's first-party namespaces cover a name: its scope must equal a configured entry
exactly, so an unscoped name and @\@acme-evil@ against an @\@acme@ entry are both refused.
-}
npmPublishAllowed :: [Scope] -> PackageName -> Bool
npmPublishAllowed scopes name = case pkgNamespace name of
    Just scope -> scope `elem` scopes
    Nothing -> False
