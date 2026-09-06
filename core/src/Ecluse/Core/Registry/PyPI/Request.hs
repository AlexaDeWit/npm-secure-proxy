-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | PyPI's own request facts, composed through the agnostic mechanics in
"Ecluse.Core.Registry.Request" (the outbound seal, the redirect pin, the identity, validators).

Three protocol details are load-bearing. Metadata comes from the index and public PyPI serves
distribution bytes from a separate files host, so the served index rebases every file URL back
onto the mount. The index path carries its trailing slash, and its project segment the PEP 503
canonical name, because PyPI redirects both and no data-plane request follows a redirect. The
index read asks for @gzip@ and an artifact request advertises no encoding at all, so the bytes
a client verifies against the served @sha256@ are the bytes that arrived.
-}
module Ecluse.Core.Registry.PyPI.Request (
    -- * The ecosystem's artifact hosts
    pypiArtifactHosts,

    -- * Request building
    simpleIndexRequest,
    artifactRequestByFile,
    artifactRequestByUrl,

    -- * URL building
    simpleIndexUrl,
    artifactFileUrl,
    artifactPath,
) where

import Network.HTTP.Client (Request (decompress, requestHeaders))
import Network.HTTP.Types.Header (hAccept, hAcceptEncoding)

import Ecluse.Core.Credential (ClientCredential)
import Ecluse.Core.Package (PackageName)
import Ecluse.Core.Registry (UrlFormationError)
import Ecluse.Core.Registry.PyPI.Credential (pypiCredential)
import Ecluse.Core.Registry.PyPI.Project (canonicalName)
import Ecluse.Core.Registry.PyPI.Wire (simpleIndexMediaType)
import Ecluse.Core.Registry.Request (Validators, addValidators, attachCredential, joinPath, parseRequestEither)
import Ecluse.Core.Registry.Request qualified as Request
import Ecluse.Core.Server.Path (encodeComponent)

{- | PyPI's canonical artifact hosts, declared to the artifact-host gate so the same-host default
admits the files host without an operator naming it.
-}
pypiArtifactHosts :: [Text]
pypiArtifactHosts = ["https://files.pythonhosted.org"]

{- | Build the Simple-index @GET@ for a project at @{baseUrl}\/simple\/{canonical-name}\/@.

Fails with a 'UrlFormationError' only when the URL cannot be formed (an empty base URL).
-}
simpleIndexRequest ::
    Text ->
    Maybe ClientCredential ->
    Validators ->
    PackageName ->
    Either UrlFormationError Request
simpleIndexRequest baseUrl credential validators name = do
    url <- simpleIndexUrl baseUrl name
    base <- parseRequestEither url
    pure
        . attachCredential pypiCredential credential
        . addValidators validators
        $ base
            { requestHeaders =
                (hAccept, simpleIndexMediaType)
                    : (hAcceptEncoding, "gzip")
                    : requestHeaders base
            }

{- | Build the artifact @GET@ at @{baseUrl}\/simple\/{canonical-name}\/{filename}@, the spelling
this mount serves and a private index addresses its own files under.
-}
artifactRequestByFile ::
    Text ->
    Maybe ClientCredential ->
    PackageName ->
    Text ->
    Either UrlFormationError Request
artifactRequestByFile baseUrl credential name filename = do
    url <- artifactFileUrl baseUrl name filename
    base <- parseRequestEither url
    pure
        . attachCredential pypiCredential credential
        $ base{decompress = const False}

{- | Build PyPI's artifact @GET@ for the absolute @url@ the projection preserved from the index's
own @files[].url@, so it names no base URL of its own.
-}
artifactRequestByUrl ::
    Maybe ClientCredential ->
    Text ->
    Either UrlFormationError Request
artifactRequestByUrl = Request.artifactRequestByUrl pypiCredential

{- | The Simple-index URL @{baseUrl}\/simple\/{canonical-name}\/@, whose trailing slash is written
because the index redirects a request without it.
-}
simpleIndexUrl :: Text -> PackageName -> Either UrlFormationError Text
simpleIndexUrl baseUrl name = joinPath baseUrl (projectPath (canonicalName name) <> "/")

{- | The artifact URL @{baseUrl}\/simple\/{canonical-name}\/{encoded-filename}@, the exact
on-the-wire name encoded as one component so a decoded escape cannot reach upstream raw.
-}
artifactFileUrl :: Text -> PackageName -> Text -> Either UrlFormationError Text
artifactFileUrl baseUrl name filename = joinPath baseUrl (artifactPath (canonicalName name) filename)

{- | @simple\/{canonical-project}\/{file}@, relative to an index root. The upstream read and the
served location are formed from this one spelling, each component percent-encoded.
-}
artifactPath :: Text -> Text -> Text
artifactPath project filename = projectPath project <> "/" <> encodeComponent filename

{- The project's index path, @simple\/{canonical-name}@. The canonical spelling is the one the
index serves without a redirect. -}
projectPath :: Text -> Text
projectPath project = "simple/" <> encodeComponent project
