-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Request shaping and URL building for the PyPI data plane. The ecosystem-agnostic mechanics
(the outbound seal, the redirect pin, the proxy identity, conditional-GET validators, URL
parsing, the path join, the opaque-artifact request core) live in
"Ecluse.Core.Registry.Request". This module holds only PyPI's own protocol facts and composes
them through that shared home.

Three details of the wire protocol are load-bearing and handled here:

* __Two hosts__. Metadata comes from the index ('simpleIndexRequest'), and public PyPI serves
  the distribution bytes from a separate files host ('pypiArtifactHosts'). A client that
  resolved metadata through Écluse and then pulled bytes straight from that host would bypass
  the gate, so the served index rebases every file URL back onto the mount.

* __The index path carries its trailing slash__. PyPI redirects @\/simple\/{project}@ to
  @\/simple\/{project}\/@, and no data-plane request follows a redirect, so the builder writes
  the slash. The project segment is the PEP 503 canonical name, because a non-canonical
  spelling is a redirect too.

* __Encoding by role__. The index read asks for @gzip@, because a project with thousands of
  files is megabytes. An artifact request advertises no encoding at all and does not
  decompress, so the bytes a client verifies against the served @sha256@ are the bytes that
  arrived.
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
import Ecluse.Core.Registry.Request (Validators, addValidators, attachCredential, joinPath, parseRequestEither)
import Ecluse.Core.Registry.Request qualified as Request
import Ecluse.Core.Server.Path (encodeComponent)

{- | PyPI's canonical artifact hosts. Public PyPI serves distribution bytes from
@files.pythonhosted.org@ rather than the index host, and the adapter declares that to the
artifact-host gate so the secure-default same-host policy admits it without an operator naming
it. A private index that serves its own bytes needs no entry, because its files sit on the
authority that served the index.
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

-- The PEP 691 media type the index read asks for. No HTML form is requested or parsed.
simpleIndexMediaType :: ByteString
simpleIndexMediaType = "application/vnd.pypi.simple.v1+json"

{- | Build the artifact @GET@ at @{baseUrl}\/simple\/{canonical-name}\/{filename}@, the spelling
this mount serves and a private index addresses its own files under.

Fails with a 'UrlFormationError' only when the URL cannot be formed.
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

{- | Build PyPI's artifact @GET@ for the absolute @url@ the projection preserved from the
index's own @files[].url@. The location is absolute, so it names no base URL, and it delegates
the credential, non-decompression, and redirect pinning to
'Ecluse.Core.Registry.Request.artifactRequestByUrl'.

Fails with a 'UrlFormationError' only when the @url@ cannot be parsed into a request.
-}
artifactRequestByUrl ::
    Maybe ClientCredential ->
    Text ->
    Either UrlFormationError Request
artifactRequestByUrl = Request.artifactRequestByUrl pypiCredential

{- | The Simple-index URL @{baseUrl}\/simple\/{canonical-name}\/@. The trailing slash is
written, because the index redirects a request without it and no data-plane request follows a
redirect.
-}
simpleIndexUrl :: Text -> PackageName -> Either UrlFormationError Text
simpleIndexUrl baseUrl name = joinPath baseUrl (projectPath (canonicalName name) <> "/")

{- | The artifact URL @{baseUrl}\/simple\/{canonical-name}\/{encoded-filename}@, where
@filename@ is the exact on-the-wire name. It is percent-encoded as a single component, so a
once-decoded escape in it cannot reach the upstream raw.

Fails with a 'UrlFormationError' only when the URL cannot be formed.
-}
artifactFileUrl :: Text -> PackageName -> Text -> Either UrlFormationError Text
artifactFileUrl baseUrl name filename = joinPath baseUrl (artifactPath (canonicalName name) filename)

{- | The path a distribution file sits at, relative to an index root:
@simple\/{canonical-project}\/{file}@. The upstream read and the served location are formed from
this one spelling, so a rebased URL and the route that must claim it cannot drift. Each
component is percent-encoded, so a reserved byte never reaches a URL raw.
-}
artifactPath :: Text -> Text -> Text
artifactPath project filename = projectPath project <> "/" <> encodeComponent filename

{- The project's index path, @simple\/{canonical-name}@. The canonical spelling is the one the
index serves without a redirect. -}
projectPath :: Text -> Text
projectPath project = "simple/" <> encodeComponent project
