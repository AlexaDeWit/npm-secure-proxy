-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | PyPI's credential presentation: the HTTP Basic pair a Python client sends on
@Authorization@, recovered here and attached under the same scheme going upstream.

The username is a client-side convention rather than an identity the index checks (@twine@
writes @__token__@, @pip@ takes whatever the URL, @keyring@, or @~\/.netrc@ holds), so the
recovery admits any username and the edge gate compares the password half alone. A credential
Écluse holds rather than receives carries no username and travels under @__token__@. A pair a
client sent travels verbatim, because rewriting a username would authenticate as somebody else.
-}
module Ecluse.Core.Registry.PyPI.Credential (
    pypiCredential,
) where

import Data.ByteArray.Encoding (Base (Base64), convertFromBase, convertToBase)
import Data.Text qualified as T
import Network.HTTP.Types.Header (RequestHeaders, hAuthorization)

import Ecluse.Core.Credential (ClientCredential (ClientCredential, credSecret, credUsername), mkSecret, unSecret)
import Ecluse.Core.Registry.Request (CredentialMapping, credentialMapping)

{- | PyPI's credential mapping: HTTP Basic over @Authorization@ in both directions. The PyPI adapter
registers it on 'Ecluse.Core.Registry.Adapter.Types.serveCredential'.
-}
pypiCredential :: CredentialMapping
pypiCredential = credentialMapping recoverBasic hAuthorization renderBasic

-- The password half may itself carry a colon, so the split takes the first one. Another scheme,
-- undecodable base64, no colon, an empty password, or no header yields 'Nothing'.
recoverBasic :: RequestHeaders -> Maybe ClientCredential
recoverBasic headers = do
    (_, raw) <- find ((== hAuthorization) . fst) headers
    let (scheme, rest) = T.break (== ' ') (decodeUtf8 raw)
    guard (T.toLower scheme == "basic")
    decoded <- decodeBase64 (encodeUtf8 (T.dropWhile (== ' ') rest))
    let (username, afterUser) = T.break (== ':') (decodeUtf8 decoded)
    password <- T.stripPrefix ":" afterUser
    guard (not (T.null password))
    pure (ClientCredential (usernameGiven username) (mkSecret password))

{- The @Authorization@ value carrying a credential under PyPI's Basic scheme. A credential with
no username of its own travels under @__token__@, the name PyPI's tooling writes for a token. -}
renderBasic :: ClientCredential -> ByteString
renderBasic credential =
    "Basic " <> convertToBase Base64 (encodeUtf8 pair :: ByteString)
  where
    pair = fromMaybe tokenUsername (credUsername credential) <> ":" <> unSecret (credSecret credential)

-- The username PyPI's own tooling writes when the password is an API token.
tokenUsername :: Text
tokenUsername = "__token__"

-- An empty username is no username, which is how a client that names none presents itself.
usernameGiven :: Text -> Maybe Text
usernameGiven username = if T.null username then Nothing else Just username

-- Decode the base64 payload of a Basic credential, or 'Nothing' for bytes that are not base64.
decodeBase64 :: ByteString -> Maybe ByteString
decodeBase64 = rightToMaybe . convertFromBase Base64
