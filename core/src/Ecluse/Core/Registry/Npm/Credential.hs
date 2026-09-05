-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | npm's credential presentation: the @Bearer@ token an npm client presents on
@Authorization@. This module recovers that token from the headers a client sends, and
attaches it under the same scheme to a request Écluse makes upstream.

The npm CLI turns an @.npmrc@ @\/\/host\/:_authToken=…@ entry into
@Authorization: Bearer …@. A mount serving npm therefore accepts that one form at its
edge, and presents that one form to an npm upstream. One 'CredentialMapping' declares
both directions, so the token text recovered from a client and the header it travels on
upstream cannot drift apart.
-}
module Ecluse.Core.Registry.Npm.Credential (
    npmCredential,
) where

import Data.Text qualified as T
import Network.HTTP.Types.Header (RequestHeaders, hAuthorization)

import Ecluse.Core.Credential (ClientCredential (credSecret), bareCredential, mkSecret, unSecret)
import Ecluse.Core.Registry.Request (CredentialMapping, credentialMapping)

{- | npm's credential mapping: @Bearer@ over @Authorization@ in both directions. The npm
adapter registers it on 'Ecluse.Core.Registry.Adapter.Types.serveCredential'.
-}
npmCredential :: CredentialMapping
npmCredential = credentialMapping recoverBearer hAuthorization renderBearer

{- The client's bearer credential from @Authorization: Bearer …@, the token text alone. npm's
scheme carries no username, so the recovered pair has none. Any other presentation yields
'Nothing': another scheme, a bare or empty token, no header. -}
recoverBearer :: RequestHeaders -> Maybe ClientCredential
recoverBearer headers = do
    (_, raw) <- find ((== hAuthorization) . fst) headers
    let value = decodeUtf8 raw
        (scheme, rest) = T.break (== ' ') value
    guard (T.toLower scheme == "bearer")
    let token = T.dropWhile (== ' ') rest
    guard (not (T.null token))
    pure (bareCredential (mkSecret token))

-- The @Authorization@ value carrying a credential under npm's @Bearer@ scheme, whose
-- grammar has no username slot to render.
renderBearer :: ClientCredential -> ByteString
renderBearer credential = "Bearer " <> encodeUtf8 (unSecret (credSecret credential))
