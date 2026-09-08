-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Artifact names and URL-component encoding shared by ecosystem routers.
"Ecluse.Core.Text" owns the component gate also used by outbound metadata.
-}
module Ecluse.Core.Server.Path (
    -- * The artifact name
    Filename,
    mkFilename,
    unFilename,

    -- * Component safety
    isSafeComponent,
    encodeComponent,
) where

import Network.HTTP.Types.URI (urlEncode)

import Ecluse.Core.Text (isSafeComponent)

{- | An artifact's on-the-wire file name, verbatim and safe to interpolate: it cleared
'isSafeComponent'. The upstream path uses this exact name, never one rebuilt from the version.
-}
newtype Filename = Filename Text
    deriving stock (Eq, Show)

{- | Read a filename from untrusted text, 'Nothing' when it is not a safe path component. Every
boundary that admits one (a route capture, a queue payload) parses through this single gate.
-}
mkFilename :: Text -> Maybe Filename
mkFilename raw
    | isSafeComponent raw = Just (Filename raw)
    | otherwise = Nothing

-- | The verbatim name, for interpolation into an upstream URL through 'encodeComponent'.
unFilename :: Filename -> Text
unFilename (Filename name) = name

{- | Encode a decoded component using only RFC 3986 unreserved bytes verbatim.
Encoding is not idempotent: a literal percent sign becomes @%25@.
-}
encodeComponent :: Text -> Text
-- 'urlEncode' in query-string mode (True), not the path mode http-types recommends: path mode
-- passes ':@&=+$,' through unencoded, which a component must not carry.
encodeComponent = decodeUtf8 . urlEncode True . encodeUtf8
