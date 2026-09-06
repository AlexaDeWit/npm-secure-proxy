-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Readers for an in-process WAI stub and the responses a proxy serves from it.

The integration pipeline fixture, the publish spec, and the load bench all address
loopback stubs the same way and read the same fields off a served response, so the
readers live here rather than inside one suite's fixture module.
-}
module Ecluse.Test.Wai (
    -- * Addressing an in-process stub
    localhost,
    selfBaseUrl,
    selfBaseUrlOf,
    rebaseAuthority,
    freePort,

    -- * Reading a request
    lookupAuth,
    lookupIfNoneMatch,

    -- * Reading a response
    status,
    reason,
    header,
    decodedBody,
    servedVersions,

    -- * Matching a response body
    bodyContainsAll,
) where

import Data.Aeson (Value (Null, Object), eitherDecodeStrict)
import Data.Aeson.Key qualified as Key
import Data.Aeson.KeyMap qualified as KeyMap
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as LBS
import Data.CaseInsensitive qualified as CI
import Data.List (lookup)
import Data.Text qualified as T
import Network.HTTP.Types (Header, hAuthorization, statusCode, statusMessage)
import Network.HTTP.Types.Header (hHost, hIfNoneMatch)
import Network.Socket (close)
import Network.Wai (Request (requestHeaders))
import Network.Wai.Handler.Warp (Port, openFreePort)
import Network.Wai.Test (SResponse (simpleBody, simpleHeaders, simpleStatus))
import Test.Hspec.Wai.Matcher (MatchBody (MatchBody))
import UnliftIO (bracket)

-- | The base URL of a loopback stub on the given port, by the @localhost@ DNS name.
localhost :: Int -> Text
localhost port = "http://localhost:" <> show port

{- | The base URL a request reached a stub at, from its @Host@ header: the only place the
harness's ephemeral port appears. An absent header falls back to @http:\/\/localhost@.
-}
selfBaseUrl :: Request -> Text
selfBaseUrl = selfBaseUrlOf . requestHeaders

-- | 'selfBaseUrl' over headers alone, for a stub that records what it was sent rather than serving.
selfBaseUrlOf :: [Header] -> Text
selfBaseUrlOf headers = "http://" <> maybe "localhost" decodeUtf8 (lookup hHost headers)

{- | Re-point every location a fixture body names at another authority. A committed fixture names
one fixed host, and an artifact location on any authority but the one that served the document is
dropped at projection, so a stub serving that fixture must first make the locations its own.
-}
rebaseAuthority :: Text -> Text -> LByteString -> LByteString
rebaseAuthority from to = encodeUtf8 . T.replace from to . decodeUtf8

{- | A TCP port nothing holds, released as soon as it is found so the listener under test binds
it itself. A brief race with another process is tolerable on loopback.
-}
freePort :: IO Port
freePort = bracket openFreePort (close . snd) (pure . fst)

-- | The @Authorization@ header value a request carried, if any.
lookupAuth :: [Header] -> Maybe ByteString
lookupAuth = lookup hAuthorization

-- | The @If-None-Match@ header value a request carried, if any.
lookupIfNoneMatch :: [Header] -> Maybe ByteString
lookupIfNoneMatch = lookup hIfNoneMatch

-- | The numeric status of a response.
status :: SResponse -> Int
status = statusCode . simpleStatus

{- | The HTTP reason phrase of a response (e.g. @"Forbidden"@). Reading it forces the status'
lazy message, so an assertion covers the per-status reason mapping, not just the code.
-}
reason :: SResponse -> ByteString
reason = statusMessage . simpleStatus

-- | A response header by name, case-insensitively.
header :: ByteString -> SResponse -> Maybe ByteString
header name resp = lookup (CI.mk name) (simpleHeaders resp)

{- | The decoded JSON body of a response, or 'Null' if it did not decode. A non-JSON body
then surfaces as a plain assertion mismatch, not a crash.
-}
decodedBody :: SResponse -> Value
decodedBody resp = fromRight Null (eitherDecodeStrict (LBS.toStrict (simpleBody resp)))

{- | Match a body that contains every needle. An assertion over a JSON body wants this rather
than a byte-exact match, because @aeson@ promises no key order.
-}
bodyContainsAll :: [ByteString] -> MatchBody
bodyContainsAll needles = MatchBody $ \_ body ->
    case filter (not . (`BS.isInfixOf` LBS.toStrict body)) needles of
        [] -> Nothing
        missing -> Just ("body " <> show body <> " is missing " <> show missing)

-- | The version keys present in a served packument body, sorted.
servedVersions :: SResponse -> [Text]
servedVersions resp = case decodedBody resp of
    Object o -> case KeyMap.lookup "versions" o of
        Just (Object vs) -> sort (map Key.toText (KeyMap.keys vs))
        _ -> []
    _ -> []
