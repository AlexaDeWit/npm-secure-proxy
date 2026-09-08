-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Bounded registry exchanges and their transport-fault classification.
Read exchanges retain explicit access refusals before reading an error body.
-}
module Ecluse.Core.Registry.Exchange (
    -- * The bounded exchange
    boundedExchange,
    boundedFetch,
    boundedRelay,

    -- * Request formation
    formThen,
) where

import Data.ByteString.Lazy qualified as LBS
import Network.HTTP.Client (
    BodyReader,
    Manager,
    Request,
    Response (responseStatus),
    brRead,
    responseBody,
    withResponse,
 )
import Network.HTTP.Types.Status (statusCode)
import UnliftIO (try)

import Ecluse.Core.Fault.Http (classifyTransport)
import Ecluse.Core.Registry (
    FetchFault (FetchBoundExceeded, FetchTransport),
    PublishRelayResponse (..),
    RegistryResponse (RegistryResponse),
    UrlFormationError,
    isAuthorisationFailure,
 )
import Ecluse.Core.Security (LimitError, Limits, boundedRead)

-- | Run a formed request and project its status and bounded body onto the caller's result. The transport wrap covers the body read, so a connection lost mid-body is a typed fault.
boundedExchange :: (Int -> ByteString -> a) -> Manager -> Limits -> Request -> IO (Either FetchFault a)
boundedExchange project manager limits request =
    runExchange manager request (readBounded project limits)

runExchange :: Manager -> Request -> (Response BodyReader -> IO (Either LimitError a)) -> IO (Either FetchFault a)
runExchange manager request readResponse =
    try (withResponse request manager readResponse)
        <&> \case
            Left httpErr -> Left (FetchTransport (classifyTransport httpErr))
            Right (Left limitErr) -> Left (FetchBoundExceeded limitErr)
            Right (Right projected) -> Right projected

-- | Preserve explicit auth refusals without reading their untrusted error bodies.
boundedFetch :: Manager -> Limits -> Request -> IO (Either FetchFault RegistryResponse)
boundedFetch manager limits request = runExchange manager request $ \response ->
    let code = statusCode (responseStatus response)
     in if isAuthorisationFailure code
            then pure (Right (RegistryResponse code ""))
            else readBounded RegistryResponse limits response

-- | The exchange keeping the answered status alongside the body, for the first-party relay.
boundedRelay :: Manager -> Limits -> Request -> IO (Either FetchFault PublishRelayResponse)
boundedRelay =
    boundedExchange $ \status body ->
        PublishRelayResponse{relayStatus = status, relayBody = LBS.fromStrict body}

-- | Run an exchange over a formed request, or fold the formation failure into the same channel, so formation and exchange reach the caller as one 'Either'.
formThen ::
    (UrlFormationError -> fault) ->
    (Request -> IO (Either fault a)) ->
    Either UrlFormationError Request ->
    IO (Either fault a)
formThen unformable = either (pure . Left . unformable)

{- An overstep yields the 'LimitError' as a value, never a truncated body. -}
readBounded :: (Int -> ByteString -> a) -> Limits -> Response BodyReader -> IO (Either LimitError a)
readBounded project limits response =
    fmap (project (statusCode (responseStatus response)))
        <$> boundedRead limits (brRead (responseBody response))
