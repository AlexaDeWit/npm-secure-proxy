-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Core.Registry.NpmSpec (spec) where

import Codec.Compression.GZip qualified as GZip
import Data.ByteString qualified as BS
import Network.HTTP.Client (
    HttpException (HttpExceptionRequest, InvalidUrlException),
    HttpExceptionContent (
        ConnectionClosed,
        ConnectionFailure,
        ConnectionTimeout,
        InternalException,
        NoResponseDataReceived,
        ResponseTimeout
    ),
    defaultManagerSettings,
    defaultRequest,
    newManager,
 )
import Network.HTTP.Types.Header (hContentEncoding)
import Network.HTTP.Types.Status (status200, status401, status403, statusCode)
import Network.TLS qualified as TLS
import Test.Hspec (Spec, describe, it, shouldBe, shouldSatisfy)
import UnliftIO (evaluate)

import Ecluse.Core.Fault (
    TransportCause (TransportProtocol, TransportTimeout, TransportTls, TransportUnreachable),
    TransportFault (tfCause),
    transportRetryable,
 )
import Ecluse.Core.Fault.Http (classifyTransport)
import Ecluse.Core.Registry (
    FetchFault (FetchBoundExceeded, FetchTransport, FetchUrlUnformable),
    RegistryResponse (..),
    UrlFormationError (EmptyBaseUrl),
 )

import Ecluse.Core.Registry.Npm (fetchMetadataFormBounded)
import Ecluse.Core.Registry.Npm.Request (MetadataForm (Full))
import Ecluse.Core.Registry.Origin (OriginClient (..))
import Ecluse.Core.Registry.Request (noValidators)
import Ecluse.Core.Security (defaultLimits, maxBodyBytes)
import Ecluse.Core.Security.Egress (mkRegistryUrl, registryUrlText)
import Ecluse.Core.Security.Egress.DevHttp (loopbackRegistryUrl)
import Ecluse.Test.Registry.Npm (defaultNpmConfig, isOdd, publicRegistryBaseUrl)

import Ecluse.Test.Stub (
    stubConfig,
    withStub,
    withStubHeaders,
 )

spec :: Spec
spec = do
    boundedBodySpec
    transportFaultSpec
    configAndWiringSpec

-- | The metadata fetch reads the upstream body through 'boundedRead' against the config's 'ocLimits'.
boundedBodySpec :: Spec
boundedBodySpec = describe "bounded metadata body read" $ do
    for_ [status401, status403] $ \upstreamStatus ->
        it ("retains HTTP " <> show (statusCode upstreamStatus) <> " before an oversized error body") $
            withStub upstreamStatus (toLazy oversizedBody) $ \stub -> do
                base <- stubConfig loopbackRegistryUrl stub
                let config = base{ocLimits = defaultLimits{maxBodyBytes = 64}}
                outcome <- fetchMetadataFormBounded config Full noValidators isOdd
                outcome `shouldBe` Right (RegistryResponse (statusCode upstreamStatus) "")

    it "refuses an over-cap body fail-closed as a FetchBoundExceeded value" $
        withStub status200 (toLazy oversizedBody) $ \stub -> do
            base <- stubConfig loopbackRegistryUrl stub
            let config = base{ocLimits = defaultLimits{maxBodyBytes = 64}}
            outcome <- fetchMetadataFormBounded config Full noValidators isOdd
            outcome `shouldSatisfy` isBoundExceeded

    it "returns a body that is within maxBodyBytes verbatim" $
        -- The read returns a body within the cap whole and unchanged: no false refusal.
        withStub status200 "{\"name\":\"is-odd\"}" $ \stub -> do
            base <- stubConfig loopbackRegistryUrl stub
            let config = base{ocLimits = defaultLimits{maxBodyBytes = 64}}
            resp <- fetchMetadataFormBounded config Full noValidators isOdd
            fmap responseBody resp `shouldBe` Right "{\"name\":\"is-odd\"}"

    it "bounds DECOMPRESSED size: a small gzip body that inflates past the cap is refused" $
        -- The size cap must cover decompressed bytes, including expansion from a gzip bomb.
        withStubHeaders status200 [(hContentEncoding, "gzip")] (toLazy gzippedOversizedBody) $ \stub -> do
            base <- stubConfig loopbackRegistryUrl stub
            let config = base{ocLimits = defaultLimits{maxBodyBytes = 1024}}
            -- Sanity: the compressed body is under the cap, so only the
            -- decompressed-size bound can explain a refusal.
            BS.length gzippedOversizedBody `shouldSatisfy` (< 1024)
            outcome <- fetchMetadataFormBounded config Full noValidators isOdd
            outcome `shouldSatisfy` isBoundExceeded

    it "reports an empty base URL as a FetchUrlUnformable value, never thrown" $ do
        -- The read-path URL-formation fault is a value (mirroring the write path's
        -- PublishFetch), not a thrown UrlFormationError laundered by a broad catch.
        manager <- newManager defaultManagerSettings
        let config = defaultNpmConfig (loopbackRegistryUrl "") manager
        outcome <- fetchMetadataFormBounded config Full noValidators isOdd
        outcome `shouldBe` Left (FetchUrlUnformable EmptyBaseUrl)

-- | 'classifyTransport' folds each @http-client@ exception shape onto the bounded 'TransportCause'.
transportFaultSpec :: Spec
transportFaultSpec = describe "transport faults as values" $ do
    it "classifies timeouts as TransportTimeout" $ do
        causeOf (HttpExceptionRequest defaultRequest ConnectionTimeout) `shouldBe` TransportTimeout
        causeOf (HttpExceptionRequest defaultRequest ResponseTimeout) `shouldBe` TransportTimeout

    it "classifies connection failures and resets as TransportUnreachable" $ do
        causeOf (HttpExceptionRequest defaultRequest (ConnectionFailure (toException FakeInnerFault))) `shouldBe` TransportUnreachable
        causeOf (HttpExceptionRequest defaultRequest ConnectionClosed) `shouldBe` TransportUnreachable
        -- A peer that hung up before the first response byte never reached a protocol
        -- exchange, so it reads as unreachable rather than as a protocol fault.
        causeOf (HttpExceptionRequest defaultRequest NoResponseDataReceived) `shouldBe` TransportUnreachable

    it "classifies a wrapped TLS exception as TransportTls" $ do
        let handshake = toException (TLS.HandshakeFailed (TLS.Error_Misc "handshake refused"))
        causeOf (HttpExceptionRequest defaultRequest (InternalException handshake)) `shouldBe` TransportTls

    it "classifies every other client fault as TransportProtocol" $ do
        -- The closed catch-all keeps the sum total over whatever http-client reports.
        causeOf (HttpExceptionRequest defaultRequest (InternalException (toException FakeInnerFault))) `shouldBe` TransportProtocol
        causeOf (InvalidUrlException "::" "bad") `shouldBe` TransportProtocol

    it "retries a timeout and an unreachable peer, and nothing else" $ do
        -- One table decides transience for every classifyTransport consumer, so no
        -- caller re-derives it from the client library's constructors.
        map transportRetryable [TransportTimeout, TransportUnreachable] `shouldBe` [True, True]
        map transportRetryable [TransportTls, TransportProtocol] `shouldBe` [False, False]

    it "reports a refused connection as a FetchTransport value, never thrown" $ do
        -- Port 1 on the loopback is privileged and unbound, so the kernel refuses the
        -- connect. It is the one live-transport case a unit test can drive determinately.
        manager <- newManager defaultManagerSettings
        let config = defaultNpmConfig (loopbackRegistryUrl "http://127.0.0.1:1") manager
        outcome <- fetchMetadataFormBounded config Full noValidators isOdd
        outcome `shouldSatisfy` isTransportFault
  where
    causeOf = tfCause . classifyTransport

configAndWiringSpec :: Spec
configAndWiringSpec = describe "config wiring" $ do
    it "defaultNpmConfig targets the public registry anonymously over the given manager" $ do
        manager <- newManager defaultManagerSettings
        -- The production https-only former accepts the public registry, so this fixture needs
        -- no loopback opt-in to reach it.
        base <- either (fail . toString) pure (mkRegistryUrl publicRegistryBaseUrl)
        let config = defaultNpmConfig base manager
        registryUrlText (ocBaseUrl config) `shouldBe` publicRegistryBaseUrl
        isJust (ocToken config) `shouldBe` False
        -- The secure-default bounds apply to an anonymous public fetch out of the box. A
        -- deployment overrides them per its budget.
        ocLimits config `shouldBe` defaultLimits
        -- A 'Manager' is opaque (no Eq/Show), so forcing it to WHNF is the
        -- assertion that the field carries the manager we passed, not a bottom.
        _ <- evaluate (ocManager config)
        pure ()

-- A body larger than the tight 64-byte cap the bounded-body test sets.
oversizedBody :: ByteString
oversizedBody = "{\"name\":\"is-odd\",\"_padding\":\"" <> BS.replicate 256 0x78 <> "\"}"

-- | A gzip body that decompresses to about 64 KiB, far past the 1 KiB cap the gzip test sets, while its compressed size stays well under that cap.
gzippedOversizedBody :: ByteString
gzippedOversizedBody =
    toStrict (GZip.compress (toLazy ("{\"name\":\"is-odd\",\"_padding\":\"" <> BS.replicate 65536 0x78 <> "\"}")))

-- | A typed stand-in for a client library's wrapped inner exception. The classification must read the wrapper's type, TLS or not, never the inner rendering.
data FakeInnerFault = FakeInnerFault
    deriving stock (Show)

instance Exception FakeInnerFault

-- | Whether a bounded fetch returned the response-bound breach as a value.
isBoundExceeded :: Either FetchFault RegistryResponse -> Bool
isBoundExceeded = \case
    Left (FetchBoundExceeded _) -> True
    _ -> False

-- | Whether a bounded fetch returned a transport failure as a value.
isTransportFault :: Either FetchFault RegistryResponse -> Bool
isTransportFault = \case
    Left (FetchTransport _) -> True
    _ -> False
