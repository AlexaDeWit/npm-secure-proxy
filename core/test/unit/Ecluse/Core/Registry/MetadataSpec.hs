-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Core.Registry.MetadataSpec (spec) where

import Test.Hspec

import Ecluse.Core.Package (PackageName)
import Ecluse.Core.Registry (
    FetchFault (FetchBoundExceeded),
    RegistryResponse (RegistryResponse),
 )
import Ecluse.Core.Registry.Metadata (
    MetadataError (MetadataAuthorisationFailure, MetadataFetch, MetadataUndecodable),
    fetchThenProject,
 )
import Ecluse.Core.Security (LimitError (BodyTooLarge))
import Ecluse.Core.Telemetry.Span (TracingPort (spanMetadataDecode, spanMetadataFetch))
import Ecluse.Test.Package (unscopedNpm)
import Ecluse.Test.Port (passthroughTracingPort)

-- | Exercise error preservation and projection through the adapters' shared read step.
spec :: Spec
spec = describe "fetchThenProject" $ do
    for_ [200, 401, 403] $ \code ->
        it ("traces the requested package and skips decode after access refusal " <> show code) $ do
            events <- newIORef ([] :: [(Text, PackageName)])
            let name = unscopedNpm "left-pad"
                record phase who action = modifyIORef' events (<> [(phase, who)]) >> action
                tracing = passthroughTracingPort{spanMetadataFetch = record "fetch", spanMetadataDecode = record "decode"}
            outcome <- fetchThenProject tracing (const (pure (Right (RegistryResponse code "body")))) name Right
            outcome `shouldBe` if code == 200 then Right "body" else Left (MetadataAuthorisationFailure code)
            readIORef events `shouldReturn` ([("fetch", name)] <> [("decode", name) | code == 200])

    for_ [401, 403] $ \code ->
        it ("retains HTTP " <> show code <> " before projecting a usable body") $
            runStep (Right (RegistryResponse code "usable")) Right
                `shouldReturn` (Left (MetadataAuthorisationFailure code) :: Either MetadataError ByteString)

    for_ [404, 500, 503] $ \code ->
        it ("keeps the existing projection policy for HTTP " <> show code) $
            runStep (Right (RegistryResponse code "body")) Right `shouldReturn` Right "body"

    it "hands the fetched body to the projection" $
        runStep (Right (RegistryResponse 200 "the-body")) Right `shouldReturn` Right "the-body"

    it "folds an exchange fault into MetadataFetch, discarding the projection" $
        runStep (Left bodyTooLarge) (const (Right "projected"))
            `shouldReturn` (Left (MetadataFetch bodyTooLarge) :: Either MetadataError ByteString)

    it "returns a projection refusal as the mount phrased it" $
        runStep (Right (RegistryResponse 200 "junk")) (const (Left MetadataUndecodable))
            `shouldReturn` (Left MetadataUndecodable :: Either MetadataError ByteString)

    it "asks the fetch action for the requested package, once" $ do
        asked <- newIORef ([] :: [PackageName])
        let fetch name = modifyIORef' asked (name :) $> Right (RegistryResponse 200 "b")
        _ <- fetchThenProject passthroughTracingPort fetch (unscopedNpm "left-pad") Right
        readIORef asked `shouldReturn` [unscopedNpm "left-pad"]

bodyTooLarge :: FetchFault
bodyTooLarge = FetchBoundExceeded (BodyTooLarge 12)

-- | Drive one step with a fixed fetch outcome, under a tracing port that opens no span.
runStep ::
    Either FetchFault RegistryResponse ->
    (ByteString -> Either MetadataError a) ->
    IO (Either MetadataError a)
runStep outcome =
    fetchThenProject passthroughTracingPort (const (pure outcome)) (unscopedNpm "left-pad")
