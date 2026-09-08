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
import Ecluse.Test.Package (unscopedNpm)
import Ecluse.Test.Port (passthroughTracingPort)

-- | The fetch-then-project step every mount's read operations share. A mount supplies the fetch action and the projection, so this pins the fold between them.
spec :: Spec
spec = describe "fetchThenProject" $ do
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
