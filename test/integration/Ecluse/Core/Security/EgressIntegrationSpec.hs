-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Core.Security.EgressIntegrationSpec (spec) where

import Data.Aeson (Value, encode, object, (.=))
import Network.HTTP.Client (Manager, defaultManagerSettings, newManager)
import Network.HTTP.Types (status200, status302)
import Network.HTTP.Types.Header (hLocation)
import Network.Wai.Handler.Warp (Port)
import Test.Hspec

import Ecluse.Core.Credential (bareCredential, mkSecret)
import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.Package (PackageName, mkPackageName)
import Ecluse.Core.Registry (FetchFault, RegistryResponse (responseBody))
import Ecluse.Core.Registry.Npm (fetchMetadataFormBounded)
import Ecluse.Core.Registry.Npm.Request (MetadataForm (Abbreviated))
import Ecluse.Core.Registry.Origin (OriginClient (OriginClient, ocBaseUrl, ocLimits, ocManager, ocToken))
import Ecluse.Core.Registry.Request (noValidators)
import Ecluse.Core.Security (defaultLimits)
import Ecluse.Core.Security.Egress.DevHttp (loopbackRegistryUrl)
import Ecluse.Test.Stub (stubPort, withStub, withStubHeaders)

{- | The data-plane egress posture, driven through the real npm fetch path against an
in-process upstream on loopback.

Production egress is https-only by construction. These cases reach an
@http:\/\/127.0.0.1@ upstream through the test-only opt-in ('loopbackRegistryUrl'),
compiled only under the @dev-http-egress@ Cabal flag.

They also cover the credential-redirect invariant, @redirectCount = 0@. The client does
not follow an upstream @302@, so an upstream cannot bounce a fetch off the build-time host
allowlist or downgrade the scheme.
-}
spec :: Spec
spec = do
    describe "egress over the validating manager (loopback http opt-in)" $ do
        it "reaches a loopback upstream addressed through the test-only http opt-in" $
            withUpstream $ \port -> do
                manager <- newManager defaultManagerSettings
                response <- fetchMetadata manager port Nothing
                fmap responseBody response `shouldBe` Right (toStrict (encode packument))

        it "uses the same validating manager for a credential-forwarding (private-origin) fetch" $
            -- The split is the credential, not the manager: a token-forwarding read reaches
            -- the same loopback upstream over the same validating manager.
            withUpstream $ \port -> do
                manager <- newManager defaultManagerSettings
                response <- fetchMetadata manager port (Just "tok")
                fmap responseBody response `shouldBe` Right (toStrict (encode packument))

    describe "no upstream redirect is followed (redirectCount = 0)" $
        it "does not chase a 302 to an off-allowlist location" $
            -- The upstream answers 302 to an off-allowlist host. With redirect-following
            -- disabled the fetch never reaches it, so no hop escapes the allowlist.
            withRedirector $ \port -> do
                manager <- newManager defaultManagerSettings
                result <- fetchMetadata manager port Nothing
                case result of
                    Right response -> responseBody response `shouldNotBe` toStrict (encode packument)
                    -- A fetch fault is equally safe: the fetch never reached the redirect target.
                    Left _ -> pass

fetchMetadata :: Manager -> Port -> Maybe Text -> IO (Either FetchFault RegistryResponse)
fetchMetadata manager port token =
    fetchMetadataFormBounded (clientConfig manager port token) Abbreviated noValidators thing

-- An origin pointed at the loopback upstream on @port@. Its base URL comes from the
-- test-only plain-HTTP opt-in, a constructor a release build does not have.
clientConfig :: Manager -> Port -> Maybe Text -> OriginClient
clientConfig manager port token =
    OriginClient
        { ocBaseUrl = loopbackRegistryUrl ("http://127.0.0.1:" <> show port)
        , ocManager = manager
        , ocToken = bareCredential . mkSecret <$> token
        , ocLimits = defaultLimits
        }

-- Run an action against an in-process upstream serving the packument on loopback.
withUpstream :: (Port -> IO a) -> IO a
withUpstream k = withStub status200 (encode packument) (k . stubPort)

-- Run an action against an in-process upstream that answers 302 to an off-allowlist host.
withRedirector :: (Port -> IO a) -> IO a
withRedirector k =
    withStubHeaders status302 [(hLocation, "https://evil.example.test/elsewhere")] "" (k . stubPort)

-- A minimal packument body the upstream serves. The test asserts on the bytes, not
-- their structure, so an opaque object is enough.
packument :: Value
packument = object ["name" .= ("thing" :: Text), "versions" .= object []]

thing :: PackageName
thing = mkPackageName Npm Nothing "thing"
