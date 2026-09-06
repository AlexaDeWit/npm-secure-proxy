-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Core.Registry.Npm.RequestSpec (spec) where

import Data.ByteString qualified as BS
import Data.List (lookup)
import Network.HTTP.Client qualified as Client
import Network.HTTP.Types.Status (status200)
import Test.Hspec (
    Spec,
    around,
    describe,
    it,
    shouldBe,
    shouldNotSatisfy,
    shouldSatisfy,
 )

import Ecluse.Core.Credential (bareCredential, mkSecret)
import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.Package (PackageName, mkPackageName, mkScope)
import Ecluse.Core.Registry (UrlFormationError (EmptyBaseUrl, UnparseableUrl))

import Ecluse.Core.Registry.Npm.Publish (publishRequest)
import Ecluse.Core.Registry.Npm.Request (
    MetadataForm (Abbreviated, Full),
    artifactFileUrl,
    artifactRequestByFile,
    artifactRequestByUrl,
    metadataRequest,
 )
import Ecluse.Core.Registry.Request (Validators (..), noValidators)

import Ecluse.Test.Registry.Npm (isOdd)
import Ecluse.Test.Stub (
    stubBaseUrl,
    withStub,
 )

spec :: Spec
spec = do
    requestShapingSpec
    contentNegotiationSpec
    pathEncodingSpec
    authSpec
    redirectSpec
    artifactSpec
    urlFailureSpec

requestShapingSpec :: Spec
requestShapingSpec =
    around (withStub status200 "{}") $
        describe "fetchMetadata request shaping" $ do
            it "relays conditional-GET validators when present" $ \stub -> do
                let validators =
                        Validators
                            { validatorIfNoneMatch = Just "\"etag-123\""
                            , validatorIfModifiedSince = Just "Wed, 21 Oct 2015 07:28:00 GMT"
                            }
                let req = metadataRequest (stubBaseUrl stub) Nothing Abbreviated validators isOdd
                case req of
                    Right r -> do
                        let hs = Client.requestHeaders r
                        lookup "If-None-Match" hs `shouldBe` Just "\"etag-123\""
                        lookup "If-Modified-Since" hs `shouldBe` Just "Wed, 21 Oct 2015 07:28:00 GMT"
                    Left e -> fail (show e)

            it "sends no conditional-GET validators by default" $ \stub -> do
                let req = metadataRequest (stubBaseUrl stub) Nothing Abbreviated noValidators isOdd
                case req of
                    Right r -> do
                        let hs = Client.requestHeaders r
                        lookup "If-None-Match" hs `shouldBe` Nothing
                        lookup "If-Modified-Since" hs `shouldBe` Nothing
                    Left e -> fail (show e)

pathEncodingSpec :: Spec
pathEncodingSpec =
    describe "scoped-package path encoding" $ do
        it "percent-encodes the scope separator of a scoped name (@scope%2Fname)" $ do
            case metadataRequest "https://reg.test" Nothing Abbreviated noValidators babelCodeFrame of
                Right r -> Client.path r `shouldBe` "/@babel%2Fcode-frame"
                Left e -> fail (show e)

        it "leaves an unscoped name unencoded" $ do
            case metadataRequest "https://reg.test" Nothing Abbreviated noValidators isOdd of
                Right r -> Client.path r `shouldBe` "/is-odd"
                Left e -> fail (show e)

        it "does not encode the leading @ of a scoped name" $ do
            case metadataRequest "https://reg.test" Nothing Abbreviated noValidators babelCodeFrame of
                Right r -> BS.isPrefixOf "/@babel" (Client.path r) `shouldBe` True
                Left e -> fail (show e)

        it "re-encodes a literal '%' in a once-decoded name so a live escape never reaches the upstream" $ do
            case metadataRequest "https://reg.test" Nothing Abbreviated noValidators onceDecodedTraversal of
                Right r -> Client.path r `shouldBe` "/foo%252e%252e%252fbar"
                Left e -> fail (show e)

contentNegotiationSpec :: Spec
contentNegotiationSpec =
    describe "metadata content negotiation" $ do
        -- The two @Accept@ values are npm's wire contract. The abbreviated install view is
        -- the primary one, and only the full packument carries the @time@ map a publish-age
        -- rule reads.
        it "asks for the abbreviated install view" $
            acceptHeaderOf Abbreviated `shouldBe` Just "application/vnd.npm.install-v1+json"

        it "asks for the full packument" $
            acceptHeaderOf Full `shouldBe` Just "application/json"
  where
    acceptHeaderOf :: MetadataForm -> Maybe ByteString
    acceptHeaderOf form =
        case metadataRequest "https://reg.test" Nothing form noValidators isOdd of
            Right r -> lookup "Accept" (Client.requestHeaders r)
            -- An unformable URL fails the assertion rather than throwing.
            Left _ -> Nothing

authSpec :: Spec
authSpec =
    describe "bearer-token attachment" $ do
        it "attaches an injected token as a Bearer Authorization header" $ do
            let token = Just (bareCredential (mkSecret "tok-abc"))
            case metadataRequest "https://reg.test" token Abbreviated noValidators isOdd of
                Right r -> lookup "Authorization" (Client.requestHeaders r) `shouldBe` Just "Bearer tok-abc"
                Left e -> fail (show e)

        it "sends no Authorization header when no token is injected" $ do
            case metadataRequest "https://reg.test" Nothing Abbreviated noValidators isOdd of
                Right r -> lookup "Authorization" (Client.requestHeaders r) `shouldBe` Nothing
                Left e -> fail (show e)

redirectSpec :: Spec
redirectSpec = describe "no data-plane request follows an upstream redirect" $ do
    it "a token-bearing metadata request has redirectCount 0" $ do
        expectRedirectCount 0 (metadataRequest "https://reg.test" (Just (bareCredential (mkSecret "tok"))) Abbreviated noValidators isOdd)

    it "a credential-less metadata request also disables redirect following (0)" $ do
        expectRedirectCount 0 (metadataRequest "https://reg.test" Nothing Abbreviated noValidators isOdd)

    it "a token-bearing by-filename artifact request has redirectCount 0 (the private tarball leg)" $ do
        expectRedirectCount 0 (artifactRequestByFile "https://reg.test" (Just (bareCredential (mkSecret "tok"))) isOdd "is-odd-1.0.0.tgz")

    it "a token-bearing publish relay request has redirectCount 0" $ do
        expectRedirectCount 0 (publishRequest "https://reg.test" (Just (bareCredential (mkSecret "tok"))) isOdd "{}")
  where
    expectRedirectCount :: Int -> Either UrlFormationError Client.Request -> IO ()
    expectRedirectCount want = \case
        Left err -> fail ("request building failed: " <> show err)
        Right req -> Client.redirectCount req `shouldBe` want

artifactSpec :: Spec
artifactSpec = describe "artifact request building" $ do
    it "artifactRequestByFile fetches by the preserved filename, non-decompressing" $ do
        case artifactRequestByFile "https://reg.test" Nothing babelCodeFrame "code-frame-7.0.0.tgz" of
            Left err -> fail ("artifactRequestByFile failed: " <> show err)
            Right req -> do
                Client.path req `shouldBe` "/@babel%2Fcode-frame/-/code-frame-7.0.0.tgz"
                Client.decompress req "application/gzip" `shouldBe` False
                Client.requestHeaders req `shouldNotSatisfy` any ((== "accept-encoding") . fst)

    it "artifactFileUrl builds the preserved-filename URL under the package /-/ path" $ do
        artifactFileUrl "https://reg.test" babelCodeFrame "code-frame-7.0.0.tgz"
            `shouldBe` Right "https://reg.test/@babel%2Fcode-frame/-/code-frame-7.0.0.tgz"

    it "artifactRequestByUrl composes npm's bearer attach through the shared builder" $ do
        case artifactRequestByUrl (Just (bareCredential (mkSecret "tok-xyz"))) "https://private.reg/files/thing.tgz" of
            Left err -> fail ("artifactRequestByUrl failed: " <> show err)
            Right req ->
                lookup "Authorization" (Client.requestHeaders req)
                    `shouldBe` Just "Bearer tok-xyz"

urlFailureSpec :: Spec
urlFailureSpec = describe "URL-formation failures" $ do
    it "metadataRequest refuses an empty base URL as a UrlFormationError, not a publish error" $ do
        metadataRequest "" Nothing Abbreviated noValidators isOdd `shouldSatisfy` urlErrorWas EmptyBaseUrl

    it "artifactRequestByFile refuses an empty base URL as a UrlFormationError" $ do
        artifactRequestByFile "" Nothing isOdd "is-odd-1.0.0.tgz" `shouldSatisfy` urlErrorWas EmptyBaseUrl

    it "artifactFileUrl refuses an empty base URL as a UrlFormationError" $ do
        artifactFileUrl "" isOdd "is-odd-1.0.0.tgz" `shouldSatisfy` urlErrorWas EmptyBaseUrl

    it "publishRequest refuses an empty base URL as a UrlFormationError" $ do
        publishRequest "" Nothing isOdd "{}" `shouldSatisfy` urlErrorWas EmptyBaseUrl

    it "reports a non-empty but unparseable base URL as UnparseableUrl" $ do
        metadataRequest "not a url" Nothing Abbreviated noValidators isOdd `shouldSatisfy` isUnparseable

    it "builds a metadata request against a well-formed base URL" $ do
        metadataRequest "https://reg.test/" Nothing Abbreviated noValidators isOdd `shouldNotSatisfy` isLeft

babelCodeFrame :: PackageName
babelCodeFrame = mkPackageName Npm (Just (mkScope "babel")) "code-frame"

onceDecodedTraversal :: PackageName
onceDecodedTraversal = mkPackageName Npm Nothing "foo%2e%2e%2fbar"

urlErrorWas :: UrlFormationError -> Either UrlFormationError a -> Bool
urlErrorWas expected = either (== expected) (const False)

isUnparseable :: Either UrlFormationError a -> Bool
isUnparseable = either matchUnparseable (const False)
  where
    matchUnparseable (UnparseableUrl _) = True
    matchUnparseable _ = False
