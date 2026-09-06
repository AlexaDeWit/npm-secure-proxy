-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Core.Registry.PyPI.RequestSpec (spec) where

import Data.List (lookup)
import Network.HTTP.Client qualified as Client
import Test.Hspec

import Ecluse.Core.BuildIdentity (userAgent)
import Ecluse.Core.Credential (ClientCredential (ClientCredential), mkSecret)
import Ecluse.Core.Ecosystem (Ecosystem (PyPI))
import Ecluse.Core.Package (PackageName, mkPackageName)
import Ecluse.Core.Registry (UrlFormationError (EmptyBaseUrl))
import Ecluse.Core.Registry.PyPI.Request (
    artifactFileUrl,
    artifactRequestByFile,
    artifactRequestByUrl,
    pypiArtifactHosts,
    simpleIndexRequest,
    simpleIndexUrl,
 )
import Ecluse.Core.Registry.Request (noValidators)

spec :: Spec
spec = do
    indexSpec
    artifactSpec
    filesHostSpec
    sealSpec

indexSpec :: Spec
indexSpec = describe "the Simple-index read" $ do
    it "addresses the project under /simple/ with its trailing slash, which the index would redirect to" $
        simpleIndexUrl "https://pypi.org" requests `shouldBe` Right "https://pypi.org/simple/requests/"

    it "normalises the project name to its PEP 503 canonical spelling, which needs no redirect" $
        simpleIndexUrl "https://pypi.org" zopeInterface `shouldBe` Right "https://pypi.org/simple/zope-interface/"

    it "joins onto a base URL that writes its own trailing slash" $
        simpleIndexUrl "https://index.test/pypi/" requests `shouldBe` Right "https://index.test/pypi/simple/requests/"

    it "refuses an empty base URL rather than forming a relative request" $
        simpleIndexUrl "" requests `shouldBe` Left EmptyBaseUrl

    it "asks for the PEP 691 JSON form and no HTML one" $ do
        req <- formed (simpleIndexRequest "https://pypi.org" Nothing noValidators requests)
        lookup "Accept" (Client.requestHeaders req) `shouldBe` Just "application/vnd.pypi.simple.v1+json"

    it "asks for gzip, because a project's index runs to megabytes" $ do
        req <- formed (simpleIndexRequest "https://pypi.org" Nothing noValidators requests)
        lookup "Accept-Encoding" (Client.requestHeaders req) `shouldBe` Just "gzip"

    it "attaches the caller's pair on the passthrough read" $ do
        req <- formed (simpleIndexRequest "https://index.test" alicePair noValidators requests)
        lookup "Authorization" (Client.requestHeaders req) `shouldBe` Just "Basic YWxpY2U6aHVudGVyMg=="

    it "sends no credential header on an anonymous read" $ do
        req <- formed (simpleIndexRequest "https://pypi.org" Nothing noValidators requests)
        lookup "Authorization" (Client.requestHeaders req) `shouldBe` Nothing

artifactSpec :: Spec
artifactSpec = describe "the artifact read" $ do
    it "addresses a file under the one spelling this mount serves" $
        artifactFileUrl "https://index.test" requests "requests-2.34.2-py3-none-any.whl"
            `shouldBe` Right "https://index.test/simple/requests/requests-2.34.2-py3-none-any.whl"

    it "percent-encodes the file name, so a decoded escape cannot reach the upstream raw" $
        artifactFileUrl "https://index.test" requests "a/../b.whl"
            `shouldBe` Right "https://index.test/simple/requests/a%2F..%2Fb.whl"

    it "advertises no encoding and does not decompress, so the served sha256 verifies" $ do
        req <- formed (artifactRequestByFile "https://index.test" Nothing requests "requests-2.34.2.tar.gz")
        Client.decompress req "application/gzip" `shouldBe` False
        Client.requestHeaders req `shouldNotSatisfy` any ((== "accept-encoding") . fst)

    it "fetches an absolute file location without naming a base URL" $ do
        req <- formed (artifactRequestByUrl Nothing "https://files.pythonhosted.org/packages/a0/requests-2.34.2.tar.gz")
        Client.host req `shouldBe` "files.pythonhosted.org"
        Client.path req `shouldBe` "/packages/a0/requests-2.34.2.tar.gz"
        Client.decompress req "application/gzip" `shouldBe` False

    it "carries the mount credential on a by-URL fetch that names one" $ do
        req <- formed (artifactRequestByUrl alicePair "https://index.test/packages/requests-2.34.2.tar.gz")
        lookup "Authorization" (Client.requestHeaders req) `shouldBe` Just "Basic YWxpY2U6aHVudGVyMg=="

    it "fetches anonymously when the caller names no credential" $ do
        req <- formed (artifactRequestByUrl Nothing "https://files.pythonhosted.org/packages/a0/requests-2.34.2.tar.gz")
        lookup "Authorization" (Client.requestHeaders req) `shouldBe` Nothing

filesHostSpec :: Spec
filesHostSpec =
    describe "the declared artifact host" $
        it "names the files host public PyPI serves distribution bytes from" $
            pypiArtifactHosts `shouldBe` ["https://files.pythonhosted.org"]

sealSpec :: Spec
sealSpec = describe "every request carries the shared outbound seal" $ do
    it "pins the redirect count on the index read, credentialed or not" $ do
        anonymous <- formed (simpleIndexRequest "https://pypi.org" Nothing noValidators requests)
        Client.redirectCount anonymous `shouldBe` 0
        credentialed <- formed (simpleIndexRequest "https://index.test" alicePair noValidators requests)
        Client.redirectCount credentialed `shouldBe` 0

    it "pins the redirect count on both artifact arms" $ do
        byFile <- formed (artifactRequestByFile "https://index.test" alicePair requests "requests-2.34.2.tar.gz")
        Client.redirectCount byFile `shouldBe` 0
        byUrl <- formed (artifactRequestByUrl alicePair "https://index.test/packages/requests-2.34.2.tar.gz")
        Client.redirectCount byUrl `shouldBe` 0

    it "identifies the proxy without spelling a User-Agent of its own" $ do
        req <- formed (simpleIndexRequest "https://pypi.org" Nothing noValidators requests)
        lookup "User-Agent" (Client.requestHeaders req) `shouldBe` Just userAgent

-- | The project every example reads.
requests :: PackageName
requests = mkPackageName PyPI Nothing "requests"

-- | A project whose published spelling is not its canonical one.
zopeInterface :: PackageName
zopeInterface = mkPackageName PyPI Nothing "Zope.Interface"

-- | The Basic pair a passthrough read carries.
alicePair :: Maybe ClientCredential
alicePair = Just (ClientCredential (Just "alice") (mkSecret "hunter2"))

-- | Unwrap a request the example expects to form.
formed :: Either UrlFormationError Client.Request -> IO Client.Request
formed = either (fail . show) pure
