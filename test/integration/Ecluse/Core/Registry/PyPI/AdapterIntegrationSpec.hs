-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

-- | Exercise the PyPI adapter through its metadata and artifact routes using local upstreams.
module Ecluse.Core.Registry.PyPI.AdapterIntegrationSpec (spec) where

import Data.Aeson (Value (Array, Object, String), decode, encode, object, (.=))
import Data.Aeson.KeyMap qualified as KeyMap
import Data.ByteString.Lazy qualified as LBS
import Data.List (dropWhileEnd, lookup)
import Data.Text qualified as T
import Data.Time (UTCTime (UTCTime), fromGregorian)
import Network.HTTP.Client (defaultManagerSettings, newManager)
import Network.HTTP.Types (Header, methodGet, methodHead, status200, status401, status403, status404, statusCode)
import Network.Wai (Application, responseLBS)
import Network.Wai qualified as Wai
import Network.Wai.Handler.Warp (testWithApplication)
import Network.Wai.Test (SResponse (simpleBody, simpleHeaders, simpleStatus))
import Test.Hspec

import Ecluse.Core.Ecosystem (Ecosystem (PyPI))
import Ecluse.Core.Rules (prepare)
import Ecluse.Core.Rules.Types (Rule (AllowIfOlderThan))
import Ecluse.Core.Security.Egress (RegistryUrl)
import Ecluse.Core.Security.Egress.DevHttp (loopbackRegistryUrl)
import Ecluse.Core.Server.Context (PackumentDeps (..))
import Ecluse.Core.Server.Response (mkHelpMessage)
import Ecluse.Core.Server.Upstream (MirrorServePlan (NoMirrorWrite))
import Ecluse.Runtime.Server (application, mkServerConfig)
import Ecluse.Server.Pipeline.TestSupport (getPath, getPathWith, newTestEnvWithQueue, postPath, requestAt)
import Ecluse.Service (mountBindingFor)
import Ecluse.Test.Package (hexSha256Of)
import Ecluse.Test.Queue (newTestMemoryQueue)
import Ecluse.Test.Rules (atDefaultPrecedence, inertRuleDeps)
import Ecluse.Test.Server.Mount (pypiServeDeps)
import Ecluse.Test.Wai (localhost, lookupAuth, selfBaseUrl)

spec :: Spec
spec = do
    indexSpec
    artifactSpec
    negotiationSpec
    refusalBodySpec
    privateLegSpec

indexSpec :: Spec
indexSpec = describe "the served Simple index" $ do
    it "serves the PEP 691 JSON form under its own media type" $
        withPyPIProxy publicIndex $ \app -> do
            resp <- getIndex app
            simpleStatus resp `shouldBe` status200
            lookup "Content-Type" (simpleHeaders resp) `shouldBe` Just "application/vnd.pypi.simple.v1+json"

    it "names the surviving releases in the PEP 700 versions array" $
        withPyPIProxy publicIndex $ \app -> do
            resp <- getIndex app
            servedVersions resp `shouldBe` ["2.34.2"]

    it "rebases every served file onto this mount, so the bytes come back through the gate" $
        withPyPIProxy publicIndex $ \app -> do
            resp <- getIndex app
            servedUrls resp
                `shouldBe` [ "http://ecluse.test/pypi/simple/requests/requests-2.34.2-py3-none-any.whl"
                           , "http://ecluse.test/pypi/simple/requests/requests-2.34.2.tar.gz"
                           ]

    it "omits the PEP 658 sidecar keys, because it serves no .metadata companion" $
        withPyPIProxy publicIndex $ \app -> do
            resp <- getIndex app
            servedKeys resp `shouldNotContain` ["core-metadata"]
            servedKeys resp `shouldNotContain` ["data-dist-info-metadata"]

    it "preserves the digest a client verifies the download against" $
        withPyPIProxy publicIndex $ \app -> do
            resp <- getIndex app
            servedDigests resp `shouldBe` [sha256Digest, sha256Digest]

    it "answers the same index with a trailing slash, which the router collapses" $
        withPyPIProxy publicIndex $ \app -> do
            resp <- getPath "/pypi/simple/requests/" app
            simpleStatus resp `shouldBe` status200
            servedVersions resp `shouldBe` ["2.34.2"]

    it "denies a non-canonical project name with the structural 404, never a redirect" $
        withPyPIProxy publicIndex $ \app -> do
            resp <- getPath "/pypi/simple/Requests" app
            simpleStatus resp `shouldBe` status404
            simpleBody resp `shouldBe` ""

artifactSpec :: Spec
artifactSpec = describe "the served distribution file" $ do
    it "streams the bytes at the URL the served index named" $
        withPyPIProxy publicIndex $ \app -> do
            resp <- getPath sdistPath app
            simpleStatus resp `shouldBe` status200
            simpleBody resp `shouldBe` artifactBytes

    it "serves bytes that hash to the sha256 the index advertised for them" $
        -- The index promises a digest and the relay must not decompress or otherwise alter what
        -- it streams, or every client's integrity check would fail on a file Écluse served.
        withPyPIProxy publicIndex $ \app -> do
            index <- getIndex app
            file <- getPath sdistPath app
            servedDigests index `shouldSatisfy` all (== hexSha256Of (LBS.toStrict (simpleBody file)))

    it "denies a file naming another project, which is a path-confusion attempt" $
        withPyPIProxy publicIndex $ \app -> do
            resp <- getPath "/pypi/simple/requests/urllib3-2.0.0.tar.gz" app
            simpleStatus resp `shouldBe` status404

negotiationSpec :: Spec
negotiationSpec = describe "content negotiation, decided from the route record" $ do
    it "serves a client that admits the JSON form" $
        withPyPIProxy publicIndex $ \app -> do
            resp <- getPathWith [("Accept", "application/vnd.pypi.simple.v1+json, text/html;q=0.01")] "/pypi/simple/requests" app
            simpleStatus resp `shouldBe` status200

    it "answers 406 to a client that requires HTML, before any upstream work" $
        withPyPIProxy publicIndex $ \app -> do
            resp <- getPathWith [("Accept", "text/html")] "/pypi/simple/requests" app
            statusOf resp `shouldBe` 406
            simpleBody resp `shouldBe` ""

refusalBodySpec :: Spec
refusalBodySpec = describe "the operator help message on a refusal the route table decides" $ do
    it "carries it on the 406 a client admitting no JSON takes" $
        withHelpfulPyPIProxy $ \app -> do
            resp <- getPathWith [("Accept", "text/html")] "/pypi/simple/requests" app
            statusOf resp `shouldBe` 406
            simpleBody resp `shouldBe` helpBytes

    it "carries it on the 405 an upload takes, because this mount publishes nothing" $ do
        withPyPIProxy publicIndex $ \app -> do
            resp <- postPath "/pypi/legacy" app
            statusOf resp `shouldBe` 405
            simpleBody resp `shouldBe` ""
        withHelpfulPyPIProxy $ \app -> do
            resp <- postPath "/pypi/legacy" app
            statusOf resp `shouldBe` 405
            simpleBody resp `shouldBe` helpBytes

    it "carries it on the structural 404 a path no route claims takes" $
        withHelpfulPyPIProxy $ \app -> do
            resp <- getPath "/pypi/pypi/requests/json" app
            statusOf resp `shouldBe` 404
            simpleBody resp `shouldBe` helpBytes

privateLegSpec :: Spec
privateLegSpec = describe "the private artifact leg, addressed by the index's own location" $ do
    for_ [status401, status403] $ \upstreamStatus ->
        it ("refuses an index HTTP " <> show (statusCode upstreamStatus) <> " on metadata and indexed artifacts") $
            withPyPIProxyResponding (const (\_ respond -> respond (responseLBS upstreamStatus [("WWW-Authenticate", "private-secret")] "private-secret"))) publicIndex privatePypiDeps $ \proxy ->
                for_ ["/pypi/simple/requests", sdistPath] $ \path ->
                    for_ [methodGet, methodHead] $ \method -> do
                        let req = Wai.defaultRequest{Wai.requestHeaders = [clientCredential, ("If-None-Match", "*")]}
                        response <- requestAt method path req (proxyApp proxy)
                        statusOf response `shouldBe` 403
                        lookup "WWW-Authenticate" (simpleHeaders response) `shouldBe` Nothing
                        decodeUtf8 (LBS.toStrict (simpleBody response)) `shouldSatisfy` (not . T.isInfixOf "private-secret")
                        when (method == methodHead) (simpleBody response `shouldBe` "")

    it "resolves the file through the private index and carries the credential there" $
        -- A private index names each file's location itself, so the leg reads that index rather
        -- than probing a conventional path the backend may not spell.
        withPrivatePyPIProxy privateIndexOnItself $ \proxy -> do
            resp <- getPathWith [clientCredential] sdistPath (proxyApp proxy)
            simpleStatus resp `shouldBe` status200
            simpleBody resp `shouldBe` artifactBytes
            hits <- privateHits proxy
            lookup sdistPath hits `shouldBe` Just (Just basicCredential)

    it "drops a file the private index puts on a foreign host, never fetching it" $
        -- The projection and the download gate read one authority definition, so a location the
        -- served listing would not carry is a location this leg does not fetch either.
        withPrivatePyPIProxy (privateIndexOn "http://files.example.invalid") $ \proxy -> do
            resp <- getPathWith [clientCredential] sdistPath (proxyApp proxy)
            statusOf resp `shouldNotBe` 200
            hits <- privateHits proxy
            map fst hits `shouldNotContain` [sdistPath]

-- | Drive the index read a modern resolver makes.
getIndex :: Application -> IO SResponse
getIndex = getPath "/pypi/simple/requests"

-- | The mount-relative path of the source distribution every example asks for.
sdistPath :: ByteString
sdistPath = "/pypi/simple/requests/requests-2.34.2.tar.gz"

-- | Boot the proxy over an in-process PyPI upstream serving the given index as its __public__ one, and the canned artifact bytes for any file path under it.
withPyPIProxy :: (Text -> Value) -> (Application -> IO a) -> IO a
withPyPIProxy indexFor k = withPyPIProxyOver indexFor publicPypiDeps (k . proxyApp)

-- | 'withPyPIProxy' on a mount whose operator configured a help message.
withHelpfulPyPIProxy :: (Application -> IO a) -> IO a
withHelpfulPyPIProxy k =
    withPyPIProxyOver publicIndex helpfulDeps (k . proxyApp)
  where
    helpfulDeps port = (\d -> d{pdHelp = Just (mkHelpMessage helpMessage)}) <$> publicPypiDeps port

-- | Boot the proxy over the same upstream bound as the __private__ one, with a public upstream nothing listens on, so what the client sees is what the private leg did.
withPrivatePyPIProxy :: (Text -> Value) -> (PyPIProxy -> IO a) -> IO a
withPrivatePyPIProxy indexFor = withPyPIProxyOver indexFor privatePypiDeps

-- | A booted proxy, with every request its upstream took and the credential each carried.
data PyPIProxy = PyPIProxy
    { proxyApp :: Application
    -- ^ The proxy under test.
    , privateHits :: IO [(ByteString, Maybe ByteString)]
    -- ^ Each upstream request as its mount-relative path and its @Authorization@ value.
    }

withPyPIProxyOver :: (Text -> Value) -> (Int -> IO PackumentDeps) -> (PyPIProxy -> IO a) -> IO a
withPyPIProxyOver = withPyPIProxyResponding id

withPyPIProxyResponding :: (Application -> Application) -> (Text -> Value) -> (Int -> IO PackumentDeps) -> (PyPIProxy -> IO a) -> IO a
withPyPIProxyResponding transform indexFor depsFor k = do
    queue <- newTestMemoryQueue
    manager <- newManager defaultManagerSettings
    recorded <- newIORef []
    testWithApplication (pure (transform (upstreamApp indexFor (record recorded)))) $ \upstreamPort -> do
        env <- newTestEnvWithQueue queue manager
        deps <- depsFor upstreamPort
        k (PyPIProxy (application (mkServerConfig (maybeToList (mountBindingFor PyPI deps Nothing))) env) (readIORef recorded))
  where
    record ref request =
        atomicModifyIORef' ref (\hits -> (hits <> [(mountPathOf request, lookupAuth (Wai.requestHeaders request))], ()))

    mountPathOf request = "/pypi/" <> encodeUtf8 (T.intercalate "/" (dropWhileEnd T.null (Wai.pathInfo request)))

upstreamApp :: (Text -> Value) -> (Wai.Request -> IO ()) -> Application
upstreamApp indexFor observe request respond = do
    observe request
    case dropWhileEnd T.null (Wai.pathInfo request) of
        -- The index read carries its trailing slash, because a real index redirects a request
        -- without one and no data-plane request follows a redirect.
        ["simple", _project] -> respond (responseLBS status200 [("Content-Type", "application/vnd.pypi.simple.v1+json")] (encode (indexFor (selfBaseUrl request))))
        ["simple", _, _] -> respond (responseLBS status200 [("Content-Type", "application/octet-stream")] artifactBytes)
        _ -> respond (responseLBS status404 [] "")

-- | The mount's serve dependencies over the one upstream bound as the public one.
publicPypiDeps :: Int -> IO PackumentDeps
publicPypiDeps upstreamPort = pypiDeps Nothing (loopbackRegistryUrl (localhost upstreamPort))

-- | The mount's serve dependencies over the one upstream bound as the private one. The public base is a port nothing listens on, so a private miss cannot be covered by a public hit.
privatePypiDeps :: Int -> IO PackumentDeps
privatePypiDeps upstreamPort =
    pypiDeps (Just (loopbackRegistryUrl (localhost upstreamPort))) (loopbackRegistryUrl "http://localhost:1")

-- | The mount's serve dependencies over the given upstreams, with the age quarantine cleared.
pypiDeps :: Maybe RegistryUrl -> RegistryUrl -> IO PackumentDeps
pypiDeps privateBase publicBase = do
    prepared <- prepare inertRuleDeps [atDefaultPrecedence (AllowIfOlderThan 0)]
    pure
        (pypiServeDeps privateBase publicBase NoMirrorWrite prepared (pure servedAt))
            { pdMountBaseUrl = "http://ecluse.test/pypi"
            }

-- | A fixed "now", so the age axis is deterministic.
servedAt :: UTCTime
servedAt = UTCTime (fromGregorian 2026 6 20) 0

-- | The public index: two files of a surviving release, each naming the upstream's own authority, and each carrying both PEP 658 sidecar spellings the served index must drop.
publicIndex :: Text -> Value
publicIndex authority =
    object
        [ "name" .= ("requests" :: Text)
        , "meta" .= object ["api-version" .= ("1.4" :: Text), "_last-serial" .= (37059094 :: Int)]
        , "files" .= map (fileOn authority) ["requests-2.34.2-py3-none-any.whl", "requests-2.34.2.tar.gz"]
        ]

-- | A private index naming its own authority, the shape a self-hosted index publishes.
privateIndexOnItself :: Text -> Value
privateIndexOnItself = publicIndex

-- | A private index naming a files host neither its own authority nor PyPI's declared one.
privateIndexOn :: Text -> Text -> Value
privateIndexOn foreign_ _authority = publicIndex foreign_

fileOn :: Text -> Text -> Value
fileOn authority filename =
    object
        [ "filename" .= filename
        , "url" .= (authority <> "/simple/requests/" <> filename)
        , "hashes" .= object ["sha256" .= sha256Digest]
        , "requires-python" .= (">=3.10" :: Text)
        , "upload-time" .= ("2026-01-01T00:00:00Z" :: Text)
        , "core-metadata" .= object ["sha256" .= sha256Digest]
        , "data-dist-info-metadata" .= object ["sha256" .= sha256Digest]
        ]

-- | The digest the index advertises, which is the one the served bytes hash to.
sha256Digest :: Text
sha256Digest = hexSha256Of (LBS.toStrict artifactBytes)

-- | The bytes the upstream serves for any distribution file.
artifactBytes :: LByteString
artifactBytes = "python distribution bytes"

-- | The credential a pip client presents, and the header value it travels in.
clientCredential :: Header
clientCredential = ("Authorization", basicCredential)

basicCredential :: ByteString
basicCredential = "Basic X190b2tlbl9fOnByaXZhdGUtdG9rZW4="

-- | The message an operator configured, and the body every refusal then carries.
helpMessage :: Text
helpMessage = "ask #platform for access"

helpBytes :: LByteString
helpBytes = LBS.fromStrict (encodeUtf8 helpMessage)

-- | The served index's PEP 700 versions array.
servedVersions :: SResponse -> [Text]
servedVersions resp = case field "versions" resp of
    Just (Array versions) -> [v | String v <- toList versions]
    _ -> []

-- | The locations the served index names, in the order it named them.
servedUrls :: SResponse -> [Text]
servedUrls = mapMaybe (entryText "url") . servedFiles

-- | The digests the served index carries, one per file.
servedDigests :: SResponse -> [Text]
servedDigests = mapMaybe digestOf . servedFiles
  where
    digestOf = \case
        Object entry | Just (Object hashes) <- KeyMap.lookup "hashes" entry -> case KeyMap.lookup "sha256" hashes of
            Just (String digest) -> Just digest
            _ -> Nothing
        _ -> Nothing

-- | Every key the served file entries carry.
servedKeys :: SResponse -> [Text]
servedKeys = concatMap keysOf . servedFiles
  where
    keysOf = \case
        Object entry -> map show (KeyMap.keys entry)
        _ -> []

servedFiles :: SResponse -> [Value]
servedFiles resp = case field "files" resp of
    Just (Array files) -> toList files
    _ -> []

entryText :: Text -> Value -> Maybe Text
entryText key = \case
    Object entry | Just (String value) <- KeyMap.lookup (fromString (toString key)) entry -> Just value
    _ -> Nothing

field :: Text -> SResponse -> Maybe Value
field key resp = case decode (simpleBody resp) of
    Just (Object top) -> KeyMap.lookup (fromString (toString key)) top
    _ -> Nothing

-- | A response's status code, for an example that names the number rather than the constant.
statusOf :: SResponse -> Int
statusOf = statusCode . simpleStatus
