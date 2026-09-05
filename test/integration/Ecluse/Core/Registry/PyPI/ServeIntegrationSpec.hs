-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The PyPI serve path end to end, through the real composition of route table, projection,
gate, merge, assembly, and relay, over in-process upstreams on loopback ports.

The tier is integration rather than unit because the path needs live upstreams to fetch from:
the ports are what make the artifact-host gate's authority comparison real rather than a
fixture. Nothing here starts a container.

What a client actually does with the served index, that a resolver reads it and installs from
the locations it names, is the end-to-end tier's, and #1092's `pip install` case belongs there.
These examples pin what the proxy serves.
-}
module Ecluse.Core.Registry.PyPI.ServeIntegrationSpec (spec) where

import Data.Aeson (Value (Array, Object, String), decode, encode, object, (.=))
import Data.Aeson.KeyMap qualified as KeyMap
import Data.List (dropWhileEnd, lookup)
import Data.Text qualified as T
import Data.Time (UTCTime (UTCTime), fromGregorian)
import Network.HTTP.Client (defaultManagerSettings, newManager)
import Network.HTTP.Types (status200, status404, statusCode)
import Network.Wai (Application, responseLBS)
import Network.Wai qualified as Wai
import Network.Wai.Handler.Warp (testWithApplication)
import Network.Wai.Test (SResponse (simpleBody, simpleHeaders, simpleStatus))
import Test.Hspec

import Ecluse.Core.Ecosystem (Ecosystem (PyPI))
import Ecluse.Core.Rules (prepare)
import Ecluse.Core.Rules.Types (Rule (AllowIfOlderThan))
import Ecluse.Core.Security.Egress.DevHttp (loopbackRegistryUrl)
import Ecluse.Core.Server.Context (PackumentDeps (..))
import Ecluse.Core.Server.Upstream (MirrorServePlan (NoMirrorWrite))
import Ecluse.Runtime.Server (application, mkServerConfig)
import Ecluse.Server.Pipeline.TestSupport (getPath, getPathWith, newTestEnvWithQueue)
import Ecluse.Service (mountBindingFor)
import Ecluse.Test.Queue (newTestMemoryQueue)
import Ecluse.Test.Rules (atDefaultPrecedence, inertRuleDeps)
import Ecluse.Test.Server.Mount (pypiServeDeps)
import Ecluse.Test.Wai (localhost)

spec :: Spec
spec = do
    indexSpec
    artifactSpec
    negotiationSpec

indexSpec :: Spec
indexSpec = describe "the served Simple index" $ do
    it "serves the PEP 691 JSON form under its own media type" $
        withPyPIProxy publicIndex artifactBytes $ \app -> do
            resp <- getIndex app
            simpleStatus resp `shouldBe` status200
            lookup "Content-Type" (simpleHeaders resp) `shouldBe` Just "application/vnd.pypi.simple.v1+json"

    it "names the surviving releases in the PEP 700 versions array" $
        withPyPIProxy publicIndex artifactBytes $ \app -> do
            resp <- getIndex app
            servedVersions resp `shouldBe` ["2.34.2"]

    it "rebases every served file onto this mount, so the bytes come back through the gate" $
        withPyPIProxy publicIndex artifactBytes $ \app -> do
            resp <- getIndex app
            servedUrls resp
                `shouldBe` [ "http://ecluse.test/pypi/simple/requests/requests-2.34.2-py3-none-any.whl"
                           , "http://ecluse.test/pypi/simple/requests/requests-2.34.2.tar.gz"
                           ]

    it "omits the PEP 658 sidecar keys, because it serves no .metadata companion" $
        withPyPIProxy publicIndex artifactBytes $ \app -> do
            resp <- getIndex app
            servedKeys resp `shouldNotContain` ["core-metadata"]
            servedKeys resp `shouldNotContain` ["data-dist-info-metadata"]

    it "preserves the digest a client verifies the download against" $
        withPyPIProxy publicIndex artifactBytes $ \app -> do
            resp <- getIndex app
            servedDigests resp `shouldBe` [sha256Digest, sha256Digest]

    it "answers the same index with a trailing slash, which the router collapses" $
        withPyPIProxy publicIndex artifactBytes $ \app -> do
            resp <- getPath "/pypi/simple/requests/" app
            simpleStatus resp `shouldBe` status200
            servedVersions resp `shouldBe` ["2.34.2"]

    it "denies a non-canonical project name with the structural 404, never a redirect" $
        withPyPIProxy publicIndex artifactBytes $ \app -> do
            resp <- getPath "/pypi/simple/Requests" app
            simpleStatus resp `shouldBe` status404
            simpleBody resp `shouldBe` ""

artifactSpec :: Spec
artifactSpec = describe "the served distribution file" $ do
    it "streams the bytes at the URL the served index named" $
        withPyPIProxy publicIndex artifactBytes $ \app -> do
            resp <- getPath "/pypi/simple/requests/requests-2.34.2.tar.gz" app
            simpleStatus resp `shouldBe` status200
            simpleBody resp `shouldBe` artifactBytes

    it "denies a file naming another project, which is a path-confusion attempt" $
        withPyPIProxy publicIndex artifactBytes $ \app -> do
            resp <- getPath "/pypi/simple/requests/urllib3-2.0.0.tar.gz" app
            simpleStatus resp `shouldBe` status404

negotiationSpec :: Spec
negotiationSpec = describe "content negotiation, decided from the route record" $ do
    it "serves a client that admits the JSON form" $
        withPyPIProxy publicIndex artifactBytes $ \app -> do
            resp <- getPathWith [("Accept", "application/vnd.pypi.simple.v1+json, text/html;q=0.01")] "/pypi/simple/requests" app
            simpleStatus resp `shouldBe` status200

    it "answers 406 to a client that requires HTML, before any upstream work" $
        withPyPIProxy publicIndex artifactBytes $ \app -> do
            resp <- getPathWith [("Accept", "text/html")] "/pypi/simple/requests" app
            statusOf resp `shouldBe` 406
            simpleBody resp `shouldBe` ""

-- | Drive the index read a modern resolver makes.
getIndex :: Application -> IO SResponse
getIndex = getPath "/pypi/simple/requests"

{- | Boot the proxy over an in-process PyPI upstream serving the given index, and an artifact
host serving the given bytes for any file path.
-}
withPyPIProxy :: (Text -> Value) -> LByteString -> (Application -> IO a) -> IO a
withPyPIProxy indexFor bytes k = do
    queue <- newTestMemoryQueue
    manager <- newManager defaultManagerSettings
    testWithApplication (pure (upstreamApp indexFor bytes)) $ \publicPort -> do
        env <- newTestEnvWithQueue queue manager
        deps <- pypiDeps publicPort
        k (application (mkServerConfig (maybeToList (mountBindingFor PyPI deps Nothing))) env)

{- The upstream double: a Simple index under @\\/simple\\/{project}@ whose file locations name
this same authority, and the canned bytes for any file under it. One authority answers both, as
a private index does and as the artifact-host gate requires of any upstream with no declared
files host. -}
upstreamApp :: (Text -> Value) -> LByteString -> Application
upstreamApp indexFor bytes request respond = case dropWhileEnd T.null (Wai.pathInfo request) of
    -- The index read carries its trailing slash, because a real index redirects a request
    -- without one and no data-plane request follows a redirect.
    ["simple", _project] -> respond (responseLBS status200 [("Content-Type", "application/vnd.pypi.simple.v1+json")] (encode (indexFor (authorityOf request))))
    ["simple", _, _] -> respond (responseLBS status200 [("Content-Type", "application/octet-stream")] bytes)
    _ -> respond (responseLBS status404 [] "")
  where
    authorityOf req = "http://" <> maybe "127.0.0.1" decodeUtf8 (Wai.requestHeaderHost req)

-- | The mount's serve dependencies over the one upstream port, with the age quarantine cleared.
pypiDeps :: Int -> IO PackumentDeps
pypiDeps publicPort = do
    prepared <- prepare inertRuleDeps [atDefaultPrecedence (AllowIfOlderThan 0)]
    pure
        (pypiServeDeps Nothing (loopbackRegistryUrl (localhost publicPort)) NoMirrorWrite prepared (pure servedAt))
            { pdMountBaseUrl = "http://ecluse.test/pypi"
            }

-- | A fixed "now", so the age axis is deterministic.
servedAt :: UTCTime
servedAt = UTCTime (fromGregorian 2026 6 20) 0

{- | The public index: two files of a surviving release, each naming the upstream's own
authority, and each carrying both PEP 658 sidecar spellings the served index must drop.
-}
publicIndex :: Text -> Value
publicIndex authority =
    object
        [ "name" .= ("requests" :: Text)
        , "meta" .= object ["api-version" .= ("1.4" :: Text), "_last-serial" .= (37059094 :: Int)]
        , "files" .= map (fileOn authority) ["requests-2.34.2-py3-none-any.whl", "requests-2.34.2.tar.gz"]
        ]

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

-- | The digest the index advertises and a client verifies the download against.
sha256Digest :: Text
sha256Digest = T.replicate 64 "a"

-- | The bytes the upstream serves for any distribution file.
artifactBytes :: LByteString
artifactBytes = "python distribution bytes"

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
