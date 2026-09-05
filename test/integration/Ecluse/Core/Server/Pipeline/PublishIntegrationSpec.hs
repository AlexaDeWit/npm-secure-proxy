-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Core.Server.Pipeline.PublishIntegrationSpec (spec) where

import Data.ByteString.Lazy qualified as LBS
import Data.Text qualified as T
import Network.HTTP.Types (hAuthorization, hContentType, methodPut, mkStatus)
import Network.Wai (
    Application,
    Request (requestBodyLength, requestHeaders, requestMethod),
    RequestBodyLength (ChunkedBody, KnownLength),
    consumeRequestBodyStrict,
    responseLBS,
 )
import Network.Wai.Handler.Warp (testWithApplication)
import Network.Wai.Test (
    SRequest (SRequest),
    SResponse (simpleBody),
    defaultRequest,
    runSession,
    setPath,
    srequest,
 )
import Test.Hspec
import UnliftIO (async, wait)
import UnliftIO.Concurrent (threadDelay)

import Ecluse (mountBindingFor)
import Ecluse.Core.Credential (Secret, mkSecret)
import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.Package (mkScope)
import Ecluse.Core.Registry.Adapter.Types (RegistryAdapter (adapterProjectName, adapterPublish))
import Ecluse.Core.Registry.Npm.Adapter (npmAdapter)
import Ecluse.Core.Registry.Npm.Publish qualified as NpmPublish
import Ecluse.Core.Security (defaultLimits)
import Ecluse.Core.Security.Egress.DevHttp (loopbackRegistryUrl)
import Ecluse.Core.Server.Admission.Bytes (ByteAdmission, newByteAdmission, newByteAdmissionTuned)
import Ecluse.Core.Server.Context (PublishDeps (..))
import Ecluse.Runtime.Server (application, mkServerConfig)
import Ecluse.Runtime.Test.Support (newTestEnv)
import Ecluse.Test.Server.Mount (inertPackumentDeps)
import Ecluse.Test.Stub (Captured (capBody), Stub, allCaptured, headerValue, stubPort, withStubHeaders)
import Ecluse.Test.Wai (status)

{- | Host a publication-target stub answering every publish with @code@ and @body@. The
continuation gets the port to point the proxy at, and the stub to inspect what it saw.
-}
withTarget :: Int -> LByteString -> (Int -> Stub -> IO a) -> IO a
withTarget code body k =
    withStubHeaders (mkStatus code "OK") [(hContentType, "application/json")] body $ \stub ->
        k (stubPort stub) stub

-- The (Authorization, body) pairs the publication target saw, in arrival order.
targetSaw :: Stub -> IO [(Maybe ByteString, ByteString)]
targetSaw stub = map (\cap -> (headerValue "Authorization" cap, capBody cap)) <$> allCaptured stub

{- | Publish dependencies pointing at the loopback target, allowing the @\@acme@ scope.
The relay forwards 'pubStaticToken' only when the client sends no token of its own.
-}
publishDepsAt :: Int -> Maybe Secret -> ByteAdmission -> PublishDeps
publishDepsAt targetPort staticToken bodyBudget =
    PublishDeps
        { pubTargetUrl = loopbackRegistryUrl ("http://127.0.0.1:" <> show targetPort)
        , pubAllowed = NpmPublish.npmPublishAllowed [mkScope "acme"]
        , pubStaticToken = staticToken
        , pubInboundToken = Nothing
        , pubLimits = defaultLimits
        , pubBodyBudget = bodyBudget
        , pubMaxRequestBytes = 26214400
        , pubHelp = Nothing
        , pubProjectName = adapterProjectName npmAdapter
        , pubAdapter = adapterPublish npmAdapter
        }

{- | A proxy 'Application' over a single @\/npm@ mount carrying the given publish deps.
'Nothing' leaves the publish path off, so the route answers @405@.
-}
proxyOver :: Maybe PublishDeps -> IO Application
proxyOver publishDeps = do
    env <- newTestEnv
    let cfg = mkServerConfig (maybeToList (mountBindingFor Npm inertPackumentDeps publishDeps))
    pure (application cfg env)

-- | 'proxyOver' for deps that still need the standard aggregate body budget.
proxyWith :: Maybe (ByteAdmission -> PublishDeps) -> IO Application
proxyWith mkPublishDeps =
    forM mkPublishDeps (\mk -> mk <$> newByteAdmission (128 * 1024 * 1024)) >>= proxyOver

{- | A proxy whose publish path caps the request body at @cap@ bytes ('pubMaxRequestBytes').
The cap fires before the relay, so the target port is an unconnectable placeholder.
-}
cappedProxyWith :: Int -> IO Application
cappedProxyWith cap =
    proxyWith (Just (\bodyBudget -> (publishDepsAt 1 Nothing bodyBudget){pubMaxRequestBytes = cap}))

-- | A @PUT \/npm\/{path}@ chunked publish carrying the given bearer (if any) and body.
putPublish :: ByteString -> Maybe Text -> LByteString -> Application -> IO SResponse
putPublish = putPublishAs ChunkedBody

{- | Like 'putPublish' but the request declares its length ('KnownLength'), so the
publish route's up-front Content-Length cap check sees it rather than the chunked path.
-}
putPublishKnownLength :: ByteString -> Maybe Text -> LByteString -> Application -> IO SResponse
putPublishKnownLength path bearer body =
    putPublishAs (KnownLength (fromIntegral (LBS.length body))) path bearer body

-- The shared @PUT \/npm\/{path}@ driver, over a given declared body length.
putPublishAs :: RequestBodyLength -> ByteString -> Maybe Text -> LByteString -> Application -> IO SResponse
putPublishAs bodyLen path bearer body =
    runSession (srequest (SRequest req body))
  where
    req =
        (setPath defaultRequest{requestMethod = methodPut, requestHeaders = auth} path)
            { requestBodyLength = bodyLen
            }
    auth = maybe [] (\t -> [(hAuthorization, "Bearer " <> encodeUtf8 t)]) bearer

-- A representative npm publish document body whose declared identity (@_id@,
-- top-level @name@) agrees with the @\@acme\/widget@ URL the tests publish to.
publishBody :: LByteString
publishBody = "{\"_id\":\"@acme/widget\",\"name\":\"@acme/widget\",\"versions\":{}}"

-- A legitimate npm client's shape: @_id@, top-level @name@, and the one @versions[].name@
-- all agree with the @\@acme\/widget@ URL, so the agreement check must still relay it.
matchingVersionBody :: LByteString
matchingVersionBody =
    "{\"_id\":\"@acme/widget\",\"name\":\"@acme/widget\",\"versions\":{\"1.0.0\":{\"name\":\"@acme/widget\",\"version\":\"1.0.0\"}}}"

-- Publish documents whose declared identity disagrees with the in-scope URL name
-- @\@acme\/widget@ on one field: the anti-shadowing bypass a crafted body attempts.
mismatchedIdBody :: LByteString
mismatchedIdBody =
    "{\"_id\":\"@victim/target\",\"name\":\"@acme/widget\",\"versions\":{}}"

mismatchedNameBody :: LByteString
mismatchedNameBody =
    "{\"_id\":\"@acme/widget\",\"name\":\"@victim/target\",\"versions\":{}}"

mismatchedVersionNameBody :: LByteString
mismatchedVersionNameBody =
    "{\"_id\":\"@acme/widget\",\"name\":\"@acme/widget\",\"versions\":{\"1.0.0\":{\"name\":\"@victim/target\",\"version\":\"1.0.0\"}}}"

spec :: Spec
spec = describe "first-party publish path → publication target (S52)" $ do
    it "503s a publish shed at the aggregate body-byte budget while the capacity is held" $ do
        -- A target that parks the first publish while it holds the whole budget. With zero
        -- waiter room the second sheds at the door, and the first completes once released.
        gate <- newEmptyMVar
        arrived <- newIORef (0 :: Int)
        let blockingApp req respond = do
                _ <- consumeRequestBodyStrict req
                modifyIORef' arrived (+ 1)
                takeMVar gate
                respond (responseLBS (mkStatus 201 "OK") [(hContentType, "application/json")] "{}")
        testWithApplication (pure blockingApp) $ \targetPort -> do
            tightBudget <- newByteAdmissionTuned 1 0 50_000
            app <- proxyOver (Just (publishDepsAt targetPort Nothing tightBudget))
            firstPublish <- async (putPublish "/npm/@acme/widget" (Just "publisher-token") publishBody app)
            -- Wait until the first publish holds the budget (its body reached the
            -- parked target), so the second genuinely contends.
            let awaitHold (n :: Int) = do
                    held <- readIORef arrived
                    when (held == 0 && n > 0) (threadDelay 10_000 >> awaitHold (n - 1))
            awaitHold 500
            secondPublish <- putPublish "/npm/@acme/widget" (Just "publisher-token") publishBody app
            status secondPublish `shouldBe` 503
            putMVar gate ()
            wait firstPublish >>= \firstResp -> status firstResp `shouldBe` 201

    it "answers an over-cap chunked publish with the documented 413, not the perimeter's neutral 500 (issue #849)" $ do
        -- A chunked body declares no length, so the counted bounded read enforces the cap as a
        -- value: a fail-closed 413, never a throw through the perimeter's neutral 500.
        app <- cappedProxyWith 8
        resp <- putPublish "/npm/@acme/widget" (Just "publisher-token") publishBody app
        status resp `shouldBe` 413

    it "answers an over-cap known-length publish with the documented 413 (Content-Length fast-fail)" $ do
        -- A declared Content-Length over the cap fails closed before the route reads a byte.
        -- Both over-cap shapes render the same 413 through the route contract.
        app <- cappedProxyWith 8
        resp <- putPublishKnownLength "/npm/@acme/widget" (Just "publisher-token") publishBody app
        status resp `shouldBe` 413

    it "relays an in-scope publish with the publisher's forwarded credential and returns the target's response" $
        withTarget 201 "{\"success\":true}" $ \targetPort target -> do
            app <- proxyWith (Just (publishDepsAt targetPort Nothing))
            resp <- putPublish "/npm/@acme/widget" (Just "publisher-token") publishBody app
            -- the proxy relays back the publication target's own success status and body
            status resp `shouldBe` 201
            simpleBody resp `shouldBe` "{\"success\":true}"
            -- the target saw the publisher's OWN token (passthrough), and the body verbatim
            seen <- targetSaw target
            seen `shouldBe` [(Just "Bearer publisher-token", LBS.toStrict publishBody)]

    it "forwards the static ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__REGISTRY__TOKEN only when the client sends no token of its own" $
        withTarget 201 "{\"success\":true}" $ \targetPort target -> do
            app <- proxyWith (Just (publishDepsAt targetPort (Just (mkSecret "fallback-token"))))
            resp <- putPublish "/npm/@acme/widget" Nothing publishBody app
            status resp `shouldBe` 201
            seen <- targetSaw target
            -- no client token, so the relay forwards the configured static fallback
            map fst seen `shouldBe` [Just "Bearer fallback-token"]

    it "refuses an out-of-scope publish with 403 BEFORE any upstream write (anti-shadowing guard)" $
        withTarget 201 "{\"success\":true}" $ \targetPort target -> do
            app <- proxyWith (Just (publishDepsAt targetPort Nothing))
            resp <- putPublish "/npm/@other/widget" (Just "publisher-token") publishBody app
            status resp `shouldBe` 403
            -- the guard fired before the relay, so the proxy never contacted the target
            targetSaw target `shouldReturn` []

    it "refuses an unscoped publish with 403 (an unscoped name is within no scope)" $
        withTarget 201 "{\"success\":true}" $ \targetPort target -> do
            app <- proxyWith (Just (publishDepsAt targetPort Nothing))
            resp <- putPublish "/npm/widget" (Just "publisher-token") publishBody app
            status resp `shouldBe` 403
            targetSaw target `shouldReturn` []

    it "refuses a scope that only prefixes an allowed one (@acme-evil vs the allowed @acme) -- exact match" $
        withTarget 201 "{\"success\":true}" $ \targetPort target -> do
            -- The guard compares scopes exactly, so it never admits a look-alike scope
            -- by prefix. The proxy never contacts the publication target.
            app <- proxyWith (Just (publishDepsAt targetPort Nothing))
            resp <- putPublish "/npm/@acme-evil/widget" (Just "publisher-token") publishBody app
            status resp `shouldBe` 403
            targetSaw target `shouldReturn` []

    it "sends NO Authorization header to the target for a fully anonymous in-scope publish (no client token, no static fallback)" $
        withTarget 201 "{\"success\":true}" $ \targetPort target -> do
            app <- proxyWith (Just (publishDepsAt targetPort Nothing))
            resp <- putPublish "/npm/@acme/widget" Nothing publishBody app
            status resp `shouldBe` 201
            -- passthrough with no client token and no static fallback, so the relay
            -- carries no credential at all
            seen <- targetSaw target
            map fst seen `shouldBe` [Nothing]

    it "405s a publish when no publication target is configured (the opt-in is off)" $
        withTarget 201 "{\"success\":true}" $ \_targetPort target -> do
            app <- proxyWith Nothing
            resp <- putPublish "/npm/@acme/widget" (Just "publisher-token") publishBody app
            status resp `shouldBe` 405
            -- The refusal names the missing setting and the publisher's way forward, in
            -- terms no one ecosystem's client owns.
            let body = decodeUtf8 (LBS.toStrict (simpleBody resp)) :: Text
            body `shouldSatisfy` T.isInfixOf "no publication target is configured"
            body `shouldSatisfy` T.isInfixOf "publish directly to the registry you intend to publish to"
            targetSaw target `shouldReturn` []

    it "relays the publication target's own error status (e.g. a 409 the registry returns) to the client" $
        withTarget 409 "{\"error\":\"version already exists\"}" $ \targetPort _target -> do
            app <- proxyWith (Just (publishDepsAt targetPort Nothing))
            resp <- putPublish "/npm/@acme/widget" (Just "publisher-token") publishBody app
            -- a first-party publisher sees the registry's real 409, not a fabricated success
            status resp `shouldBe` 409
            simpleBody resp `shouldBe` "{\"error\":\"version already exists\"}"

    -- An unformable target URL is this proxy's own misconfiguration (500). A target that
    -- never answers is an upstream outage (502). Both legs of that split are pinned here.
    it "500s a publish whose publication target URL cannot be formed (a misconfiguration, not an outage)" $ do
        app <- proxyWith (Just (\budget -> (publishDepsAt 1 Nothing budget){pubTargetUrl = loopbackRegistryUrl ""}))
        resp <- putPublish "/npm/@acme/widget" (Just "publisher-token") publishBody app
        status resp `shouldBe` 500

    it "502s a publish the publication target never answers (an outage, not a misconfiguration)" $ do
        -- Port 1 is an unconnectable placeholder, so the relay reports a transport fault.
        app <- proxyWith (Just (publishDepsAt 1 Nothing))
        resp <- putPublish "/npm/@acme/widget" (Just "publisher-token") publishBody app
        status resp `shouldBe` 502

    -- An in-scope URL whose body declares a different package would publish a name the scope
    -- guard never authorised, so the guard checks @_id@, @name@, and @versions[].name@ first.
    it "refuses a publish whose body _id disagrees with the in-scope URL name (403 before any relay)" $
        withTarget 201 "{\"success\":true}" $ \targetPort target -> do
            app <- proxyWith (Just (publishDepsAt targetPort Nothing))
            resp <- putPublish "/npm/@acme/widget" (Just "publisher-token") mismatchedIdBody app
            status resp `shouldBe` 403
            -- the agreement check fired before the relay, so nothing reached the target
            targetSaw target `shouldReturn` []

    it "refuses a publish whose body top-level name disagrees with the in-scope URL name (403 before any relay)" $
        withTarget 201 "{\"success\":true}" $ \targetPort target -> do
            app <- proxyWith (Just (publishDepsAt targetPort Nothing))
            resp <- putPublish "/npm/@acme/widget" (Just "publisher-token") mismatchedNameBody app
            status resp `shouldBe` 403
            targetSaw target `shouldReturn` []

    it "refuses a publish whose body versions[].name disagrees with the in-scope URL name (403 before any relay)" $
        withTarget 201 "{\"success\":true}" $ \targetPort target -> do
            app <- proxyWith (Just (publishDepsAt targetPort Nothing))
            resp <- putPublish "/npm/@acme/widget" (Just "publisher-token") mismatchedVersionNameBody app
            status resp `shouldBe` 403
            targetSaw target `shouldReturn` []

    it "relays an in-scope publish whose body _id / name / versions[].name all agree with the URL name" $
        withTarget 201 "{\"success\":true}" $ \targetPort target -> do
            app <- proxyWith (Just (publishDepsAt targetPort Nothing))
            resp <- putPublish "/npm/@acme/widget" (Just "publisher-token") matchingVersionBody app
            -- a body whose every declared name matches the URL still relays (no over-refusal)
            status resp `shouldBe` 201
            seen <- targetSaw target
            map fst seen `shouldBe` [Just "Bearer publisher-token"]
