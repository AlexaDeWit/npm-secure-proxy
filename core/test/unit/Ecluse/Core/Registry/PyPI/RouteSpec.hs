-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | PyPI's route table, driven through 'matchRoute'.

A route record's action is a closure with nothing to compare, so these examples assert which
route claims a request, what its captures parse to, and which requests claim nothing at all and
so take the deny-by-default @404@.
-}
module Ecluse.Core.Registry.PyPI.RouteSpec (spec) where

import Network.HTTP.Types.Header (RequestHeaders)
import Network.HTTP.Types.Method (Method, methodDelete, methodGet, methodHead, methodPost, methodPut)
import Test.Hspec

import Ecluse.Core.Ecosystem (Ecosystem (PyPI))
import Ecluse.Core.Package (PackageName, mkPackageName, renderPackageName)
import Ecluse.Core.Registry.PyPI.Route (artifactCoordinate, pypiRoutes, takeProject)
import Ecluse.Core.Server.Path (Filename, unFilename)
import Ecluse.Core.Server.Route (Route (routeName), RouteName (RouteName), matchRoute)
import Ecluse.Core.Version (Version, renderVersion)

spec :: Spec
spec = do
    matchingSpec
    negotiationSpec
    captureSpec
    coordinateSpec

matchingSpec :: Spec
matchingSpec = describe "which route claims a request" $ do
    it "routes a project's index read" $
        claimed methodGet jsonAccept ["simple", "requests"] `shouldBe` Just (RouteName "simpleIndex")

    it "routes the same path with a trailing slash, which the router strips" $
        -- The mount dispatcher drops a trailing empty segment before the table sees the path,
        -- so /simple/requests/ and /simple/requests are one template.
        claimed methodGet jsonAccept ["simple", "requests"] `shouldBe` Just (RouteName "simpleIndex")

    it "routes a HEAD of the index as the bodiless variation of its GET" $
        claimed methodHead jsonAccept ["simple", "requests"] `shouldBe` Just (RouteName "simpleIndex")

    it "routes a distribution file read" $
        claimed methodGet [] ["simple", "requests", "requests-2.34.2-py3-none-any.whl"]
            `shouldBe` Just (RouteName "distribution")

    it "routes the upload endpoint under POST" $
        claimed methodPost [] ["legacy"] `shouldBe` Just (RouteName "upload")

    it "claims nothing for a non-canonical project name, so it takes the structural 404" $ do
        claimed methodGet jsonAccept ["simple", "Requests"] `shouldBe` Nothing
        claimed methodGet jsonAccept ["simple", "zope.interface"] `shouldBe` Nothing
        claimed methodGet jsonAccept ["simple", "typing_extensions"] `shouldBe` Nothing

    it "claims nothing for a file naming another project (path confusion)" $
        claimed methodGet [] ["simple", "requests", "urllib3-2.0.0.tar.gz"] `shouldBe` Nothing

    it "claims nothing for a traversal in either capture" $ do
        claimed methodGet jsonAccept ["simple", ".."] `shouldBe` Nothing
        claimed methodGet [] ["simple", "requests", ".."] `shouldBe` Nothing

    it "claims nothing for the JSON API, which this mount does not serve" $
        claimed methodGet [] ["pypi", "requests", "json"] `shouldBe` Nothing

    it "claims nothing for a PEP 658 metadata sidecar" $
        claimed methodGet [] ["simple", "requests", "requests-2.34.2-py3-none-any.whl.metadata"]
            `shouldBe` Nothing

    it "claims nothing for the root index, which lists every project on the upstream" $
        claimed methodGet [] ["simple"] `shouldBe` Nothing

    it "claims nothing for a DELETE, because a client yank is not supported" $
        claimed methodDelete [] ["simple", "requests"] `shouldBe` Nothing

    it "claims nothing for a PUT, which is npm's publish method and not PyPI's" $
        claimed methodPut [] ["legacy"] `shouldBe` Nothing

negotiationSpec :: Spec
negotiationSpec = describe "the index route serves the PEP 691 JSON form alone" $ do
    it "claims a request that admits the JSON form" $
        claimed methodGet jsonAccept ["simple", "requests"] `shouldBe` Just (RouteName "simpleIndex")

    it "claims a request that sends no Accept header at all" $
        claimed methodGet [] ["simple", "requests"] `shouldBe` Just (RouteName "simpleIndex")

    it "still claims a request that admits no JSON, so the route answers its own 406" $
        -- The refusal is the route's, not a fall-through: a fall-through would give the 404
        -- of an unrouted path and tell a legacy client its project does not exist.
        claimed methodGet htmlOnlyAccept ["simple", "requests"] `shouldBe` Just (RouteName "simpleIndex")

    it "negotiates nothing on the distribution route, whose body is upstream's own" $
        claimed methodGet htmlOnlyAccept ["simple", "requests", "requests-2.34.2.tar.gz"]
            `shouldBe` Just (RouteName "distribution")

captureSpec :: Spec
captureSpec = describe "takeProject" $ do
    it "peels a canonical project name off the path" $
        fmap (first renderProject) (takeProject ["requests", "more"])
            `shouldBe` Just ("requests", ["more"])

    it "refuses a spelling the upstream index would redirect" $ do
        takeProject ["Requests"] `shouldSatisfy` isNothing
        takeProject ["zope.interface"] `shouldSatisfy` isNothing

    it "refuses a name the shared floor rejects" $ do
        takeProject [""] `shouldSatisfy` isNothing
        takeProject ["../etc"] `shouldSatisfy` isNothing

    it "refuses an empty path" $
        takeProject [] `shouldSatisfy` isNothing

coordinateSpec :: Spec
coordinateSpec = describe "artifactCoordinate" $ do
    it "reads the release a wheel names, keyed canonically" $
        fmap renderCoordinate (artifactCoordinate requests "requests-2.34.2-py3-none-any.whl")
            `shouldBe` Just ("2.34.2", "requests-2.34.2-py3-none-any.whl")

    it "reads the release a source distribution names" $
        fmap renderCoordinate (artifactCoordinate requests "requests-2.34.2.tar.gz")
            `shouldBe` Just ("2.34.2", "requests-2.34.2.tar.gz")

    it "keeps the file name verbatim, so the upstream path is the one the client asked for" $
        fmap (snd . renderCoordinate) (artifactCoordinate requests "requests-2.34-py3-none-any.whl")
            `shouldBe` Just "requests-2.34-py3-none-any.whl"

    it "refuses a file naming another project" $
        artifactCoordinate requests "urllib3-2.0.0.tar.gz" `shouldSatisfy` isNothing

    it "refuses a name that is not a distribution at all" $
        artifactCoordinate requests "requests" `shouldSatisfy` isNothing

-- | The route that claims a request, or 'Nothing' when none does (the deny-by-default @404@).
claimed :: Method -> RequestHeaders -> [Text] -> Maybe RouteName
claimed method headers segments = routeName . fst <$> matchRoute pypiRoutes method headers segments

-- | The Accept a modern pip sends.
jsonAccept :: RequestHeaders
jsonAccept = [("Accept", "application/vnd.pypi.simple.v1+json, application/vnd.pypi.simple.v1+html;q=0.1, text/html;q=0.01")]

-- | The Accept a client below the supported floor sends.
htmlOnlyAccept :: RequestHeaders
htmlOnlyAccept = [("Accept", "text/html")]

-- | The project the coordinate examples read files for.
requests :: PackageName
requests = mkPackageName PyPI Nothing "requests"

-- | A parsed project name as it renders.
renderProject :: PackageName -> Text
renderProject = renderPackageName

-- | A parsed coordinate as its rendered release and file name.
renderCoordinate :: (Version, Filename) -> (Text, Text)
renderCoordinate (version, file) = (renderVersion version, unFilename file)
