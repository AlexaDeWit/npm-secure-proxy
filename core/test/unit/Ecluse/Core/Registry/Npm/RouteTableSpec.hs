-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT
-- TupleSections: the frozen reference parser copies 'takeScoped''s (,rest) form.
{-# LANGUAGE TupleSections #-}

{- | npm's route table, held against an __independent reference__: a hand-written
implementation of the same grammar that shares no code with the table under test. The
equivalence properties are therefore a genuine differential check of the routing engine,
not a tautology.

These examples check the security-critical routing path on two axes. A route record's
action is a closure with nothing to compare, but its /decision/ and its /parse/ both
compare directly:

* __Which route claims a request__ ('matchRoute', by 'routeId', or nothing at all). This
  covers matching order, the method condition, the precedence of the reserved meta-routes,
  and the __denials__. A path-confusion artifact name claims no route and falls through to
  the @404@.

* __What a route's captures parse to__ ('takePackage', 'tarballCoordinate'). This is where
  the scoped-name decoding, the component-safety gate, and the artifact coordinate live.
  The table references them by name, so these examples assert them directly rather than
  through the router.

The reference encodes the grammar exactly, including the two rules asserted directly
below:

* A lone @"-"@ is never a package name, on __any__ method, because it is the reserved
  meta-route prefix. A @PUT \/-@ denies rather than publishing a package called @"-"@.
* A @DELETE@ reaches the dist-tag removal and nothing else, and a @POST@ reaches no route,
  so either over a package path denies rather than being served a packument.
-}
module Ecluse.Core.Registry.Npm.RouteTableSpec (spec) where

import Data.Text qualified as T
import Hedgehog (Gen, cover, forAll, (===))
import Hedgehog.Gen qualified as Gen
import Network.HTTP.Types.Method (Method, methodDelete, methodGet, methodHead, methodPost, methodPut)
import Test.Hspec
import Test.Hspec.Hedgehog (hedgehog)
import Test.Hspec.QuickCheck (modifyMaxSuccess)

import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.Package (PackageName, mkPackageName, mkScope, unscopedName)
import Ecluse.Core.Registry.Npm.Route (NpmCap (NpmFilename, NpmPackage), npmRoutes, takePackage, tarballCoordinate, tarballPath)
import Ecluse.Core.Server.Path (isSafeComponent)
import Ecluse.Core.Server.Route (Route (routeName), RouteName (RouteName), matchRoute)
import Ecluse.Core.Version (mkVersion)
import Ecluse.Test.Package (unsafeFilename)
import Ecluse.Test.Registry.Npm (genPathSegments)
import Ecluse.Test.Server.Route (claimsEveryRendering)

{- | The route a request takes: the name of the first route to claim it, or 'Nothing' when
none does (the deny-by-default @404@). These examples assert only which route claimed the
request, never what its closure serves.
-}
matchedId :: Method -> [Text] -> Maybe RouteName
-- npm's routes negotiate no media type, so the reference routes with no Accept header.
matchedId method segments = routeName . fst <$> matchRoute npmRoutes method [] segments

spec :: Spec
spec = do
    describe "every rendered tarball URL is one this table claims" $ do
        it "claims the artifact route's own rendering, scoped or not" $
            -- A rewritten dist.tarball no route claims is a 404 on every install, and one a
            -- different route claims is worse. The render and the match are one record. The
            -- file name is one the route's own coordinate check accepts, because a rendering
            -- for a name it refuses is a URL this mount would never have served.
            hedgehog $ do
                name <- forAll genPackageName
                file <- forAll (genTarballName name)
                claimsEveryRendering npmRoutes (RouteName "tarball") [NpmPackage name, NpmFilename file]

        it "renders the path the served packument rewrites a tarball onto" $ do
            tarballPath (mkPackageName Npm Nothing "lodash") "lodash-4.17.21.tgz"
                `shouldBe` Just "lodash/-/lodash-4.17.21.tgz"
            tarballPath (mkPackageName Npm (Just (mkScope "babel")) "code-frame") "code-frame-7.0.0.tgz"
                `shouldBe` Just "@babel/code-frame/-/code-frame-7.0.0.tgz"

    describe "npm's route table (differential against an independent reference)" $ do
        modifyMaxSuccess (const 5000) $
            it "claims the same route as the reference, over generated requests" $
                hedgehog $ do
                    method <- forAll genMethod
                    segments <- forAll genPathSegments
                    matchedId method segments === referenceRouteId method segments

        modifyMaxSuccess (const 5000) $
            it "parses a package unit exactly as the reference does" $
                hedgehog $ do
                    segments <- forAll genPathSegments
                    takePackage segments === refTakePackage segments

        -- 'genPathSegments' explores arbitrary paths, and a dist-tag path is four or five
        -- specific segments, so it never reaches one. This generator shapes the request instead.
        modifyMaxSuccess (const 2000) $
            it "claims the same route as the reference, over generated dist-tag requests" $
                hedgehog $ do
                    (method, segments) <- forAll genDistTagRequest
                    let claimed = matchedId method segments
                    cover 5 "claims the dist-tag list" (claimed == Just (RouteName "distTagList"))
                    cover 2 "claims the dist-tag set" (claimed == Just (RouteName "distTagSet"))
                    cover 2 "claims the dist-tag removal" (claimed == Just (RouteName "distTagRemove"))
                    cover 20 "falls through to the 404" (isNothing claimed)
                    claimed === referenceRouteId method segments

    describe "the routes it claims" $ do
        -- Worked examples: also documentation of the grammar the table encodes.
        it "GET /-/ping is the liveness probe" $
            matchedId methodGet ["-", "ping"] `shouldBe` Just (RouteName "ping")
        it "GET /-/v1/search is the (unsupported) search route" $
            matchedId methodGet ["-", "v1", "search"] `shouldBe` Just (RouteName "search")
        it "GET /-/package/{pkg}/dist-tags is the (unsupported) dist-tag list route" $
            matchedId methodGet ["-", "package", "lodash", "dist-tags"]
                `shouldBe` Just (RouteName "distTagList")
        it "PUT /-/package/{pkg}/dist-tags/{tag} is the (unsupported) dist-tag set route" $
            matchedId methodPut ["-", "package", "lodash", "dist-tags", "latest"]
                `shouldBe` Just (RouteName "distTagSet")
        it "DELETE /-/package/{pkg}/dist-tags/{tag} is the (unsupported) dist-tag removal route" $
            matchedId methodDelete ["-", "package", "lodash", "dist-tags", "latest"]
                `shouldBe` Just (RouteName "distTagRemove")
        it "GET /{package} is a packument read" $
            matchedId methodGet ["lodash"] `shouldBe` Just (RouteName "packument")
        it "GET /{package}/-/{file}.tgz is an artifact read" $
            matchedId methodGet ["lodash", "-", "lodash-1.0.0.tgz"] `shouldBe` Just (RouteName "tarball")
        it "PUT /{package} is a publish" $
            matchedId methodPut ["lodash"] `shouldBe` Just (RouteName "publish")
        it "a HEAD reads like a GET" $
            matchedId methodHead ["lodash"] `shouldBe` Just (RouteName "packument")
        it "an unknown meta-route denies" $
            matchedId methodGet ["-", "bogus"] `shouldBe` Nothing

        -- Path confusion is a denial: the router fabricates no coordinate from a mismatched
        -- artifact basename.
        it "an artifact whose basename is for another package is not claimed (path confusion)" $
            matchedId methodGet ["lodash", "-", "evil-1.0.0.tgz"] `shouldBe` Nothing

        -- "-" is the reserved meta-route prefix, and npm cannot hold a package named "-".
        it "a lone \"-\" is never a package, on any method" $ do
            matchedId methodPut ["-"] `shouldBe` Nothing
            matchedId methodGet ["-"] `shouldBe` Nothing

        -- A POST reaches no route, and a DELETE only the dist-tag removal, so either over a
        -- package path matches nothing and denies rather than serving a packument.
        it "a method the front door does not answer denies" $ do
            matchedId methodDelete ["lodash"] `shouldBe` Nothing
            matchedId methodPost ["lodash"] `shouldBe` Nothing
            matchedId methodDelete ["lodash", "-", "lodash-1.0.0.tgz"] `shouldBe` Nothing
            matchedId methodPost ["-", "package", "lodash", "dist-tags", "latest"] `shouldBe` Nothing

    describe "what its captures parse to" $ do
        it "normalises both scoped-name wire encodings to the same package" $
            takePackage ["@scope", "pkg"] `shouldBe` takePackage ["@scope/pkg"]
        it "parses an unscoped package unit" $
            takePackage ["lodash"] `shouldBe` Just (mkPackageName Npm Nothing "lodash", [])
        it "parses a scoped package unit, leaving the tail" $
            takePackage ["@babel/core", "-", "core-7.0.0.tgz"]
                `shouldBe` Just (mkPackageName Npm (Just (mkScope "babel")) "core", ["-", "core-7.0.0.tgz"])
        it "refuses a traversal component" $
            takePackage [".."] `shouldBe` Nothing

        it "reads the version out of an artifact name, preserving the file verbatim" $
            tarballCoordinate (mkPackageName Npm Nothing "lodash") "lodash-1.0.0.tgz"
                `shouldBe` Just (mkVersion Npm "1.0.0", unsafeFilename "lodash-1.0.0.tgz")
        it "drops the scope from a scoped package's artifact name, as npm does" $
            tarballCoordinate (mkPackageName Npm (Just (mkScope "babel")) "code-frame") "code-frame-7.0.0.tgz"
                `shouldBe` Just (mkVersion Npm "7.0.0", unsafeFilename "code-frame-7.0.0.tgz")
        it "refuses an artifact name for a different package (path confusion)" $
            tarballCoordinate (mkPackageName Npm Nothing "lodash") "evil-1.0.0.tgz" `shouldBe` Nothing
        it "refuses a bare .tgz with no version" $
            tarballCoordinate (mkPackageName Npm Nothing "lodash") "lodash-.tgz" `shouldBe` Nothing

-- Generators -----------------------------------------------------------------

genMethod :: Gen Method
genMethod = Gen.element [methodGet, methodPut, methodHead, methodPost, methodDelete]

{- | A request shaped like a dist-tag route, every part perturbed, so the property reaches
all three routes and the near misses that must deny. 'genPathSegments' reaches none of them.
-}
genDistTagRequest :: Gen (Method, [Text])
genDistTagRequest = do
    method <- genDistTagMethod
    prefix <- genLiteralSeg "-"
    package <- genLiteralSeg "package"
    name <- genPackageUnit
    distTags <- genLiteralSeg "dist-tags"
    tag <- Gen.frequency [(1, pure []), (1, (: []) <$> genTagSeg)]
    pure (method, [prefix, package] <> name <> [distTags] <> tag)

-- Weighted to the three methods the dist-tag routes answer, keeping the one that must deny.
-- DELETE claims the removal route, so it carries PUT's weight instead of sharing POST's arm.
genDistTagMethod :: Gen Method
genDistTagMethod =
    Gen.frequency
        [ (3, pure methodGet)
        , (1, pure methodHead)
        , (3, pure methodPut)
        , (3, pure methodDelete)
        , (1, pure methodPost)
        ]

-- A literal slot: mostly the segment the route requires, sometimes a near miss.
genLiteralSeg :: Text -> Gen Text
genLiteralSeg literal = Gen.frequency [(4, pure literal), (1, Gen.element nearMissSegs)]

nearMissSegs :: [Text]
nearMissSegs = ["", "..", "-", "package", "dist-tags", "v1", "lodash"]

-- The package slot: an unscoped name, a scoped name in either wire encoding, or a segment that
-- derails the match. Eight of the ten weights are a name the capture accepts.
genPackageUnit :: Gen [Text]
genPackageUnit =
    Gen.frequency
        [ (4, (: []) <$> Gen.element ["lodash", "is-odd", "pkg"])
        , (2, (: []) <$> Gen.element ["@babel/code-frame", "@acme/widget"])
        , (2, (\scope base -> [scope, base]) <$> Gen.element ["@babel", "@acme"] <*> Gen.element ["core", "widget"])
        , (2, (: []) <$> Gen.element ["-", "..", "foo/bar", "@babel", ""])
        ]

-- A package identity the render property builds a URL for: unscoped or scoped, both encodings
-- of which the artifact route claims.
genPackageName :: Gen PackageName
genPackageName =
    Gen.choice
        [ mkPackageName Npm Nothing <$> Gen.element ["lodash", "is-odd", "pkg"]
        , mkPackageName Npm . Just . mkScope <$> Gen.element ["babel", "acme"] <*> Gen.element ["core", "widget"]
        ]

{- An artifact file name for one package, in npm's own convention: the unscoped name, the
version, and the @.tgz@ suffix. It is what a real dist.tarball ends in, and what the route's
cross-capture check accepts. -}
genTarballName :: PackageName -> Gen Text
genTarballName name = do
    version <- Gen.element ["1.0.0", "4.17.21", "0.0.1-rc.1", "7.0.0"]
    pure (unscopedName name <> "-" <> version <> ".tgz")

-- The tag slot: four names the capture accepts, two components it must refuse.
genTagSeg :: Gen Text
genTagSeg = Gen.element ["latest", "next", "beta", "1.0.0", "..", "a/b"]

-- The independent reference ---------------------------------------------------
--
-- A hand-written implementation of the npm grammar, structured as pattern matching. It
-- shares no code with the table under test, so the equivalence properties are a genuine
-- differential check rather than a tautology.

-- | Which route the reference grammar says claims a request.
referenceRouteId :: Method -> [Text] -> Maybe RouteName
referenceRouteId method segments
    | method == methodPut = refWrite segments
    | method == methodDelete = refRemove segments
    | method == methodGet || method == methodHead = refRead segments
    -- Any other method matches no route: deny by default.
    | otherwise = Nothing

refRead :: [Text] -> Maybe RouteName
refRead ("-" : meta) = refMeta meta
refRead segments = refPackage segments

refWrite :: [Text] -> Maybe RouteName
-- "-" is the reserved meta-route prefix, so a write under it is never a publish.
refWrite ("-" : meta) = refMetaTagged (RouteName "distTagSet") meta
refWrite segments = case refTakePackage segments of
    Just (_name, []) -> Just (RouteName "publish")
    _ -> Nothing

-- The dist-tag removal is the only route a DELETE claims.
refRemove :: [Text] -> Maybe RouteName
refRemove ("-" : meta) = refMetaTagged (RouteName "distTagRemove") meta
refRemove _ = Nothing

refMeta :: [Text] -> Maybe RouteName
refMeta = \case
    ["ping"] -> Just (RouteName "ping")
    ["v1", "search"] -> Just (RouteName "search")
    "package" : rest -> refDistTagList rest
    _ -> Nothing

-- The tagged dist-tag path, under the name its method claims: the set for a PUT, the removal
-- for a DELETE. It is the only route either method reaches under the reserved prefix.
refMetaTagged :: RouteName -> [Text] -> Maybe RouteName
refMetaTagged claimed ("package" : rest) = case refTakePackage rest of
    Just (_name, ["dist-tags", tag]) | isSafeComponent tag -> Just claimed
    _ -> Nothing
refMetaTagged _ _ = Nothing

refDistTagList :: [Text] -> Maybe RouteName
refDistTagList segments = case refTakePackage segments of
    Just (_name, ["dist-tags"]) -> Just (RouteName "distTagList")
    _ -> Nothing

refPackage :: [Text] -> Maybe RouteName
refPackage segments = case refTakePackage segments of
    Nothing -> Nothing
    Just (name, rest) -> refDispatch name rest
  where
    refDispatch name = \case
        [] -> Just (RouteName "packument")
        ["-", file] | isSafeComponent file -> refTarball name file
        _ -> Nothing

refTakePackage :: [Text] -> Maybe (PackageName, [Text])
refTakePackage [] = Nothing
refTakePackage (seg : rest)
    | "@" <- T.take 1 seg = refTakeScoped seg rest
    | refComponent seg = Just (mkPackageName Npm Nothing seg, rest)
    | otherwise = Nothing

refTakeScoped :: Text -> [Text] -> Maybe (PackageName, [Text])
refTakeScoped seg rest =
    case T.breakOn "/" (T.drop 1 seg) of
        (scope, base)
            | not (T.null base) -> (,rest) <$> refScopedName scope (T.drop 1 base)
        _ -> case rest of
            (base : more) -> (,more) <$> refScopedName (T.drop 1 seg) base
            _ -> Nothing

refScopedName :: Text -> Text -> Maybe PackageName
refScopedName scope base
    | refComponent scope && refComponent base =
        Just (mkPackageName Npm (Just (mkScope scope)) base)
    | otherwise = Nothing

-- One usable npm name component, restated here: npm's error tier, so one identity has exactly one
-- spelling and no codepoint outside the allowlist reaches an upstream URL.
refComponent :: Text -> Bool
refComponent c =
    isSafeComponent c
        && T.all (`elem` refNameChars) c
        && T.take 1 c `notElem` [".", "-", "_"]
        && T.toLower c `notElem` ["node_modules", "favicon.ico"]

-- The allowlist written out rather than classified, so the reference restates the grammar
-- instead of sharing a character predicate with it.
refNameChars :: [Char]
refNameChars = ['a' .. 'z'] <> ['A' .. 'Z'] <> ['0' .. '9'] <> "-_.!~*'()"

-- The artifact route claims a request only when the file name parses for that package.
refTarball :: PackageName -> Text -> Maybe RouteName
refTarball name file =
    case T.stripSuffix ".tgz" file >>= T.stripPrefix (unscopedName name <> "-") of
        Just version
            | not (T.null version) -> Just (RouteName "tarball")
        _ -> Nothing
