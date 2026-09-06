-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Core.Registry.Npm.RouteSpec (spec) where

import Data.Char (isControl)
import Data.Text qualified as T
import Hedgehog (forAll)
import Hedgehog qualified as H
import Test.Hspec
import Test.Hspec.Hedgehog (hedgehog, modifyMaxSuccess)

import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.Package (
    PackageName,
    mkPackageName,
    mkScope,
    pkgNamespace,
    renderPackageName,
    unScope,
 )
import Network.HTTP.Types.Method (Method, methodDelete, methodGet, methodPut)

import Ecluse.Core.Registry.Npm.Route (npmRoutes, takePackage, tarballCoordinate)
import Ecluse.Core.Server.Path (Filename, unFilename)
import Ecluse.Core.Server.Route (Route (routeName), RouteName (RouteName), matchRoute)
import Ecluse.Core.Version (Version, mkVersion)
import Ecluse.Test.Package (unsafeFilename, unscopedNpm)
import Ecluse.Test.Registry.Npm qualified as NpmFixture

{- | What a request routes to, rebuilt from the table's public surface: which route claimed the
path, and what that route's captures parse to. The routes carry actions, not comparable values.
-}
data Routed
    = ToPackument PackageName
    | ToTarball PackageName Version Filename
    | ToPublish PackageName
    | ToPing
    | ToSearch
    | ToDistTagList
    | ToDistTagSet
    | ToDistTagRemove
    | Denied
    deriving stock (Eq, Show)

routed :: Method -> [Text] -> Routed
routed method segments =
    case routeName . fst <$> matchRoute npmRoutes method [] segments of
        Nothing -> Denied
        Just (RouteName "ping") -> ToPing
        Just (RouteName "search") -> ToSearch
        Just (RouteName "distTagList") -> ToDistTagList
        Just (RouteName "distTagSet") -> ToDistTagSet
        Just (RouteName "distTagRemove") -> ToDistTagRemove
        Just (RouteName "packument") -> maybe Denied (ToPackument . fst) (takePackage segments)
        Just (RouteName "publish") -> maybe Denied (ToPublish . fst) (takePackage segments)
        Just (RouteName "tarball") -> fromMaybe Denied $ do
            (name, rest) <- takePackage segments
            file <- case rest of
                ["-", f] -> Just f
                _ -> Nothing
            (version, filename) <- tarballCoordinate name file
            pure (ToTarball name version filename)
        Just _ -> Denied

{- | The read classification (a @GET@) of an npm path. A @HEAD@ classifies identically, so @GET@
stands for every read method here.
-}
classify :: [Text] -> Routed
classify = routed methodGet

-- | The write classification (a @PUT@) of an npm path.
written :: [Text] -> Routed
written = routed methodPut

-- | The removal classification (a @DELETE@) of an npm path.
removed :: [Text] -> Routed
removed = routed methodDelete

-- | A scoped npm package identity (scope, base name), for expected 'Route's.
scoped :: Text -> Text -> PackageName
scoped scope = mkPackageName Npm (Just (mkScope scope))

-- | An npm version, for the parsed coordinate a 'Tarball' route carries.
npmVersion :: Text -> Version
npmVersion = mkVersion Npm

{- | A scoped name's two-segment wire encoding (@\@scope@ then @pkg@), or 'Nothing' when the name
carries no separator to split at.
-}
twoSegments :: Text -> Maybe [Text]
twoSegments raw = case T.breakOn "/" raw of
    (scopeSeg, rest) | Just baseSeg <- T.stripPrefix "/" rest -> Just [scopeSeg, baseSeg]
    _ -> Nothing

{- | The npm routing table, asserted as @pathInfo → Route@. The path arrives percent-decoded, so
each scoped case appears in both wire encodings and both must agree.
-}
spec :: Spec
spec = do
    describe "takePackage -- the one npm name grammar, in both wire encodings" $
        for_ NpmFixture.npmNameVerdicts $ \(raw, valid) ->
            it (NpmFixture.nameVerdictLabel raw valid) $ do
                isJust (takePackage [raw]) `shouldBe` valid
                -- A percent-decoded path splits a scoped name across two segments as readily
                -- as one. Both encodings reach the same verdict, and the same name.
                for_ (twoSegments raw) $ \segs -> takePackage segs `shouldBe` takePackage [raw]

    describe "classify -- packuments" $ do
        it "routes an unscoped package to its packument" $
            classify ["is-odd"] `shouldBe` ToPackument (unscopedNpm "is-odd")
        it "routes a scoped package (two segments) to its packument" $
            classify ["@babel", "code-frame"]
                `shouldBe` ToPackument (scoped "babel" "code-frame")
        it "routes a scoped package (one decoded segment) to its packument" $
            classify ["@babel/code-frame"]
                `shouldBe` ToPackument (scoped "babel" "code-frame")
        it "agrees on the same Route for both scoped encodings" $
            classify ["@babel", "code-frame"] `shouldBe` classify ["@babel/code-frame"]

    describe "classify -- tarballs (the parsed artifact coordinate)" $ do
        it "routes an unscoped tarball to its artifact, parsing the version" $
            classify ["is-odd", "-", "is-odd-3.0.1.tgz"]
                `shouldBe` ToTarball (unscopedNpm "is-odd") (npmVersion "3.0.1") (unsafeFilename "is-odd-3.0.1.tgz")
        it "routes a scoped tarball (two segments) to its artifact" $
            -- The basename drops the scope: @\@babel\/code-frame@ → @code-frame-7.0.0.tgz@.
            classify ["@babel", "code-frame", "-", "code-frame-7.0.0.tgz"]
                `shouldBe` ToTarball (scoped "babel" "code-frame") (npmVersion "7.0.0") (unsafeFilename "code-frame-7.0.0.tgz")
        it "routes a scoped tarball (one decoded segment) to its artifact" $
            classify ["@babel/code-frame", "-", "code-frame-7.0.0.tgz"]
                `shouldBe` ToTarball (scoped "babel" "code-frame") (npmVersion "7.0.0") (unsafeFilename "code-frame-7.0.0.tgz")
        it "reads a prerelease-hyphen version out of the basename verbatim" $
            -- The version itself carries hyphens (@1.0.0-rc.1@). The parse must split on
            -- the FIRST @{name}-@ boundary, taking everything after it as the version.
            classify ["pkg", "-", "pkg-1.0.0-rc.1.tgz"]
                `shouldBe` ToTarball (unscopedNpm "pkg") (npmVersion "1.0.0-rc.1") (unsafeFilename "pkg-1.0.0-rc.1.tgz")
        it "preserves the filename verbatim, not one rebuilt from (name, version)" $
            -- The file's parsed version round-trips and the Filename is byte-identical
            -- to what arrived. That Filename, not a reconstruction, fetches the bytes.
            classify ["@babel/code-frame", "-", "code-frame-7.0.0.tgz"]
                `shouldBe` ToTarball (scoped "babel" "code-frame") (npmVersion "7.0.0") (unsafeFilename "code-frame-7.0.0.tgz")
        it "denies a basename that does not match the requested package (path-confusion)" $
            -- The file names a DIFFERENT package's artifact under @is-odd@'s path.
            -- The basename lacks the @is-odd-@ prefix, so the parse denies rather than fabricates.
            classify ["is-odd", "-", "is-even-3.0.1.tgz"] `shouldBe` Denied
        it "denies a basename that is the bare package name with no version" $
            -- @{name}.tgz@ has no @-{version}@ run, so there is no coordinate to parse.
            classify ["is-odd", "-", "is-odd.tgz"] `shouldBe` Denied
        it "denies a basename that is the name and a trailing hyphen but empty version" $
            classify ["is-odd", "-", "is-odd-.tgz"] `shouldBe` Denied

    describe "classify -- meta-routes (matched before any package)" $ do
        it "routes /-/ping to Ping" $
            classify ["-", "ping"] `shouldBe` ToPing
        it "routes /-/v1/search to Search" $
            classify ["-", "v1", "search"] `shouldBe` ToSearch
        it "treats an unknown /-/… meta-route as Unsupported, never a package" $
            classify ["-", "whoami"] `shouldBe` Denied

    describe "classify -- dist-tags (claimed, then refused as unimplemented)" $ do
        -- The route claims the path so the client is told the operation is not implemented,
        -- rather than reading a deny-by-default 404 as the package being absent.
        it "routes /-/package/{pkg}/dist-tags to the dist-tag list" $
            classify ["-", "package", "is-odd", "dist-tags"] `shouldBe` ToDistTagList
        it "routes a scoped package's dist-tags (two segments)" $
            classify ["-", "package", "@babel", "code-frame", "dist-tags"] `shouldBe` ToDistTagList
        it "routes a scoped package's dist-tags (one decoded segment)" $
            classify ["-", "package", "@babel/code-frame", "dist-tags"] `shouldBe` ToDistTagList
        it "routes a PUT of /-/package/{pkg}/dist-tags/{tag} to the dist-tag set" $
            written ["-", "package", "is-odd", "dist-tags", "latest"] `shouldBe` ToDistTagSet
        it "denies a dist-tag list with a trailing tag (the tag is the write path's)" $
            classify ["-", "package", "is-odd", "dist-tags", "latest"] `shouldBe` Denied
        it "denies a dist-tag set with no tag" $
            written ["-", "package", "is-odd", "dist-tags"] `shouldBe` Denied
        it "denies a dist-tag path whose package is unsafe" $
            classify ["-", "package", "..", "dist-tags"] `shouldBe` Denied
        it "denies a dist-tag set whose tag is unsafe" $
            written ["-", "package", "is-odd", "dist-tags", "../evil"] `shouldBe` Denied
        it "routes a DELETE of /-/package/{pkg}/dist-tags/{tag} to the dist-tag removal" $
            removed ["-", "package", "is-odd", "dist-tags", "latest"] `shouldBe` ToDistTagRemove
        it "routes a scoped package's dist-tag removal (both wire encodings)" $ do
            removed ["-", "package", "@babel", "code-frame", "dist-tags", "latest"]
                `shouldBe` ToDistTagRemove
            removed ["-", "package", "@babel/code-frame", "dist-tags", "latest"]
                `shouldBe` ToDistTagRemove
        it "denies a dist-tag removal with no tag" $
            removed ["-", "package", "is-odd", "dist-tags"] `shouldBe` Denied
        it "denies a dist-tag removal whose tag is unsafe" $
            removed ["-", "package", "is-odd", "dist-tags", "../evil"] `shouldBe` Denied
        it "denies a DELETE outside the dist-tag path (the method claims nothing else)" $ do
            -- The removal route is the only one a DELETE reaches. A package or artifact
            -- path under DELETE still takes the deny-by-default 404.
            removed ["is-odd"] `shouldBe` Denied
            removed ["is-odd", "-", "is-odd-3.0.1.tgz"] `shouldBe` Denied

    describe "classify -- publish (PUT /{pkg}, the method-aware write route)" $ do
        it "routes a PUT of an unscoped package to Publish" $
            written ["is-odd"] `shouldBe` ToPublish (unscopedNpm "is-odd")
        it "routes a PUT of a scoped package (two segments) to Publish" $
            written ["@acme", "widget"] `shouldBe` ToPublish (scoped "acme" "widget")
        it "routes a PUT of a scoped package (one decoded segment) to Publish" $
            written ["@acme/widget"] `shouldBe` ToPublish (scoped "acme" "widget")
        it "agrees on the same Publish route for both scoped encodings" $
            written ["@acme", "widget"] `shouldBe` written ["@acme/widget"]
        it "denies a PUT to a tarball slot (a publish is a bare-package path only)" $
            -- The version lives in the body, not the path. A PUT to /{pkg}/-/{file}.tgz
            -- is not a publish.
            written ["is-odd", "-", "is-odd-3.0.1.tgz"] `shouldBe` Denied
        it "denies a PUT to a meta-route" $
            written ["-", "ping"] `shouldBe` Denied
        it "denies a PUT with trailing junk after the package" $
            written ["is-odd", "extra"] `shouldBe` Denied
        it "denies a PUT to the empty path" $
            written [] `shouldBe` Denied
        it "denies a PUT of an unsafe name (embedded slash) -- the same component gate as reads" $
            written ["foo/bar"] `shouldBe` Denied
        it "denies a PUT of a bare scope with no package name" $
            written ["@acme"] `shouldBe` Denied
        it "denies a PUT of a name outside the ASCII boundary -- the same grammar as reads" $
            -- The publish handler is reachable only through this capture, so a name the
            -- grammar refuses never becomes a write.
            written ["@acme/wid\x3164\&get"] `shouldBe` Denied
        it "does not publish a GET of the same package (a GET /{pkg} is a Packument)" $
            -- The method decides as much as the path: the same /{pkg} reads under GET
            -- and publishes under PUT.
            classify ["is-odd"] `shouldBe` ToPackument (unscopedNpm "is-odd")

    describe "classify -- unrecognised paths deny by default" $ do
        it "routes the empty path to Unsupported" $
            classify [] `shouldBe` Denied
        it "routes a bare slash (one empty segment) to Unsupported" $
            classify [""] `shouldBe` Denied
        it "routes a non-.tgz artifact-shaped path to Unsupported" $
            classify ["is-odd", "-", "is-odd-3.0.1.zip"] `shouldBe` Denied
        it "routes a bare \".tgz\" (no name before the suffix) to Unsupported" $
            -- The basename is empty, so it can never match @{name}-{version}@.
            classify ["is-odd", "-", ".tgz"] `shouldBe` Denied
        it "routes a version-manifest request to Unsupported" $
            -- @GET /{pkg}/{version}@ is not a packument. Only a bare package path is, so
            -- a trailing version segment matches no route.
            classify ["is-odd", "3.0.1"] `shouldBe` Denied
        it "routes a scope with no package name to Unsupported" $
            classify ["@babel"] `shouldBe` Denied
        it "routes a scope with an empty trailing name to Unsupported" $
            -- Reachable from @\/\@scope%2F@: percent-decoding @%2F@ yields one segment
            -- @"\@babel\/"@, whose base name is empty. That is a degenerate scoped name.
            classify ["@babel/"] `shouldBe` Denied
        it "routes an empty scope (\"@\" then name) to Unsupported" $
            -- @mkScope "@"@ strips to @""@, which would render as @\/code-frame@.
            classify ["@", "code-frame"] `shouldBe` Denied
        it "routes a scoped name whose base still contains a slash to Unsupported" $
            -- An npm name never contains @\'\/\'@ beyond the scope separator.
            classify ["@babel/code/frame"] `shouldBe` Denied
        it "routes trailing junk after a package to Unsupported" $
            classify ["is-odd", "extra", "junk"] `shouldBe` Denied

    describe "classify -- unsafe path components deny by default" $ do
        -- A single percent-decoded segment can carry traversal, separator, or control
        -- content. 'classify' must never accept it as a name, scope, or file, because
        -- downstream code interpolates the component into the upstream URL.
        it "rejects an unscoped name with an embedded slash" $
            -- Reachable from @\/foo%2Fbar@: percent-decoding @%2F@ yields one segment
            -- @"foo\/bar"@. Accepting it as a packument would smuggle a path.
            classify ["foo/bar"] `shouldBe` Denied
        it "rejects an unscoped name with an embedded backslash" $
            classify ["foo\\bar"] `shouldBe` Denied
        it "rejects the parent-directory name \"..\"" $
            classify [".."] `shouldBe` Denied
        it "rejects the current-directory name \".\"" $
            classify ["."] `shouldBe` Denied
        it "rejects an unscoped name with a tab (control) character" $
            classify ["foo\tbar"] `shouldBe` Denied
        it "rejects an unscoped name with a NUL character" $
            classify ["foo\0bar"] `shouldBe` Denied
        it "rejects a scope of \"..\" (one decoded segment)" $
            classify ["@../pkg"] `shouldBe` Denied
        it "rejects a scope of \"..\" (two segments)" $
            classify ["@..", "pkg"] `shouldBe` Denied
        it "rejects a tarball filename that escapes via traversal" $
            -- The filename ends in @.tgz@ yet contains @..\/@: the suffix guard
            -- alone is not enough, so the safe-component check must reject it.
            classify ["is-odd", "-", "../evil.tgz"] `shouldBe` Denied
        it "rejects a tarball filename with an embedded slash" $
            classify ["is-odd", "-", "sub/is-odd-3.0.1.tgz"] `shouldBe` Denied

    describe "classify -- real names still classify (no over-rejection)" $ do
        -- Guard against the safe-component check rejecting plausibly-real names.
        -- Interior dots, hyphens, and uppercase are all fine: this is a security
        -- boundary, not an npm-policy validator.
        it "accepts an unscoped name with interior dots" $
            classify ["lodash.merge"] `shouldBe` ToPackument (unscopedNpm "lodash.merge")
        it "accepts another dotted unscoped name" $
            classify ["is.odd"] `shouldBe` ToPackument (unscopedNpm "is.odd")
        it "accepts a hyphenated unscoped name" $
            classify ["is-odd"] `shouldBe` ToPackument (unscopedNpm "is-odd")
        it "accepts a scoped name in two segments" $
            classify ["@babel", "code-frame"]
                `shouldBe` ToPackument (scoped "babel" "code-frame")
        it "accepts a scoped name in one decoded segment" $
            classify ["@babel/code-frame"]
                `shouldBe` ToPackument (scoped "babel" "code-frame")
        it "accepts the @types scope" $
            classify ["@types", "node"] `shouldBe` ToPackument (scoped "types" "node")

    describe "properties" $
        -- The invariant: no hostile path yields an accepted route with an unsafe component.
        -- The coverage classification below proves the generator reaches both arms.
        -- Each component is checked alone, because a scoped name renders with a structural '/'.
        -- 1000 rather than the default 100: the accepted arm runs at 13%, and 100 samples of
        -- a 13% rate fall under the 5% floor once in 426 runs. At 1000 the floor is unreachable.
        modifyMaxSuccess (const 1000) $
            it "an accepted route never carries an unsafe component" $
                hedgehog $ do
                    segs <- forAll NpmFixture.genPathSegments
                    let route = classify segs
                    -- Non-vacuity: the same generator must reach both arms often.
                    H.cover 5 "accepted (packument/artifact)" (isAccepted route)
                    H.cover 5 "denied or answered locally" (not (isAccepted route))
                    case route of
                        ToPackument pn ->
                            H.assert (all safe (nameComponents pn))
                        ToTarball pn _ file ->
                            H.assert (all safe (unFilename file : nameComponents pn))
                        _ -> pure ()

-- | Whether a route is an accepted package route (the arms the invariant binds).
isAccepted :: Routed -> Bool
isAccepted = \case
    ToPackument _ -> True
    ToTarball{} -> True
    _ -> False

{- | The structural components of an accepted name: its scope, if any, and its base name. The
caller checks each component on its own rather than across the scope separator.
-}
nameComponents :: PackageName -> [Text]
nameComponents pn =
    case pkgNamespace pn of
        Nothing -> [renderPackageName pn]
        Just s ->
            let scopeTxt = unScope s
                base = fromMaybe (renderPackageName pn) (T.stripPrefix ("@" <> scopeTxt <> "/") (renderPackageName pn))
             in [scopeTxt, base]

{- | The router's safety rule, restated here so the property pins the externally observable
guarantee independently of the router's implementation.
-}
safe :: Text -> Bool
safe c =
    not (T.null c)
        && c /= "."
        && c /= ".."
        && T.all (\ch -> ch /= '/' && ch /= '\\' && not (isControl ch)) c
