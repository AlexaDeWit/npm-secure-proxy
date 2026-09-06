-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.E2E.Harness.Verdaccio (
    verdaccioHasVersion,
    verdaccioHasVersionNow,
    verdaccioListing,
    verdaccioAwaitListed,
    verdaccioNamesUnder,
) where

import Data.ByteString.Lazy qualified as LBS
import Data.Text qualified as T
import Network.HTTP.Client (
    httpLbs,
    parseRequest,
    responseBody,
    responseStatus,
 )
import Network.HTTP.Types (statusCode)
import UnliftIO (handleAny)

import Ecluse.Core.Package (PackageName, renderPackageName)
import Ecluse.Core.Registry (ParseError (parseErrorMessage))
import Ecluse.Core.Registry.Maintenance (inBucket, mkNameAlphabet, parseNamePrefix)
import Ecluse.Core.Registry.Npm.Maintenance (parsePackageListing)
import Ecluse.E2E.Harness.Types
import Ecluse.Test.Poll (pollUntil)

{- | Poll Verdaccio (the mirror) until it serves the given version of a package, or the
timeout lapses. A 'False' means the version never appeared within the patience window.
-}
verdaccioHasVersion :: E2E -> Text -> Text -> IO Bool
verdaccioHasVersion e2e pkg version =
    pollUntil 40 500000 id (verdaccioHasVersionNow e2e pkg version)

{- | Check once whether the mirror already serves a version, with no retry. Use it for an
absent-now precondition, to skip the patience window 'verdaccioHasVersion' spends.
-}
verdaccioHasVersionNow :: E2E -> Text -> Text -> IO Bool
verdaccioHasVersionNow e2e pkg version =
    handleAny (\_ -> pure False) $ do
        req <- parseRequest (toString (e2eVerdaccio e2e <> "/" <> pkg))
        resp <- httpLbs req (e2eManager e2e)
        pure
            ( statusCode (responseStatus resp) == 200
                && version `T.isInfixOf` decodeUtf8 (LBS.toStrict (responseBody resp))
            )

{- | Every package name the store lists, read through the same @\/-\/all@ document and the same
projector the protocol maintenance leaf drives. It is what a sweep intersects its candidates with,
so an image whose listing changed shape fails here rather than inside a cycle.
-}
verdaccioListing :: E2E -> IO [Text]
verdaccioListing e2e = map renderPackageName <$> verdaccioPackages e2e

{- | Wait until the listing names a package. A sweep walks this document rather than a packument,
so a case that seeds a package for one waits here: a store can serve a version it has not listed.
It answers 'Nothing' once the name arrives, and otherwise what the store served instead, because a
sweep that found no candidate and a store that listed nothing report the same empty cycle.
-}
verdaccioAwaitListed :: E2E -> Text -> IO (Maybe Text)
verdaccioAwaitListed e2e pkg = do
    listed <- pollUntil 40 500000 id (handleAny (\_ -> pure False) (elem pkg <$> verdaccioListing e2e))
    if listed then pure Nothing else Just <$> unlistedReport e2e pkg

{- The evidence a never-listed package leaves: the names the projector read, and the document they
came from, bounded so one failure stays readable.
-}
unlistedReport :: E2E -> Text -> IO Text
unlistedReport e2e pkg =
    handleAny (\err -> pure (preamble <> "the listing could not be read: " <> show err)) $ do
        body <- verdaccioListingBody e2e
        pure
            ( preamble
                <> "the projector read: "
                <> either parseErrorMessage (T.intercalate ", " . map renderPackageName) (parsePackageListing body)
                <> "\nthe store served (first 2048 characters): "
                <> T.take 2048 (decodeUtf8 body)
            )
  where
    preamble = "the store never listed " <> pkg <> "; "

{- | The names the store lists that fall in one bucket of the name space, through the same
predicate a store with no prefix filter of its own is walked by.
-}
verdaccioNamesUnder :: E2E -> Text -> IO [Text]
verdaccioNamesUnder e2e raw = do
    names <- verdaccioPackages e2e
    prefix <- maybe (fail ("no bucket spells " <> toString raw)) pure (parseNamePrefix (mkNameAlphabet (toString raw)) raw)
    pure (map renderPackageName (filter (inBucket prefix) names))

verdaccioPackages :: E2E -> IO [PackageName]
verdaccioPackages e2e = do
    body <- verdaccioListingBody e2e
    either (fail . toString . parseErrorMessage) pure (parsePackageListing body)

-- The listing document unparsed, so a failure can report what the store actually served.
verdaccioListingBody :: E2E -> IO ByteString
verdaccioListingBody e2e = do
    req <- parseRequest (toString (e2eVerdaccio e2e <> "/-/all"))
    resp <- httpLbs req (e2eManager e2e)
    when (statusCode (responseStatus resp) /= 200) (fail "the store served no package listing")
    pure (LBS.toStrict (responseBody resp))
