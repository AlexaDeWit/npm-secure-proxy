-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.E2E.Harness.Verdaccio (
    verdaccioHasVersion,
    verdaccioHasVersionNow,
    verdaccioListing,
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
    req <- parseRequest (toString (e2eVerdaccio e2e <> "/-/all"))
    resp <- httpLbs req (e2eManager e2e)
    when (statusCode (responseStatus resp) /= 200) (fail "the store served no package listing")
    either (fail . toString . parseErrorMessage) pure (parsePackageListing (LBS.toStrict (responseBody resp)))
