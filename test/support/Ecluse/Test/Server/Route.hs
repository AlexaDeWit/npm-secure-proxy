-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Generators for a route table's properties, shared across ecosystems.

The module name follows this support library's @Ecluse.X -> Ecluse.Test.X@ convention, and
mirrors "Ecluse.Core.Server.Route".

A router property explores paths, and the traversal, separator, and control fragments it must
explore are the same whatever protocol the table speaks. 'genPathSegmentFrom' builds those in
and takes the ecosystem's own names and route words as literals, so a second table reuses the
hostile half rather than restating it.

'claimsEveryRendering' is the other shared property: every URL a route renders must be a URL
that same route claims. A rendered URL no route claims is a @404@ on every install, and one a
/different/ route claims is worse, so each ecosystem holds its table to it.
-}
module Ecluse.Test.Server.Route (
    genPathSegmentsFrom,
    genPathSegmentFrom,
    genSegmentName,
    claimsEveryRendering,
) where

import Hedgehog (Gen, PropertyT, annotateShow, failure, (===))
import Hedgehog.Gen qualified as Gen
import Hedgehog.Range qualified as Range
import Network.HTTP.Types.Method (methodGet)

import Ecluse.Core.Server.Route (Route (routeName), RouteName, matchRoute, renderRoute)

-- | A URL path of arbitrary segments, at the length a router's property explores.
genPathSegmentsFrom :: [Text] -> Gen [Text]
genPathSegmentsFrom = Gen.list (Range.linear 0 4) . genPathSegmentFrom

{- | One path segment: a plain name, one of the built-in hostile fragments or the caller's own
@literals@, or free text over the punctuation a path carries.
-}
genPathSegmentFrom :: [Text] -> Gen Text
genPathSegmentFrom literals =
    Gen.frequency
        [ (5, genSegmentName)
        , (4, Gen.element (hostileFragments <> literals))
        , (4, Gen.text (Range.linear 0 8) (Gen.element segmentChars))
        ]

-- | A plain segment name: alphanumerics, with the punctuation a name component may carry.
genSegmentName :: Gen Text
genSegmentName =
    Gen.text (Range.linear 1 8) (Gen.frequency [(8, Gen.alphaNum), (2, Gen.element ['.', '-', '_'])])

-- Traversal, separator, and control fragments no router may trust a segment with.
hostileFragments :: [Text]
hostileFragments =
    [ ""
    , "."
    , ".."
    , "-"
    , "-foo"
    , "a/b"
    , "a\\b"
    , "a\tb"
    , "a\0b"
    , "foo/bar"
    ]

segmentChars :: String
segmentChars = ['a', 'b', 'c', 'n', 'p', 'm', '@', '-', '/', '.', '%', ' ', '1', '2', '3', '4']

{- | Assert that the named route's own rendering of one set of captures is a URL that same
route claims out of its table.

The captures come from the caller, because building a legal one is the ecosystem's own grammar.
A route that renders nothing for them fails the property: the captures did not fill its
template, which is a table whose render and match disagree.
-}
claimsEveryRendering :: (Monad m) => [Route v] -> RouteName -> [v] -> PropertyT m ()
claimsEveryRendering table name captures =
    case find ((== name) . routeName) table of
        Nothing -> refuse "the table declares no route under this name"
        Just route -> case renderRoute route captures of
            Nothing -> refuse "the route rendered no path for its own captures"
            Just segments -> do
                annotateShow segments
                fmap (unName . routeName . fst) (matchRoute table methodGet [] segments) === Just (unName name)
  where
    refuse reason = do
        annotateShow (unName name, reason :: Text)
        failure

-- The route name as text, so a mismatch reports which route claimed the rendering.
unName :: RouteName -> Text
unName = show
