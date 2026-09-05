-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Version identity and ordering.

A 'Version' carries the raw text verbatim, because version strings are embedded in
artifact URLs and re-served, so fidelity matters. Beside it sits a parsed, canonical
'VersionKey', present only when the raw text parses for its ecosystem. Ordering goes
through 'compareVersions', which is defined __only__ on parsed keys, so non-canonical
text can never reach the comparator (/parse, don't validate/).

Parsing is per-ecosystem, selected by the 'Ecosystem' tag from
"Ecluse.Core.Ecosystem": semver for npm ("Ecluse.Core.Version.Semver"), PEP 440 for PyPI
("Ecluse.Core.Version.Pep440"), @Gem::Version@ for RubyGems ("Ecluse.Core.Version.Gem").
Each grammar and its ordering rules live in its own module. This module is the
agnostic abstraction that dispatches to them on the 'Ecosystem' tag. The grammar
modules stay __private__: callers build with 'mkVersion' (total) or 'parseVersionKey'
(reports the parse error) and compare with 'compareVersions'.

"Ecluse.Core.Package" consumes this vocabulary (@PackageDetails@ holds a 'Version'), as
does the rules engine ("Ecluse.Core.Rules"). See
@docs\/architecture\/domain-model.md@ → "Version".
-}
module Ecluse.Core.Version (
    -- * Versions
    Version,
    versionKey,
    mkVersion,
    renderVersion,
    compareVersions,

    -- * Canonical ordering keys
    VersionKey,
    parseVersionKey,
    VersionError (..),
    isStable,

    -- * Canonical PEP 440 spelling
    canonicalPep440,

    -- * Resolving @dist-tags.latest@
    selectLatest,
) where

import Data.Foldable (maximumBy)
import Data.List.NonEmpty qualified as NE

import Ecluse.Core.Ecosystem (Ecosystem (..))
import Ecluse.Core.Version.Gem (GemKey, isGemStable, parseGem)
import Ecluse.Core.Version.Pep440 (Pep440Key, isPep440Stable, parsePep440, renderPep440)
import Ecluse.Core.Version.Semver (SemverKey, isSemverStable, parseSemver)

{- | A package version.

It keeps the raw text verbatim, because version strings are embedded in artifact URLs
and re-served. Ordering instead uses the parsed 'VersionKey'.

There is deliberately __no__ 'Ord' on 'Version'. Comparison goes through
'compareVersions', which is defined only on parsed keys, so non-canonical text can never
reach the comparator.
-}
data Version = Version
    { -- The version as published: for rendering and round-tripping only, never
      -- for ordering decisions.
      versionRaw :: Text
    , versionKey :: Maybe VersionKey
    {- ^ The parsed, canonical ordering key. 'Nothing' if the raw text did not parse
    for its ecosystem, in which case ordering rules abstain.
    -}
    }
    deriving stock (Eq, Show)

{- | Build a 'Version', parsing the raw text into a canonical key when possible.
Total: a version that does not parse is still represented, with no key, rather than
rejected. A proxy therefore never drops a version over a parser gap.
-}
mkVersion :: Ecosystem -> Text -> Version
mkVersion eco raw = Version raw (rightToMaybe (parseVersionKey eco raw))

-- | Render a version in wire form: the raw text, verbatim as published.
renderVersion :: Version -> Text
renderVersion = versionRaw

{- | Compare two versions by their canonical keys. 'Nothing' when either version has no
key, in which case an ordering-based rule abstains.
-}
compareVersions :: Version -> Version -> Maybe Ordering
compareVersions a b = compare <$> versionKey a <*> versionKey b

{- | Whether a parsed version is a __stable__ (final, non-prerelease) release. The notion
is ecosystem-specific: see 'isSemverStable', 'isPep440Stable' and 'isGemStable'.

>>> isStable <$> parseVersionKey Npm "1.0.0"
Right True
>>> isStable <$> parseVersionKey Npm "1.0.0-rc.1"
Right False
>>> isStable <$> parseVersionKey PyPI "1.0.post1"
Right True
>>> isStable <$> parseVersionKey PyPI "1.0a1.dev2"
Right False
>>> isStable <$> parseVersionKey RubyGems "1.0.0.pre"
Right False
-}
isStable :: VersionKey -> Bool
isStable = \case
    NpmKey k -> isSemverStable k
    PyPIKey k -> isPep440Stable k
    RubyGemsKey k -> isGemStable k

{- | The one spelling a PEP 440 version canonicalises to, or 'Nothing' when it does not parse.
A PyPI projection keys its versions by this, so two spellings of one release merge into one
entry; the raw spelling survives per artifact through the filename.

>>> canonicalPep440 "1.0.0"
Just "1"
>>> canonicalPep440 "not-a-version"
Nothing
-}
canonicalPep440 :: Text -> Maybe Text
canonicalPep440 = fmap renderPep440 . parsePep440

{- | Resolve @dist-tags.latest@ once the caller has filtered out the denied and
undecidable versions. This is the keep-unless-denied, stable-preferring rule from
@docs\/architecture\/rules-engine.md@. The result, when present, is always one of
@survivors@.

The resolution, in order:

* No survivors: 'Nothing'.
* Keep: if @chosen@ survives by raw text, return it unchanged, so a prerelease never
displaces a maintainer's stable @latest@.
* Repoint: among survivors with a parseable key, take the greatest stable one, else the
greatest prerelease one.
* No parseable survivor: fall back to the lexicographically smallest survivor by
'renderVersion', so the result still names a present version.
-}
selectLatest :: Maybe Version -> [Version] -> Maybe Version
selectLatest chosen survivors = case nonEmpty survivors of
    Nothing -> Nothing
    Just survivors1
        | Just v <- chosen, survives v -> Just v
        | otherwise -> Just (repointLatest survivors1)
  where
    survives v = any ((== renderVersion v) . renderVersion) survivors

-- The repoint arm of 'selectLatest', whose Haddock documents the resolution order.
repointLatest :: NonEmpty Version -> Version
repointLatest survivors =
    let keyed = [(v, k) | v <- toList survivors, Just k <- [versionKey v]]
        stable = [vk | vk@(_, k) <- keyed, isStable k]
     in case nonEmpty stable of
            Just s -> fst (maxByKey s)
            Nothing -> case nonEmpty keyed of
                Just ks -> fst (maxByKey ks)
                -- No parseable survivor: deterministic, present fallback.
                Nothing -> NE.head (NE.sortWith renderVersion survivors)
  where
    -- Greatest by canonical key. Total, because every element carries a key.
    maxByKey :: NonEmpty (Version, VersionKey) -> (Version, VersionKey)
    maxByKey = maximumBy (comparing snd)

-- | Why a version string failed to parse.
newtype VersionError = VersionError
    { versionErrorMessage :: Text
    }
    deriving stock (Eq, Show)

{- | The parsed, canonical, comparable form of a version. The type is __opaque__ and
'parseVersionKey' is its only constructor, so the comparator structurally cannot see
non-canonical input. Its 'Ord' is meaningful only within one ecosystem, the only case
that arises.
-}
data VersionKey
    = NpmKey SemverKey
    | PyPIKey Pep440Key
    | RubyGemsKey GemKey
    deriving stock (Eq, Ord, Show)

{- | Parse raw version text into a canonical 'VersionKey' for its ecosystem, or report
why it did not parse.
-}
parseVersionKey :: Ecosystem -> Text -> Either VersionError VersionKey
parseVersionKey eco raw = case eco of
    Npm -> note (NpmKey <$> parseSemver raw)
    PyPI -> note (PyPIKey <$> parsePep440 raw)
    RubyGems -> note (RubyGemsKey <$> parseGem raw)
  where
    note = maybe (Left (VersionError ("unparseable version: " <> raw))) Right
