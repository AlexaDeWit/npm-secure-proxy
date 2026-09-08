-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT
{-# LANGUAGE OverloadedStrings #-}

{- | Decode advisory evidence for the compiled artifact.
Package keys use the same ecosystem identity as policy queries.
-}
module Ecluse.Core.Osv.Advisory (
    OsvAdvisory (..),
    OsvAffected (..),
    OsvPackage (..),
    OsvRange (..),
    OsvEvent (..),
    OsvDatabaseSpecific (..),
    OsvSeverityEntry (..),
    ExtractedOsv (..),
    advisorySeverity,
    extractFromAdvisory,
    orderableBounds,
    unorderableBounds,
    osvExportUrl,
) where

import Data.Aeson (FromJSON (..), withObject, (.:), (.:?))
import Data.Text qualified as T
import Data.Universe.Class (Universe (universe))
import Security.CVSS (cvssScore, parseCVSS)

import Ecluse.Core.Ecosystem (Ecosystem)
import Ecluse.Core.Osv.Ecosystem (osvEcosystemFor, osvExportDirectory)
import Ecluse.Core.Osv.Epss (EpssScores, epssForIds)
import Ecluse.Core.Osv.Types (UpperBound (..))
import Ecluse.Core.Package (canonicalise)
import Ecluse.Core.Text (joinUrlPath)
import Ecluse.Core.Version (parseVersionKey)

-- | Build the ecosystem archive URL under a configured OSV export base.
osvExportUrl :: Text -> Text -> String
osvExportUrl baseUrl ecosystem = toString (joinUrlPath baseUrl (ecosystem <> "/all.zip"))

-- | Exact model of what osv.dev makes available
data OsvAdvisory = OsvAdvisory
    { osvId :: Text
    , osvAliases :: Maybe [Text]
    {- ^ The same vulnerability's identifiers in other databases. An npm advisory is
    GHSA-keyed, so its CVE ids live here, and they are what the EPSS feed keys on.
    -}
    , osvAffected :: Maybe [OsvAffected]
    , osvSeverity :: Maybe [OsvSeverityEntry]
    , osvDatabaseSpecific :: Maybe OsvDatabaseSpecific
    }
    deriving stock (Show, Eq)

instance FromJSON OsvAdvisory where
    parseJSON = withObject "OsvAdvisory" $ \v ->
        OsvAdvisory
            <$> v .: "id"
            <*> v .:? "aliases"
            <*> v .:? "affected"
            <*> v .:? "severity"
            <*> v .:? "database_specific"

{- | One entry of an advisory's @severity@ array: a scoring-system tag (@CVSS_V3@) and
its value. For a CVSS system that value is the /vector string/, not a number.
-}
data OsvSeverityEntry = OsvSeverityEntry
    { sevType :: Text
    , sevScore :: Text
    }
    deriving stock (Show, Eq)

instance FromJSON OsvSeverityEntry where
    parseJSON = withObject "OsvSeverityEntry" $ \v ->
        OsvSeverityEntry
            <$> v .: "type"
            <*> v .: "score"

-- | The subset of an advisory's @database_specific@ block the pipeline consumes.
newtype OsvDatabaseSpecific = OsvDatabaseSpecific
    { dbsSeverity :: Maybe Text
    {- ^ The source database's qualitative severity label (for GHSA-sourced npm
    advisories: @LOW@, @MODERATE@, @HIGH@, or @CRITICAL@).
    -}
    }
    deriving stock (Show, Eq)

instance FromJSON OsvDatabaseSpecific where
    parseJSON = withObject "OsvDatabaseSpecific" $ \v ->
        OsvDatabaseSpecific
            <$> v .:? "severity"

data OsvAffected = OsvAffected
    { affectedPackage :: OsvPackage
    , affectedRanges :: Maybe [OsvRange]
    , affectedVersions :: Maybe [Text]
    {- ^ Exact affected versions enumerated outside any range, each an affected point.
    Much of the npm malware feed names the single bad version here with no @ranges@.
    -}
    }
    deriving stock (Show, Eq)

instance FromJSON OsvAffected where
    parseJSON = withObject "OsvAffected" $ \v ->
        OsvAffected
            <$> v .: "package"
            <*> v .:? "ranges"
            <*> v .:? "versions"

data OsvPackage = OsvPackage
    { packageName :: Text
    , packageEcosystem :: Text
    }
    deriving stock (Show, Eq)

instance FromJSON OsvPackage where
    parseJSON = withObject "OsvPackage" $ \v ->
        OsvPackage
            <$> v .: "name"
            <*> v .: "ecosystem"

data OsvRange = OsvRange
    { rangeType :: Text
    , rangeEvents :: [OsvEvent]
    }
    deriving stock (Show, Eq)

instance FromJSON OsvRange where
    parseJSON = withObject "OsvRange" $ \v ->
        OsvRange
            <$> v .: "type"
            <*> v .: "events"

{- | One event in a range's ordered event list, carrying exactly one bound. @introduced@ opens
the affected interval inclusively, @fixed@ closes it exclusively, and @last_affected@ inclusively.
-}
data OsvEvent = OsvEvent
    { eventIntroduced :: Maybe Text
    , eventFixed :: Maybe Text
    , eventLastAffected :: Maybe Text
    }
    deriving stock (Show, Eq)

instance FromJSON OsvEvent where
    parseJSON = withObject "OsvEvent" $ \v ->
        OsvEvent
            <$> v .:? "introduced"
            <*> v .:? "fixed"
            <*> v .:? "last_affected"

{- | An artifact segment keyed by the ecosystem's canonical package name.
A missing introduced bound means affected from the beginning.
-}
data ExtractedOsv = ExtractedOsv
    { extPackage :: Text
    , extEcosystem :: Text
    , extCveId :: Text
    , extIntroduced :: Maybe Text
    , extUpperBound :: UpperBound
    , extSeverity :: Maybe Double
    {- ^ The advisory's CVSS base score (0 to 10), carried onto each of its segments.
    'Nothing' when the advisory is unscored, as much of the npm malware feed is.
    -}
    , extEpss :: Maybe Double
    {- ^ The advisory's EPSS probability (0 to 1), carried onto each of its segments.
    'Nothing' when the feed scores none of its identifiers.
    -}
    }
    deriving stock (Show, Eq)

-- | Prefer the highest parsing CVSS vector, then the qualitative label's ceiling, or no score.
advisorySeverity :: OsvAdvisory -> Maybe Double
advisorySeverity adv = vectorScore <|> labelScore
  where
    vectorScore = case mapMaybe (parseVectorScore . sevScore) (fromMaybe [] (osvSeverity adv)) of
        [] -> Nothing
        (s : ss) -> Just (foldl' max s ss)
    labelScore = ghsaSeverityCeiling =<< (dbsSeverity =<< osvDatabaseSpecific adv)

-- The CVSS base score of a vector string via the library, or 'Nothing' if it does
-- not parse (a CVSS version this build's parser rejects).
parseVectorScore :: Text -> Maybe Double
parseVectorScore = either (const Nothing) (Just . oneDecimal . snd . cvssScore) . parseCVSS

-- The CVSS specification defines base scores to one decimal place. Rounding in 'Double'
-- space keeps the stored value exact to compare, not a Float-to-Double widening artefact.
oneDecimal :: Float -> Double
oneDecimal f = fromIntegral (round (realToFrac f * 10 :: Double) :: Integer) / 10

-- Use the band's ceiling so a qualitative score cannot fall below its possible deny threshold.
ghsaSeverityCeiling :: Text -> Maybe Double
ghsaSeverityCeiling label = case T.toUpper (T.strip label) of
    "NONE" -> Just 0.0
    "LOW" -> Just 3.9
    "MODERATE" -> Just 6.9
    "MEDIUM" -> Just 6.9
    "HIGH" -> Just 8.9
    "CRITICAL" -> Just 10.0
    _ -> Nothing

{- | Canonicalise package keys and retain raw version bounds for every affected segment.
Unknown ecosystems keep their package spelling.
-}
extractFromAdvisory :: EpssScores -> OsvAdvisory -> [ExtractedOsv]
extractFromAdvisory scores adv = do
    aff <- fromMaybe [] (osvAffected adv)
    let pkg = affectedPackage aff
        eco = find ((== packageEcosystem pkg) . osvExportDirectory . osvEcosystemFor) universe
        name = maybe id canonicalise eco (packageName pkg)
    Segment intro upper <- affectedSegments aff
    pure $
        ExtractedOsv
            { extPackage = name
            , extEcosystem = packageEcosystem pkg
            , extCveId = osvId adv
            , extIntroduced = intro
            , extUpperBound = upper
            , extSeverity = severity
            , extEpss = epss
            }
  where
    -- Shared across every segment the advisory yields: both scores are a property of
    -- the advisory, not of a segment.
    severity = advisorySeverity adv
    -- The feed keys on CVE ids, and an npm row keys on the GHSA id, so the join runs
    -- over the advisory's own id and its aliases together.
    epss = epssForIds scores (osvId adv : fromMaybe [] (osvAliases adv))

{- | Does every bound this segment carries parse under the ecosystem's version grammar? A bound
that does not leaves 'Ecluse.Core.Cve.insideAffectedRange' matching every version, fail-closed.
-}
orderableBounds :: Ecosystem -> ExtractedOsv -> Bool
orderableBounds eco = null . unorderableBounds eco

-- | The bounds this segment carries that the ecosystem's version grammar cannot parse.
unorderableBounds :: Ecosystem -> ExtractedOsv -> [Text]
unorderableBounds eco osv = filter (not . parses) (catMaybes [extIntroduced osv, upperBound (extUpperBound osv)])
  where
    parses = isRight . parseVersionKey eco

    upperBound = \case
        FixedBefore f -> Just f
        LastAffected la -> Just la
        Unbounded -> Nothing

-- One affected interval: an inclusive lower bound and where it closes.
data Segment = Segment (Maybe Text) UpperBound

-- OSV spells "affected from the beginning" as @introduced: "0"@, which semver rejects. Decoded here
-- to no lower bound. An enumerated version of @"0"@ is a version, not a sentinel, and never comes here.
rangeSegment :: Maybe Text -> UpperBound -> Segment
rangeSegment introduced = Segment (introduced >>= beyondTheBeginning)
  where
    beyondTheBeginning i = if i == "0" then Nothing else Just i

affectedSegments :: OsvAffected -> [Segment]
affectedSegments aff =
    maybe [] (concatMap (extractRange . rangeEvents) . filter versionTyped) (affectedRanges aff)
        <> maybe [] (map exactVersion) (affectedVersions aff)
  where
    exactVersion v = Segment (Just v) (LastAffected v)

    -- Git commits are not version bounds. Treating them as unorderable versions would deny every release.
    versionTyped :: OsvRange -> Bool
    versionTyped r = T.toUpper (T.strip (rangeType r)) `elem` ["SEMVER", "ECOSYSTEM"]

-- An introduced event closes an already-open interval as unbounded.
extractRange :: [OsvEvent] -> [Segment]
extractRange = go Nothing
  where
    go Nothing [] = []
    go (Just i) [] = [rangeSegment (Just i) Unbounded]
    go current (e : es)
        | Just i <- eventIntroduced e =
            case current of
                Just prev -> rangeSegment (Just prev) Unbounded : go (Just i) es
                Nothing -> go (Just i) es
        | Just f <- eventFixed e = rangeSegment current (FixedBefore f) : go Nothing es
        | Just la <- eventLastAffected e = rangeSegment current (LastAffected la) : go Nothing es
        | otherwise = go current es
