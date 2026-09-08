-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

-- | A shared package catalogue and live-registry fetch path for the smoke and capture tiers.
module Ecluse.Test.RegistryCapture (
    -- * The curated catalogue
    Catalogue (..),
    loadCatalogue,
    decodeCatalogue,
    smokeRegistryPackages,

    -- * The live registry fetch
    registryUrl,
    fetchPackumentBody,
    fetchVersions,
    parseRegistryVersions,
) where

import Control.Exception (try)
import Data.Aeson (FromJSON (parseJSON), eitherDecode, withObject, (.:))
import Data.Aeson.Types (Parser)
import Data.ByteString.Lazy qualified as BSL
import Data.Map.Strict qualified as Map
import Data.Text qualified as T
import Network.HTTP.Client (
    Manager,
    httpLbs,
    parseUrlThrow,
    requestHeaders,
    responseBody,
    responseTimeout,
    responseTimeoutMicro,
 )

import Ecluse.Core.Ecosystem (Ecosystem (..), parseEcosystem)
import Ecluse.Core.Registry (RegistryResponse (RegistryResponse))
import Ecluse.Core.Registry.Npm.Project (parseVersionList)
import Ecluse.Core.Version (renderVersion)
import Ecluse.Test.Registry.PyPI.Wire qualified as PyPI
import Ecluse.Test.Registry.Rubygems.Wire qualified as Rubygems

-- | The curated package catalogue: the per-ecosystem smoke names and the benchmark-corpus capture pins, decoded from the shared JSON source.
data Catalogue = Catalogue
    { catSmokeNames :: Map Ecosystem [Text]
    -- ^ Curated gnarly-version package names per ecosystem, for the version-oracle differential.
    , catBenchPins :: Map Text Text
    -- ^ Benchmark-corpus capture pins: an npm package name to the version it is captured at.
    }
    deriving stock (Eq, Show)

instance FromJSON Catalogue where
    parseJSON = withObject "Catalogue" $ \o -> do
        rawNames <- o .: "smokeNames"
        pins <- o .: "pins"
        names <- Map.fromList <$> traverse parseEcoKey (Map.toList rawNames)
        pure Catalogue{catSmokeNames = names, catBenchPins = pins}
      where
        parseEcoKey :: (Text, [Text]) -> Parser (Ecosystem, [Text])
        parseEcoKey (k, vs) = case parseEcosystem k of
            Just eco -> pure (eco, vs)
            Nothing -> fail ("RegistryCapture: unknown ecosystem key in smokeNames: " <> toString k)

-- | The committed catalogue's path, relative to the package root the test suites run from. The Node corpus-capture script reads the same file, so both sides share one curated source.
cataloguePath :: FilePath
cataloguePath = "bench/corpus/pins.json"

-- | Decode a 'Catalogue' from raw JSON bytes.
decodeCatalogue :: LByteString -> Either String Catalogue
decodeCatalogue = eitherDecode

-- | Read and decode the committed catalogue from 'cataloguePath'. A missing or malformed file fails loudly because that is a committed-data defect, not a runtime condition a caller decides on.
loadCatalogue :: IO Catalogue
loadCatalogue = do
    raw <- readFileLBS cataloguePath
    either (\e -> fail (cataloguePath <> " did not decode: " <> e)) pure (decodeCatalogue raw)

-- | The curated smoke names as @(ecosystem, names)@ pairs, ordered by ecosystem. This is the shape the version-oracle differential iterates.
smokeRegistryPackages :: Catalogue -> [(Ecosystem, [Text])]
smokeRegistryPackages = Map.toList . catSmokeNames

-- | The registry endpoint that lists a package's published versions. It percent-encodes a scoped npm name (@\@types\/node@ → @\@types%2Fnode@).
registryUrl :: Ecosystem -> Text -> Text
registryUrl eco pkg = case eco of
    Npm -> "https://registry.npmjs.org/" <> T.replace "/" "%2F" pkg
    PyPI -> "https://pypi.org/pypi/" <> pkg <> "/json"
    RubyGems -> "https://rubygems.org/api/v1/versions/" <> pkg <> ".json"

-- The User-Agent every capture fetch identifies itself with.
captureUserAgent :: ByteString
captureUserAgent = "ecluse-registry-capture"

-- | Fetch a package's raw version-listing body from its registry. The result is 'Nothing' on any network failure or non-2xx status, so a live tier pends on absence instead of failing.
fetchPackumentBody :: Manager -> Ecosystem -> Text -> IO (Maybe LByteString)
fetchPackumentBody manager eco pkg = do
    result <- try $ do
        req0 <- parseUrlThrow (toString (registryUrl eco pkg))
        let req =
                req0
                    { requestHeaders = [("User-Agent", captureUserAgent)]
                    , responseTimeout = responseTimeoutMicro (30 * 1000 * 1000)
                    }
        responseBody <$> httpLbs req manager
    pure $ case result of
        Left (_ :: SomeException) -> Nothing
        Right body -> Just body

-- | Fetch a package's published version strings from its registry.
fetchVersions :: Manager -> Ecosystem -> Text -> IO (Maybe [Text])
fetchVersions manager eco pkg =
    (>>= parseRegistryVersions eco) <$> fetchPackumentBody manager eco pkg

-- | Extract a registry response's published version strings through each ecosystem's __canonical__ wire decoder, never a re-parse here.
parseRegistryVersions :: Ecosystem -> LByteString -> Maybe [Text]
parseRegistryVersions eco body = case eco of
    Npm -> rightToMaybe (map renderVersion <$> parseVersionList (RegistryResponse 200 (BSL.toStrict body)))
    PyPI -> PyPI.projectVersions <$> decode' body
    RubyGems -> Rubygems.listingVersions <$> decode' body
  where
    decode' :: (FromJSON a) => LByteString -> Maybe a
    decode' = rightToMaybe . eitherDecode
