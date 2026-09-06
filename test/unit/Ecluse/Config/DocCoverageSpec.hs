-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Config.DocCoverageSpec (spec) where

import Data.Char (isAsciiLower)
import Data.Text qualified as T
import System.Directory (listDirectory)
import System.FilePath (takeExtension, (</>))
import Test.Hspec

import Ecluse.Config (loadConfig, renderConfigError)

{- | Every operator-facing @ECLUSE_*@ spelling outside a mount's tagged endpoints, paired with a
value the loader must accept. Each needs its document key in @config\/default.yaml@, and must load.
-}
documentedEnvVars :: [(String, String)]
documentedEnvVars =
    [ ("ECLUSE_SERVER__PORT", "8081")
    , ("ECLUSE_SERVER__PUBLIC_URL", "https://registry.example.test")
    , ("ECLUSE_SERVER__AUTH_TOKEN", "edge-token")
    , ("ECLUSE_SERVER__HELP_MESSAGE", "ask platform engineering")
    , ("ECLUSE_SERVER__SHUTDOWN_DRAIN_TIMEOUT", "5")
    , ("ECLUSE_QUEUE__URL", "https://sqs.us-east-1.amazonaws.com/123456789012/mirror")
    , ("ECLUSE_QUEUE__MAX_MEMORY_DEPTH", "100")
    , ("ECLUSE_QUEUE__MAX_RECEIVE_COUNT", "8")
    , ("ECLUSE_LIMITS__MAX_RESPONSE_BYTES", "1048576")
    , ("ECLUSE_LIMITS__MAX_REQUEST_BYTES", "1048576")
    , ("ECLUSE_LIMITS__MAX_VERSION_COUNT", "100")
    , ("ECLUSE_LIMITS__MAX_ARTIFACT_COUNT", "100")
    , ("ECLUSE_LIMITS__MAX_NESTING_DEPTH", "16")
    , ("ECLUSE_LIMITS__MAX_ADVISORY_DATABASE_BYTES", "1048576")
    , ("ECLUSE_CACHE__TTL", "30")
    , ("ECLUSE_CACHE__MAX_ENTRIES", "64")
    , ("ECLUSE_CACHE__MAX_BYTES", "1048576")
    , ("ECLUSE_INTEGRITY__MIN_PUBLIC", "sha256")
    , ("ECLUSE_INTEGRITY__MIN_TRUSTED", "sha256")
    , ("ECLUSE_INTEGRITY__DIVERGENCE_POLICY", "warn")
    , ("ECLUSE_EGRESS__ADDITIONAL_BLOCKED_RANGES", "198.18.0.0/15")
    , ("ECLUSE_ADVISORIES__URL", "s3://advisories/ecluse")
    , ("ECLUSE_ADVISORIES__POLL_INTERVAL", "60")
    , ("ECLUSE_ADVISORIES__COMPILE_INTERVAL", "3600")
    , ("ECLUSE_ADVISORIES__DATA_DIR", "/var/lib/ecluse/advisories")
    , ("ECLUSE_ADVISORIES__OSV_EXPORT_BASE_URL", "https://osv.example.test")
    , ("ECLUSE_ADVISORIES__EPSS_FEED_URL", "https://epss.example.test/scores.csv.gz")
    , ("ECLUSE_RUNTIME__CORES", "2")
    , ("ECLUSE_RUNTIME__CORES_CEILING", "16")
    , ("ECLUSE_RUNTIME__MAX_HEAP_BYTES", "268435456")
    , ("ECLUSE_RUNTIME__SERVE_MAX_IN_FLIGHT", "8")
    , ("ECLUSE_RUNTIME__PUBLIC_CONNECTIONS_PER_HOST", "4")
    , ("ECLUSE_RUNTIME__PRIVATE_CONNECTIONS_PER_HOST", "4")
    , ("ECLUSE_OBSERVABILITY__LOG_FORMAT", "json")
    , ("ECLUSE_OBSERVABILITY__LOG_LEVEL", "info")
    , ("ECLUSE_OBSERVABILITY__TELEMETRY", "off")
    , ("ECLUSE_DREDGER__CHUNK_SIZE", "25")
    , ("ECLUSE_DREDGER__CHUNK_PAUSE", "5")
    , ("ECLUSE_DREDGER__CYCLE_PAUSE", "600")
    , ("ECLUSE_DREDGER__DELETION_CAP", "500")
    , ("ECLUSE_DREDGER__FULL_WALK", "true")
    , ("ECLUSE_RULES", "{\"min-age\":{\"ageSeconds\":100}}")
    , ("ECLUSE_MOUNTS__NPM__ENABLED", "true")
    , ("ECLUSE_MOUNTS__NPM__FIRST_PARTY", "@acme")
    , ("ECLUSE_MOUNTS__NPM__INTEGRITY__MIN_TRUSTED", "sha256")
    , ("ECLUSE_MOUNTS__NPM__INTEGRITY__DIVERGENCE_POLICY", "warn")
    ]

{- | The mount endpoint spellings, one loadable layer per store tag. An endpoint names exactly one
tag, so the three cannot be set together: two tags on one endpoint is itself a refusal.
-}
taggedMountLayers :: [[(String, String)]]
taggedMountLayers = [registryLayer, codeArtifactLayer, verdaccioLayer]

registryLayer :: [(String, String)]
registryLayer =
    [ ("ECLUSE_MOUNTS__NPM__PUBLIC_UPSTREAM__REGISTRY__URL", "https://registry.npmjs.org")
    , ("ECLUSE_MOUNTS__NPM__PRIVATE_UPSTREAM__REGISTRY__URL", "https://private.example.test")
    , ("ECLUSE_MOUNTS__NPM__MIRROR_TARGET__REGISTRY__URL", "https://mirror.example.test")
    , ("ECLUSE_MOUNTS__NPM__MIRROR_TARGET__REGISTRY__TOKEN", "mirror-write-token")
    , ("ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__REGISTRY__URL", "https://publish.example.test")
    , ("ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__REGISTRY__TOKEN", "publish-token")
    ]

codeArtifactLayer :: [(String, String)]
codeArtifactLayer =
    [ ("ECLUSE_MOUNTS__NPM__PUBLIC_UPSTREAM__REGISTRY__URL", "https://registry.npmjs.org")
    , ("ECLUSE_MOUNTS__NPM__PRIVATE_UPSTREAM__CODE_ARTIFACT__URL", codeArtifactRepository <> "internal/")
    , ("ECLUSE_MOUNTS__NPM__MIRROR_TARGET__CODE_ARTIFACT__URL", codeArtifactRepository <> "mirror/")
    , ("ECLUSE_MOUNTS__NPM__MIRROR_TARGET__CODE_ARTIFACT__TOKEN_DURATION", "3600")
    , ("ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__CODE_ARTIFACT__URL", codeArtifactRepository <> "internal/")
    , ("ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__CODE_ARTIFACT__TOKEN", "publish-token")
    ]

-- The npm-format repository endpoints of one CodeArtifact domain, which the tag validates against.
codeArtifactRepository :: String
codeArtifactRepository = "https://acme-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/"

verdaccioLayer :: [(String, String)]
verdaccioLayer =
    [ ("ECLUSE_MOUNTS__NPM__PUBLIC_UPSTREAM__REGISTRY__URL", "https://registry.npmjs.org")
    , ("ECLUSE_MOUNTS__NPM__PRIVATE_UPSTREAM__VERDACCIO__URL", "https://verdaccio.example.test/")
    , ("ECLUSE_MOUNTS__NPM__MIRROR_TARGET__VERDACCIO__URL", "https://verdaccio.example.test/")
    , ("ECLUSE_MOUNTS__NPM__MIRROR_TARGET__VERDACCIO__TOKEN", "mirror-write-token")
    , ("ECLUSE_MOUNTS__NPM__MIRROR_TARGET__VERDACCIO__PERMIT_DELETION", "true")
    , ("ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__VERDACCIO__URL", "https://verdaccio.example.test/")
    , ("ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__VERDACCIO__TOKEN", "publish-token")
    ]

{- | Process-level and indirection spellings: documented in the operator manual's prose,
because they are consumed before (or beside) config resolution and have no document key.
-}
documentedProcessVars :: [String]
documentedProcessVars =
    [ "ECLUSE_CONFIG"
    , "ECLUSE_SERVER__AUTH_TOKEN_FILE"
    , "ECLUSE_MOUNTS__NPM__MIRROR_TARGET__VERDACCIO__TOKEN_FILE"
    , "ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__CODE_ARTIFACT__TOKEN_FILE"
    ]

{- | Spellings the loader must refuse: the keys this configuration pass renamed, and a plain
typo. The loader owns the whole @ECLUSE_@ prefix, so each becomes an unknown document key.
-}
retiredEnvVars :: [(String, String)]
retiredEnvVars =
    [ ("ECLUSE_ADVISORIES__BUCKET", "advisories")
    , ("ECLUSE_ADVISORIES__MAX_DATABASE_BYTES", "1048576")
    , ("ECLUSE_QUEUE__MEMORY_MAX_DEPTH", "100")
    , ("ECLUSE_MOUNTS__NPM__MIN_TRUSTED_INTEGRITY", "sha256")
    , ("ECLUSE_MOUNTS__NPM__MIRROR_TARGET_TOKEN", "mirror-write-token")
    , ("ECLUSE_MOUNTS__NPM__MIRROR_TOKEN_DURATION", "3600")
    , ("ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET_TOKEN", "publish-token")
    , ("ECLUSE_MOUNTS__NPM__MIRROR_CODE_ARTIFACT_TOKEN_DURATION", "3600")
    , ("ECLUSE_MOUNTS__NPM__PUBLISH_ALLOW", "@acme")
    , ("ECLUSE_SERVER__PROT", "8080")
    , ("ECLUSE_NONSENSE", "1")
    ]

-- | Every Markdown page of the operator manual, read as one text.
readOperatorManual :: IO Text
readOperatorManual = do
    names <- listDirectory manualDir
    pages <- traverse (readFileBS . (manualDir </>)) (filter isMarkdown names)
    pure (foldMap decodeUtf8 pages)
  where
    manualDir = "web/content/docs"
    isMarkdown = (== ".md") . takeExtension

{- | The section and leaf a spelling resolves to (@ECLUSE_MOUNTS__NPM__INTEGRITY__MIN_TRUSTED@ is
@mounts@ and @minTrusted@), camel-cased as the resolver reads them. One segment names the section.
-}
documentKey :: String -> Maybe (Text, Maybe Text)
documentKey var = do
    body <- T.stripPrefix "ECLUSE_" (T.pack var)
    top :| rest <- nonEmpty (T.splitOn "__" body)
    pure (T.toLower top, camel <$> listToMaybe (reverse rest))
  where
    camel segment = case T.splitOn "_" (T.toLower segment) of
        (w : ws) -> w <> T.concat (map T.toTitle ws)
        [] -> ""

{- | Whether @config/default.yaml@ documents a key: its leaf under the section, or the section
alone for a spelling with no leaf. A commented @# key:@ counts, being how a computed default reads.
-}
documentsKey :: Text -> (Text, Maybe Text) -> Bool
documentsKey yaml (section, mLeaf) = case mLeaf of
    Nothing -> any isHeader allLines
    Just leaf -> any (keyLine leaf) sectionLines
  where
    allLines = T.lines yaml
    sectionLines = takeWhile (not . isSection) (drop 1 (dropWhile (not . isHeader) allLines))
    uncomment = T.stripStart . T.dropWhile (== '#') . T.stripStart
    topLevel l = not (T.isPrefixOf " " l)
    isHeader l = topLevel l && uncomment l == section <> ":"
    isSection l = topLevel l && maybe False (T.all isAsciiLower) (T.stripSuffix ":" (uncomment l))
    keyLine leaf l = T.isPrefixOf (leaf <> ":") (uncomment l)

spec :: Spec
spec = describe "the configuration reference covers the accepted variables" $ do
    it "config/default.yaml documents every golden-list key" $ do
        yaml <- decodeUtf8 <$> readFileBS "config/default.yaml"
        let missing =
                [ var
                | var <- map fst (documentedEnvVars <> concat taggedMountLayers)
                , maybe True (not . documentsKey yaml) (documentKey var)
                ]
        missing `shouldBe` []

    it "the operator manual mentions every process-level spelling" $ do
        manual <- readOperatorManual
        let missing =
                [ var
                | var <- documentedProcessVars
                , not (T.pack var `T.isInfixOf` manual)
                ]
        missing `shouldBe` []

    -- One layer per tag, because an endpoint carrying two of them is a refusal by design.
    it "keeps the golden list honest: every listed variable loads under its own tag" $
        for_ taggedMountLayers $ \layer ->
            loadConfig (documentedEnvVars <> layer) Nothing `shouldSatisfy` isRight

    -- The loader owns the whole ECLUSE_ prefix, so a retired or misspelled variable becomes an
    -- unknown document key rather than resolving quietly to its default.
    it "refuses every retired and misspelled ECLUSE_ variable, naming the key it could not place" $
        for_ retiredEnvVars $ \(var, value) ->
            case loadConfig [(var, value)] Nothing of
                Right _ -> expectationFailure (var <> ": expected a refusal, the load succeeded")
                Left errs ->
                    T.unlines (map renderConfigError errs)
                        `shouldSatisfy` T.isInfixOf (leafOf var)
  where
    -- The document spelling the refusal quotes: the variable's own leaf, or its top-level
    -- key when it names no leaf.
    leafOf var = case documentKey var of
        Just (_, Just leaf) -> leaf
        Just (section, Nothing) -> section
        Nothing -> ""
