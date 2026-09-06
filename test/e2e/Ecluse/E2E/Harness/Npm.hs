-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.E2E.Harness.Npm (
    npmInstall,
    npmInstallIn,
    npmCiIn,
    npmPublishIn,
    withNpmProject,
    withPublishProject,
    installWithLifecycleProbe,

    -- * Assertions
    shouldSucceed,
    shouldFail,

    -- * Constants
    publishTargetEnv,
    publishScope,
    publishInScopeName,
    publishOutOfScopeName,
    publishDredgerName,
    publishVersion,
) where

import Data.ByteString.Lazy qualified as LBS

import Data.Text qualified as T
import System.Directory (createDirectoryIfMissing, doesFileExist, getTemporaryDirectory, removePathForcibly)
import System.Exit (ExitCode (ExitSuccess))
import System.FilePath ((</>))
import System.Process.Typed (proc, readProcess, setEnv, setWorkingDir)
import Test.Hspec (expectationFailure)
import UnliftIO (bracket, handleAny)
import UnliftIO.Environment (getEnvironment)

import Ecluse.E2E.Harness.Docker (uniqueSuffix)
import Ecluse.E2E.Harness.Types

shouldSucceed :: (MonadIO m) => NpmResult -> m NpmResult
shouldSucceed res = liftIO $ case npmExit res of
    ExitSuccess -> pure res
    _ -> expectationFailure ("npm failed!\nSTDOUT:\n" <> T.unpack (npmStdout res) <> "\nSTDERR:\n" <> T.unpack (npmStderr res)) >> pure res

shouldFail :: (MonadIO m) => NpmResult -> m NpmResult
shouldFail res = liftIO $ case npmExit res of
    ExitSuccess -> expectationFailure ("npm incorrectly succeeded!\nSTDOUT:\n" <> T.unpack (npmStdout res) <> "\nSTDERR:\n" <> T.unpack (npmStderr res)) >> pure res
    _ -> pure res

{- | Bracket an isolated npm consumer project: a consumer @package.json@, an empty @.npmrc@, and
the pinned isolated environment. For a publish-capable project, see 'withPublishProject'.
-}
withNpmProject :: E2E -> (NpmProject -> IO a) -> IO a
withNpmProject e2e = withProjectContents e2e consumerPackageJson ""

{- The shared body behind 'withNpmProject' and 'withPublishProject'. The pinned cache,
userconfig, prefix, and @HOME@ keep developer global state out and the proxy the only registry. -}
withProjectContents :: E2E -> Text -> Text -> (NpmProject -> IO a) -> IO a
withProjectContents e2e packageJson npmrcContents use = do
    sfx <- uniqueSuffix
    tmpRoot <- getTemporaryDirectory
    let projectDir = tmpRoot </> ("ecluse-e2e-npm-" <> sfx)
        cacheDir = projectDir </> "cache"
        prefixDir = projectDir </> "prefix"
        npmrc = projectDir </> ".npmrc"
    bracket
        ( do
            createDirectoryIfMissing True cacheDir
            createDirectoryIfMissing True prefixDir
            writeFileText (projectDir </> "package.json") packageJson
            writeFileText npmrc npmrcContents
            baseEnv <- getEnvironment
            let overrides =
                    [ ("npm_config_registry", toString (e2eRegistry e2e))
                    , ("npm_config_cache", cacheDir)
                    , ("npm_config_userconfig", npmrc)
                    , ("npm_config_prefix", prefixDir)
                    , ("npm_config_audit", "false")
                    , ("npm_config_fund", "false")
                    , ("npm_config_update_notifier", "false")
                    , ("npm_config_progress", "false")
                    , -- No npm child may run an upstream package's lifecycle scripts, an arbitrary-code-execution
                      -- surface. This project sits outside the repo tree, beyond the root @.npmrc@'s reach.
                      ("npm_config_ignore_scripts", "true")
                    , -- npm's 10 s then 60 s retry backoff is sized for the public internet, and
                      -- every registry here is a container on a local network. Keep the retries.
                      ("npm_config_fetch_retry_mintimeout", "200")
                    , ("npm_config_fetch_retry_maxtimeout", "1000")
                    , ("HOME", projectDir)
                    ]
                cleanEnv =
                    filter
                        (\(k, _) -> k `notElem` map fst overrides && not ("npm_config_" `isPrefixOf` k))
                        baseEnv
                        <> overrides
            pure NpmProject{npDir = projectDir, npEnv = cleanEnv}
        )
        (\_ -> handleAny (const pass) (removePathForcibly projectDir))
        use

{- | Bracket an isolated, __publishable__ npm project. Without the @.npmrc@ bearer token npm
refuses the publish with @ENEEDAUTH@ before it reaches the proxy, so the identity is immaterial.
-}
withPublishProject :: E2E -> Text -> Text -> (NpmProject -> IO a) -> IO a
withPublishProject e2e name version =
    withProjectContents
        e2e
        (publishPackageJson name version)
        (npmAuthLine (e2eRegistry e2e) publishAuthToken)

-- | Run @npm@ with the given args in a project, capturing its exit and output.
runNpm :: NpmProject -> [String] -> IO NpmResult
runNpm proj args = do
    let cmd = setWorkingDir (npDir proj) . setEnv (npEnv proj) $ proc "npm" args
    (code, out, err) <- readProcess cmd
    pure
        NpmResult
            { npmExit = code
            , npmStdout = decodeUtf8 (LBS.toStrict out)
            , npmStderr = decodeUtf8 (LBS.toStrict err)
            }

-- | @npm install \<pkg\>@ in a project. It writes the lockfile for a later 'npmCiIn'.
npmInstallIn :: NpmProject -> Text -> IO NpmResult
npmInstallIn proj pkg = runNpm proj ["install", toString pkg]

{- | @npm ci@ in a project. It installs from the lockfile's @resolved@ URLs and never re-resolves
through the packument, so it never contacts the public upstream.
-}
npmCiIn :: NpmProject -> IO NpmResult
npmCiIn proj = runNpm proj ["ci"]

{- | @npm publish@ in a publishable project. A zero exit means the proxy admitted the publish and
the target accepted it, and a non-zero means the anti-shadowing guard refused the name with a @403@.
-}
npmPublishIn :: NpmProject -> IO NpmResult
npmPublishIn proj = runNpm proj ["publish"]

{- | @npm install \<pkg\>@ against the proxy in a throwaway project (see 'withNpmProject'),
for the one-shot cases that only need the install's outcome.
-}
npmInstall :: E2E -> Text -> IO NpmResult
npmInstall e2e pkg = withNpmProject e2e (`npmInstallIn` pkg)

{- | Install a project whose own @postinstall@ would create a sentinel file, and report whether it
appeared. The 'Bool' is 'False' on a faithful run, and flips to 'True' if script suppression breaks.
-}
installWithLifecycleProbe :: E2E -> IO (NpmResult, Bool)
installWithLifecycleProbe e2e =
    withProjectContents e2e lifecycleProbePackageJson "" $ \proj -> do
        res <- runNpm proj ["install"]
        ran <- doesFileExist (npDir proj </> lifecycleSentinel)
        pure (res, ran)

-- The file a lifecycle script would create. The path is relative, so it lands in the project root:
-- npm's working directory for a root package's own lifecycle scripts.
lifecycleSentinel :: FilePath
lifecycleSentinel = "lifecycle-script-ran"

-- The npm CLI runs a root package's lifecycle scripts on @npm install@ unless they are disabled,
-- so this @postinstall@ is a faithful probe for suppressed script execution.
lifecycleProbePackageJson :: Text
lifecycleProbePackageJson =
    "{\"name\":\"e2e-lifecycle-probe\",\"version\":\"1.0.0\",\"private\":true,\"scripts\":{\"postinstall\":\"touch lifecycle-script-ran\"}}\n"

consumerPackageJson :: Text
consumerPackageJson = "{\"name\":\"e2e-consumer\",\"version\":\"1.0.0\",\"private\":true}\n"

{- | The extra proxy environment that turns the first-party publish path __on__. The target is
Verdaccio, which the base topology also reads as the private upstream, so a published package is
readable back over the private leg. The relay forwards the client's own bearer, so no static token.
-}
publishTargetEnv :: [(Text, Text)]
publishTargetEnv =
    [ ("ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__VERDACCIO__URL", "https://mirror/")
    , ("ECLUSE_MOUNTS__NPM__FIRST_PARTY", publishScope)
    ]

{- | The first-party namespace 'publishTargetEnv' configures. Every in-scope name derives from
it, so the configured scope and the names cannot drift apart.
-}
publishScope :: Text
publishScope = "@acme"

{- | A first-party package __within__ the configured 'publishTargetEnv' scope, which the
anti-shadowing guard admits and the relay forwards to the publication target.
-}
publishInScopeName :: Text
publishInScopeName = publishScope <> "/e2e-publish"

{- | A package in a scope __outside__ the mount's first-party namespaces. The guard must refuse an
@npm publish@ of it __before__ any upstream write, the property the refuse-before-write scenario proves.
-}
publishOutOfScopeName :: Text
publishOutOfScopeName = "@rogue/e2e-shadow"

{- | A first-party package the sweep scenarios publish and no other case touches, so its survival
after a sweep that names it is attributable to the first-party belt alone.
-}
publishDredgerName :: Text
publishDredgerName = publishScope <> "/e2e-dredger-first-party"

-- | The single version the publish scenarios publish (and read back).
publishVersion :: Text
publishVersion = "1.0.0"

-- The bearer token a publishable project's @.npmrc@ carries. It satisfies npm's client-side
-- publish gate, and the target accepts regardless, so the identity is immaterial at this tier.
publishAuthToken :: Text
publishAuthToken = "e2e-publisher-token"

-- A publishable project's @package.json@: the scoped name and version npm packs and
-- publishes. Deliberately not @private@: npm refuses to publish a private package.
publishPackageJson :: Text -> Text -> Text
publishPackageJson name version =
    "{\"name\":\"" <> name <> "\",\"version\":\"" <> version <> "\"}\n"

-- The npm CLI keys auth by the registry URL's host and path, with the scheme stripped and a leading
-- @\/\/@.
npmAuthLine :: Text -> Text -> Text
npmAuthLine registry token =
    "//" <> withoutScheme registry <> ":_authToken=" <> token <> "\n"
  where
    withoutScheme u = fromMaybe u (T.stripPrefix "http://" u <|> T.stripPrefix "https://" u)
