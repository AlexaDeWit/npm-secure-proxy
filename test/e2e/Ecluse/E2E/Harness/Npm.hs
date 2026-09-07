-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | npm clients for end-to-end scenarios.
Each project isolates npm state and disables package lifecycle scripts.
-}
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

-- | Fail the assertion with npm's output when the command failed.
shouldSucceed :: (MonadIO m) => NpmResult -> m NpmResult
shouldSucceed res = liftIO $ case npmExit res of
    ExitSuccess -> pure res
    _ -> expectationFailure ("npm failed!\nSTDOUT:\n" <> T.unpack (npmStdout res) <> "\nSTDERR:\n" <> T.unpack (npmStderr res)) >> pure res

-- | Fail the assertion with npm's output when the command unexpectedly succeeded.
shouldFail :: (MonadIO m) => NpmResult -> m NpmResult
shouldFail res = liftIO $ case npmExit res of
    ExitSuccess -> expectationFailure ("npm incorrectly succeeded!\nSTDOUT:\n" <> T.unpack (npmStdout res) <> "\nSTDERR:\n" <> T.unpack (npmStderr res)) >> pure res
    _ -> pure res

-- | Isolate a consumer's npm state and remove its project directory after the action.
withNpmProject :: E2E -> (NpmProject -> IO a) -> IO a
withNpmProject e2e = withProjectContents e2e consumerPackageJson ""

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

-- | Prepare an isolated publisher with the token npm requires before contacting the proxy.
withPublishProject :: E2E -> Text -> Text -> (NpmProject -> IO a) -> IO a
withPublishProject e2e name version =
    withProjectContents
        e2e
        (publishPackageJson name version)
        (npmAuthLine (e2eRegistry e2e) publishAuthToken)

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

-- | Install from the project's lockfile without resolving package metadata.
npmCiIn :: NpmProject -> IO NpmResult
npmCiIn proj = runNpm proj ["ci"]

-- | Publish through the configured proxy with package lifecycle scripts disabled.
npmPublishIn :: NpmProject -> IO NpmResult
npmPublishIn proj = runNpm proj ["publish"]

-- | Install through the proxy in a temporary project that is removed after the command.
npmInstall :: E2E -> Text -> IO NpmResult
npmInstall e2e pkg = withNpmProject e2e (`npmInstallIn` pkg)

-- | Report whether installation executed a sentinel-writing lifecycle script that should be disabled.
installWithLifecycleProbe :: E2E -> IO (NpmResult, Bool)
installWithLifecycleProbe e2e =
    withProjectContents e2e lifecycleProbePackageJson "" $ \proj -> do
        res <- runNpm proj ["install"]
        ran <- doesFileExist (npDir proj </> lifecycleSentinel)
        pure (res, ran)

lifecycleSentinel :: FilePath
lifecycleSentinel = "lifecycle-script-ran"

lifecycleProbePackageJson :: Text
lifecycleProbePackageJson =
    "{\"name\":\"e2e-lifecycle-probe\",\"version\":\"1.0.0\",\"private\":true,\"scripts\":{\"postinstall\":\"touch lifecycle-script-ran\"}}\n"

consumerPackageJson :: Text
consumerPackageJson = "{\"name\":\"e2e-consumer\",\"version\":\"1.0.0\",\"private\":true}\n"

-- | Publish first-party packages into the Verdaccio store used by the proxy's private upstream.
publishTargetEnv :: [(Text, Text)]
publishTargetEnv =
    [ ("ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__VERDACCIO__URL", "https://mirror/")
    , ("ECLUSE_MOUNTS__NPM__FIRST_PARTY", publishScope)
    ]

-- | The configured first-party namespace, shared by all in-scope fixture names.
publishScope :: Text
publishScope = "@acme"

-- | An in-scope package for publication through the proxy.
publishInScopeName :: Text
publishInScopeName = publishScope <> "/e2e-publish"

-- | An out-of-scope package whose publication must stop before an upstream write.
publishOutOfScopeName :: Text
publishOutOfScopeName = "@rogue/e2e-shadow"

-- | A first-party package reserved for the Dredger's protection scenario.
publishDredgerName :: Text
publishDredgerName = publishScope <> "/e2e-dredger-first-party"

-- | The single version the publish scenarios publish (and read back).
publishVersion :: Text
publishVersion = "1.0.0"

-- The bearer token a publishable project's @.npmrc@ carries. It satisfies npm's client-side
-- publish gate, and the target accepts regardless, so the identity is immaterial at this tier.
publishAuthToken :: Text
publishAuthToken = "e2e-publisher-token"

-- npm refuses to publish a package marked private.
publishPackageJson :: Text -> Text -> Text
publishPackageJson name version =
    "{\"name\":\"" <> name <> "\",\"version\":\"" <> version <> "\"}\n"

-- npm keys authentication by the registry's host and path, without its scheme.
npmAuthLine :: Text -> Text -> Text
npmAuthLine registry token =
    "//" <> withoutScheme registry <> ":_authToken=" <> token <> "\n"
  where
    withoutScheme u = fromMaybe u (T.stripPrefix "http://" u <|> T.stripPrefix "https://" u)
