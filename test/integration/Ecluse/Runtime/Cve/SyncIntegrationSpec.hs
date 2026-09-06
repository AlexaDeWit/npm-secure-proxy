-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The advisory fast lane, proven end to end in two phases against one booted proxy:

1. __Control__: the bucket is empty, so the gate denies the young security fix (@403@).
   The audit body carries both the fast lane's abstain reason (no advisory database
   is loaded) and the quarantine's. That proves the CVE rule ran, abstained for the
   stated cause, and left the ordinary policy to govern.
2. Pilot's real one-shot pipeline (@runPilotCompile@ with @--upload@) compiles the
   shared advisory corpus into an @osv.db@. It then uploads the database to the
   ministack S3 bucket through @exportToS3@. The running sync task's next poll
   detects, verifies, and shadow-swaps it, with no restart and no configuration
   change.
3. The identical request then returns @200@ with the version served: the fast
   lane opened because a synced advisory names it as the exact fix.

Hermetic and gating, but requires a Docker daemon (for @ministack@'s S3).
-}
module Ecluse.Runtime.Cve.SyncIntegrationSpec (spec) where

import Data.Aeson (Value, encode, object, (.=))
import Data.Text qualified as T
import Data.Time (UTCTime (UTCTime), fromGregorian, nominalDay)
import Katip (KatipContextT, SimpleLogPayload, runKatipContextT)
import Network.HTTP.Client (defaultManagerSettings, newManager)
import Network.HTTP.Types (status200)
import Network.Wai (Application)
import Network.Wai.Test (SResponse (simpleBody))
import System.IO.Temp (withSystemTempDirectory)
import Test.Hspec
import UnliftIO (tryAny)
import UnliftIO.Async (withAsync)

import Amazonka qualified as AWS
import Amazonka.S3 qualified as S3
import Conduit (runResourceT)
import Ecluse (mountBindingFor)
import Ecluse.Config (AppConfig, Config (configApp), loadConfig)
import Ecluse.Core.Breaker (noBreakerReporter)
import Ecluse.Core.Cve.Slot (currentAdvisoryEtag, newCveSlot, withSlotLookup)
import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.Rules (RuleDeps (..), prepare)
import Ecluse.Core.Rules.Types (Rule (AllowIfOlderThan, AllowIfRemediatesCve))
import Ecluse.Core.Security.Egress.DevHttp (loopbackRegistryUrl)
import Ecluse.Core.Server.Context (PackumentDeps (..))
import Ecluse.Core.Server.Upstream (MirrorServePlan (MirrorOnAdmit))
import Ecluse.Integration.Ministack (endpointFor, quietLogEnv, withMinistack)
import Ecluse.Pilot (PilotCompileOptions (..), runPilotCompile)
import Ecluse.Runtime.Aws.S3 (buildS3Env)
import Ecluse.Runtime.Cve.Sync (CveFetch (fetchDownload), OsvDbFetchFault (OsvDbTooLarge), SyncEnv (..), SyncSchedule (..), newS3CveSource, runCveSync, s3CveFetchFor)
import Ecluse.Runtime.Server (application, mkServerConfig)
import Ecluse.Runtime.Telemetry (telemetryDisabled)
import Ecluse.Runtime.Test.Support (newTestEnvWith)
import Ecluse.Server.Pipeline.TestSupport (getPath)
import Ecluse.Test.Osv (CorpusVersion (CorpusV1), osvCorpusZip)
import Ecluse.Test.OsvDb (epssFixtureFile)
import Ecluse.Test.Package (hexSha1Of, sriSha512Of)
import Ecluse.Test.Poll (pollUntil)
import Ecluse.Test.Port (noopAdvisorySyncMetricsPort, passthroughAdvisorySyncTracingPort)
import Ecluse.Test.Queue (newTestMemoryQueue)
import Ecluse.Test.Registry.Npm (VersionSpec (..), packumentValue, versionSpec, versionValue)
import Ecluse.Test.Rules (atDefaultPrecedence, noFaultReporter)
import Ecluse.Test.Server.Mount (npmServeDeps)
import Ecluse.Test.Stub (Captured (capHeaders), stubBaseUrl, stubLocalhostUrl, withRoutedStub, withStub)
import Ecluse.Test.Wai (rebaseAuthority, selfBaseUrlOf, status)

import Ecluse.Runtime.Aws.Env (AwsEndpoint (endpointHost, endpointPort))

spec :: Spec
spec =
    aroundAll withMinistack $
        describe "advisory sync + shadow swap (ministack S3, one proxy, two phases)" $
            it "denies the young fix with no database, then admits it once the synced artifact swaps in" $ \container ->
                withSystemTempDir $ \dataDir ->
                    withPublicUpstream $ \publicUrl ->
                        withPrivateUpstream $ \privateUrl -> do
                            -- The bucket, addressed exactly as the released image would
                            -- (the standard AWS_ENDPOINT_URL override), created empty.
                            let endpoint = endpointFor container
                                endpointUrl = "http://" <> endpointHost endpoint <> ":" <> show (endpointPort endpoint)
                                bucket = "cve-sync-spec"
                            appCfg <-
                                either (fail . ("CveSyncSpec fixture env: " <>) . show) (pure . configApp) $
                                    loadConfig (s3EnvVars endpointUrl bucket) Nothing
                            awsEnv <- buildS3Env (Just endpoint)
                            createBucketWithRetry awsEnv bucket 30
                            cveSource <- newS3CveSource (Just endpoint)

                            -- One proxy wiring: the slot, the fast-lane policy over it,
                            -- and the sync task polling the (empty) bucket.
                            slot <- newCveSlot
                            let ruleDeps =
                                    RuleDeps
                                        { rdWithCveLookup = withSlotLookup slot
                                        , rdCurrentAdvisoryEtag = currentAdvisoryEtag slot
                                        , rdBreakerReporter = noBreakerReporter
                                        , rdFaultReporter = noFaultReporter
                                        }
                                syncEnv =
                                    SyncEnv
                                        { syncFetch = s3CveFetchFor cveSource bucket "npm-osv-schema3.db" (512 * 1024 * 1024)
                                        , syncEcosystem = Npm
                                        , syncDbPath = dataDir <> "/npm-osv-schema3.db"
                                        , syncSlot = slot
                                        }
                                schedule = SyncSchedule{schedBootBackoff = [50_000, 50_000], schedPollDelay = 100_000}
                            app <- proxyApp ruleDeps privateUrl publicUrl
                            withAsync (runQuiet (runCveSync noopAdvisorySyncMetricsPort passthroughAdvisorySyncTracingPort syncEnv schedule pass)) $ \_ -> do
                                -- Phase 1 control: no database, and the fix is too young for the
                                -- quarantine, so the fast lane abstains and no version survives.
                                denied <- getPath "/npm/corpus-vuln" app
                                status denied `shouldBe` 403
                                let deniedBody = decodeUtf8 (simpleBody denied) :: Text
                                deniedBody `shouldSatisfy` T.isInfixOf "no advisory database is loaded"
                                deniedBody `shouldSatisfy` T.isInfixOf "minimum age"

                                -- The running sync task's next poll verifies the new artifact and
                                -- swaps it in, with no restart and no config change.
                                publishViaPilot (Just endpoint) appCfg CorpusV1

                                -- Phase 2: the proxy admits the identical request, and
                                -- the served document carries the fixed version.
                                served <- awaitAdmitted app "/npm/corpus-vuln"
                                (decodeUtf8 (simpleBody served) :: Text) `shouldSatisfy` T.isInfixOf "\"1.2.0\""

                                -- The fetch fails fast on the declared length, before any bytes
                                -- sink to disk.
                                let cappedFetch = s3CveFetchFor cveSource bucket "npm-osv-schema3.db" 16
                                fetchDownload cappedFetch (dataDir <> "/capped.db.tmp")
                                    `shouldReturn` Left (OsvDbTooLarge 16)
  where
    withSystemTempDir = withSystemTempDirectory "ecluse-cve-sync-spec"

-- The environment layer for the S3 side: the standard endpoint override and
-- credential keys, the required upstream, and the advisory store.
s3EnvVars :: Text -> Text -> [(String, String)]
s3EnvVars endpointUrl bucket =
    [ ("ECLUSE_SERVER__PUBLIC_URL", "https://registry.example.test")
    , ("ECLUSE_MOUNTS__NPM__PRIVATE_UPSTREAM__REGISTRY__URL", "https://private.invalid")
    , ("ECLUSE_MOUNTS__NPM__MIRROR_TARGET__REGISTRY__URL", "https://mirror.invalid")
    , ("ECLUSE_MOUNTS__NPM__MIRROR_TARGET__REGISTRY__TOKEN", "test-token")
    , ("ECLUSE_ADVISORIES__URL", toString ("s3://" <> bucket))
    , ("AWS_REGION", "us-east-1")
    , ("AWS_ENDPOINT_URL", toString endpointUrl)
    , ("AWS_ACCESS_KEY_ID", "test")
    , ("AWS_SECRET_ACCESS_KEY", "test")
    ]

-- Create the bucket, retrying while the container's S3 gateway finishes waking
-- (the readiness wait only proves the port accepts connections).
createBucketWithRetry :: AWS.Env -> Text -> Int -> IO ()
createBucketWithRetry awsEnv bucket attempts =
    pollUntil attempts 500_000 isRight attempt >>= \case
        Right _ -> pass
        Left err -> fail ("CveSyncSpec: bucket never became creatable: " <> show err)
  where
    attempt = tryAny (runResourceT (AWS.send awsEnv (S3.newCreateBucket (S3.BucketName bucket))))

-- The same compile-then-upload cycle the Pilot worker runs, never a direct PutObject. The
-- compile output lands in its own temp dir, apart from the proxy's sync data dir.
publishViaPilot :: Maybe AwsEndpoint -> AppConfig -> CorpusVersion -> IO ()
publishViaPilot s3Endpoint appCfg v = do
    zipBytes <- osvCorpusZip v
    epssBytes <- readFileLBS epssFixtureFile
    logEnv <- quietLogEnv
    withStub status200 zipBytes $ \stub ->
        withStub status200 epssBytes $ \epssStub ->
            withSystemTempDirectory "ecluse-pilot-out" $ \pilotDir ->
                void $
                    runPilotCompile
                        logEnv
                        telemetryDisabled
                        s3Endpoint
                        appCfg
                        PilotCompileOptions
                            { pcoEcosystem = "npm"
                            , pcoSource = Just (toString (stubBaseUrl stub) <> "/all.zip")
                            , pcoEpssSource = Just (toString (stubBaseUrl epssStub) <> "/epss.csv.gz")
                            , pcoOutDir = pilotDir
                            , pcoUpload = True
                            }

-- The real serve application over the shipped fast-lane policy: the quarantine plus
-- AllowIfRemediatesCve, with the packument stub as the public origin.
proxyApp :: RuleDeps -> Text -> Text -> IO Application
proxyApp ruleDeps privateUrl publicUrl = do
    prepared <- prepare ruleDeps [atDefaultPrecedence (AllowIfOlderThan (7 * nominalDay)), atDefaultPrecedence AllowIfRemediatesCve]
    manager <- newManager defaultManagerSettings
    queue <- newTestMemoryQueue
    env <- newTestEnvWith queue (manager, manager) telemetryDisabled
    let deps =
            ( npmServeDeps
                (Just (loopbackRegistryUrl privateUrl))
                (loopbackRegistryUrl publicUrl)
                (MirrorOnAdmit (loopbackRegistryUrl privateUrl))
                prepared
                (pure fixedNow)
            )
                { pdMountBaseUrl = "https://proxy.test/npm"
                , pdEgressUrl = Right . loopbackRegistryUrl
                }
    pure (application (mkServerConfig (maybeToList (mountBindingFor Npm deps Nothing))) env)

{- A single-version packument for @corpus-vuln\@1.2.0@, the fixed version GHSA-corpus-0001 names.
Its publish time is one day before the fixed clock, so only the fast lane can admit it, and its
artifact location is re-pointed at the port the stub came up on so the projection keeps it.
-}
withPublicUpstream :: (Text -> IO a) -> IO a
withPublicUpstream k = withRoutedStub selfHosted (k . stubLocalhostUrl)
  where
    selfHosted cap = (status200, [], rebaseAuthority artifactPlaceholder (selfBaseUrlOf (capHeaders cap)) (encode packument))

-- The authority the committed packument names, replaced by the stub's own before it is served.
artifactPlaceholder :: Text
artifactPlaceholder = "http://localhost:1"

{- The private upstream resolves with no versions, so the public leg and the rules decide.
A 404 would turn a total public denial into a retryable 503, hiding the 403 this test pins. -}
withPrivateUpstream :: (Text -> IO a) -> IO a
withPrivateUpstream k = withStub status200 (encode emptyPackument) (k . stubLocalhostUrl)

-- A well-formed packument naming no versions at all.
emptyPackument :: Value
emptyPackument = object ["name" .= ("corpus-vuln" :: Text), "dist-tags" .= object [], "versions" .= object []]

packument :: Value
packument =
    packumentValue
        "corpus-vuln"
        "1.2.0"
        [
            ( "1.2.0"
            , versionValue
                ( (versionSpec "corpus-vuln" "1.2.0" (artifactPlaceholder <> "/corpus-vuln/-/corpus-vuln-1.2.0.tgz"))
                    { vsIntegrity = Just sha512Integrity
                    , vsShasum = Just sha1Shasum
                    }
                )
            )
        ]
        ["1.2.0" .= ("2026-06-19T00:00:00.000Z" :: Text)]
        []

-- Placeholder artifact bytes carrying honest digests, so integrity admission
-- never confounds what the rules decided.
artifactBytes :: LByteString
artifactBytes = "corpus-vuln-1.2.0-artifact-bytes"

sha1Shasum :: Text
sha1Shasum = hexSha1Of (toStrict artifactBytes)

sha512Integrity :: Text
sha512Integrity = sriSha512Of (toStrict artifactBytes)

-- A fixed clock one day after the stub packument's publish time: always inside
-- the 7-day quarantine.
fixedNow :: UTCTime
fixedNow = UTCTime (fromGregorian 2026 6 20) 0

-- Poll the same request until the proxy serves the packument (the swap landed),
-- bounded so a broken sync fails the test rather than hanging it.
awaitAdmitted :: Application -> ByteString -> IO SResponse
awaitAdmitted app path = do
    resp <- pollUntil 150 100_000 admitted (getPath path app)
    if admitted resp
        then pure resp
        else fail "the artifact never swapped in: the request was still denied after the patience window"
  where
    admitted resp = status resp == 200

runQuiet :: KatipContextT IO a -> IO a
runQuiet action = do
    logEnv <- quietLogEnv
    runKatipContextT logEnv (mempty :: SimpleLogPayload) mempty action
