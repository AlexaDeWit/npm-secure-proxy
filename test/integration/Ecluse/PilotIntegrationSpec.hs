-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Pilot publication refusal against the S3 emulator.
Rejected feeds preserve the previous object's identity and modification time.
-}
module Ecluse.PilotIntegrationSpec (spec) where

import Amazonka qualified as AWS
import Amazonka.S3 qualified as S3
import Amazonka.S3.ListObjectsV2 qualified as S3
import Amazonka.S3.Types.Object qualified as S3Object
import Control.Monad.Trans.Resource (runResourceT)
import Data.ByteString.Lazy qualified as LBS
import Network.HTTP.Types.Status (status200)
import System.IO.Temp (withSystemTempDirectory)
import Test.Hspec (Spec, aroundAll, describe, it, shouldBe, shouldSatisfy, shouldThrow)

import Ecluse.Config (Config (configApp), loadConfig)
import Ecluse.Config.Ambient (parseEndpointUrl)
import Ecluse.Core.Osv.Stream (PilotIngestAborted (..))
import Ecluse.Integration.Ministack (endpointFor, quietLogEnv, withMinistack)
import Ecluse.Pilot (PilotCompileOptions (..), runPilotCompile)
import Ecluse.Runtime.Aws.S3 (buildS3Env)
import Ecluse.Runtime.Telemetry (telemetryDisabled)
import Ecluse.Test.Osv (CorpusVersion (CorpusV1), osvCorpusZip, osvZipOf)
import Ecluse.Test.OsvDb (epssFixtureFile)
import Ecluse.Test.Poll (retryingIO)
import Ecluse.Test.Stub (Captured (capMethod), allCaptured, stubBaseUrl, withStub)

spec :: Spec
spec = describe "Pilot refuses zero relevant rows before S3 publication" $
    aroundAll withMinistack $
        for_ [("empty", osvZipOf []), ("wrong-ecosystem", LBS.readFile "test/unit/fixtures/osv/sample.zip")] $ \(label, rejectedZip) ->
            for_ [False, True] $ \hasPrevious ->
                it (label <> " archive, previous=" <> show hasPrevious) $ \container ->
                    withSystemTempDirectory "ecluse-pilot-rejected" $ \outDir -> do
                        let endpoint = endpointFor container
                            bucket = "pilot-" <> toText label <> if hasPrevious then "-replacement" else "-first"
                        base <- buildS3Env (Just endpoint)
                        let aws = base{AWS.region = AWS.Region' "us-east-1"}
                        retryingIO 21 500_000 (void (runResourceT (AWS.send aws (S3.newCreateBucket (S3.BucketName bucket)))))
                        appCfg <- either (fail . show) (pure . configApp) (loadConfig [("ECLUSE_ADVISORIES__URL", toString ("s3://" <> bucket))] Nothing)
                        logEnv <- quietLogEnv
                        epssData <- LBS.readFile epssFixtureFile
                        goodZip <- osvCorpusZip CorpusV1
                        badZip <- rejectedZip
                        let compile target zipData = withStub status200 zipData $ \stub ->
                                withStub status200 epssData $ \epssStub ->
                                    runPilotCompile
                                        logEnv
                                        telemetryDisabled
                                        (Just target)
                                        appCfg
                                        PilotCompileOptions
                                            { pcoEcosystem = "pypi"
                                            , pcoSource = Just (toString (stubBaseUrl stub) <> "/all.zip")
                                            , pcoEpssSource = Just (toString (stubBaseUrl epssStub) <> "/epss.csv.gz")
                                            , pcoOutDir = outDir
                                            , pcoUpload = True
                                            }
                            snapshot = do
                                response <- runResourceT (AWS.send aws (S3.newListObjectsV2 (S3.BucketName bucket)))
                                pure [(S3Object.key object, S3Object.eTag object, S3Object.lastModified object, S3Object.size object) | object <- fromMaybe [] (S3.contents response)]
                        when hasPrevious (void (compile endpoint goodZip))
                        before <- snapshot
                        length before `shouldBe` if hasPrevious then 1 else 0
                        for_ before $ \(_, etag, modified, _) -> do
                            etag `shouldSatisfy` isJust
                            modified `shouldSatisfy` isJust
                        withStub status200 LBS.empty $ \observer -> do
                            target <- either (fail . show) pure (parseEndpointUrl (stubBaseUrl observer))
                            compile target badZip `shouldThrow` (\(PilotIngestAborted _) -> True)
                            allCaptured observer >>= (`shouldBe` [])
                            after <- snapshot
                            after `shouldBe` before
                            void (compile target goodZip)
                            requests <- allCaptured observer
                            map capMethod requests `shouldBe` ["PUT"]
