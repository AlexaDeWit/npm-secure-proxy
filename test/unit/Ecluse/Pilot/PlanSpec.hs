-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT
{-# LANGUAGE OverloadedStrings #-}

{- | Pilot compilation and publication planning regressions.
Object keys retain their configured prefix and schema epoch.
-}
module Ecluse.Pilot.PlanSpec (spec) where

import Test.Hspec

import Ecluse.Composition.Support (expectAppConfig)
import Ecluse.Config (AdvisoriesSettings, AdvisoryStoreUrl, AppConfig (cfgAdvisories))
import Ecluse.Config.AdvisoryStore (mkAdvisoryStoreUrl)
import Ecluse.Core.Ecosystem (Ecosystem (Npm, PyPI))
import Ecluse.Core.Osv.Compile (CompileSources (..))
import Ecluse.Core.Osv.Ecosystem (osvEcosystemFor)
import Ecluse.Pilot.Plan (
    ExportLoopPlan (ExportIdle, ExportTo),
    PilotCompileOptions (..),
    PilotUploadUnconfigured (PilotUploadUnconfigured),
    UploadPlan (UploadSkipped, UploadTo),
    compileSources,
    configuredSources,
    exportCadenceMicros,
    exportLoopPlan,
    idleCadenceMicros,
    uploadPlan,
    uploadTarget,
 )

-- The advisory settings the shipped defaults resolve to, with the given overlay applied.
advisoriesWith :: [(String, String)] -> IO AdvisoriesSettings
advisoriesWith env = cfgAdvisories <$> expectAppConfig env Nothing

-- A store the config layer would have built, so the plan sees what a boot hands it.
storeAt :: Text -> IO AdvisoryStoreUrl
storeAt raw = either (fail . toString) pure (mkAdvisoryStoreUrl "advisories.url" raw)

-- A one-shot run that compiles npm and neither overrides nor uploads.
bareOptions :: PilotCompileOptions
bareOptions =
    PilotCompileOptions
        { pcoEcosystem = "npm"
        , pcoSource = Nothing
        , pcoEpssSource = Nothing
        , pcoOutDir = "/tmp/ecluse-pilot"
        , pcoUpload = False
        }

spec :: Spec
spec = do
    describe "exportLoopPlan -- whether the scheduled loop exports at all, and for what" $ do
        it "idles on the shipped defaults, which configure no store" $ do
            advisories <- advisoriesWith []
            exportLoopPlan advisories [Npm] `shouldBe` Just ExportIdle

        it "idles with no mount either, because the store is what turns exporting on" $ do
            advisories <- advisoriesWith []
            exportLoopPlan advisories [] `shouldBe` Just ExportIdle

        it "exports to the configured store, the one thing that turns it on" $ do
            advisories <- advisoriesWith [("ECLUSE_ADVISORIES__URL", "s3://advisories/ecluse")]
            store <- storeAt "s3://advisories/ecluse"
            exportLoopPlan advisories [Npm] `shouldBe` Just (ExportTo store (Npm :| []))

        it "carries every mounted ecosystem, so a second mount earns its own artifact" $ do
            advisories <- advisoriesWith [("ECLUSE_ADVISORIES__URL", "s3://advisories/ecluse")]
            store <- storeAt "s3://advisories/ecluse"
            exportLoopPlan advisories [Npm, PyPI] `shouldBe` Just (ExportTo store (Npm :| [PyPI]))

        it "plans nothing for a configured store with no mount, which the boot refuses" $ do
            advisories <- advisoriesWith [("ECLUSE_ADVISORIES__URL", "s3://advisories/ecluse")]
            exportLoopPlan advisories [] `shouldBe` Nothing

    describe "exportCadenceMicros -- the delay between cycles" $ do
        it "converts the shipped hourly interval to microseconds" $ do
            advisories <- advisoriesWith []
            exportCadenceMicros advisories `shouldBe` 3600 * 1000000

        it "converts a configured interval" $ do
            advisories <- advisoriesWith [("ECLUSE_ADVISORIES__COMPILE_INTERVAL", "90")]
            exportCadenceMicros advisories `shouldBe` 90 * 1000000

        it "stays positive at the largest interval the decoder accepts" $ do
            -- The decoder caps compileInterval at maxBound `div` 1000000 seconds. At that
            -- cap the conversion must not wrap, or the loop would spin instead of waiting.
            let cap = (maxBound :: Int) `div` 1000000
            advisories <- advisoriesWith [("ECLUSE_ADVISORIES__COMPILE_INTERVAL", show cap)]
            exportCadenceMicros advisories `shouldSatisfy` (> 0)

    describe "idleCadenceMicros -- how long the disabled loop sleeps" $
        it "sleeps a day, because only a reboot picks up an added store" $
            idleCadenceMicros `shouldBe` 24 * 60 * 60 * 1000000

    describe "configuredSources -- the upstreams a scheduled cycle reads" $ do
        it "builds the ecosystem's export URL under the configured base" $ do
            advisories <- advisoriesWith [("ECLUSE_ADVISORIES__OSV_EXPORT_BASE_URL", "https://osv.example.test")]
            csOsvExportUrl (configuredSources advisories (osvEcosystemFor Npm))
                `shouldBe` "https://osv.example.test/npm/all.zip"

        it "reads the EPSS feed from its own key, not the export base" $ do
            advisories <- advisoriesWith [("ECLUSE_ADVISORIES__EPSS_FEED_URL", "https://epss.example.test/scores.csv.gz")]
            csEpssFeedUrl (configuredSources advisories (osvEcosystemFor Npm))
                `shouldBe` "https://epss.example.test/scores.csv.gz"

        it "spells the export path as osv.dev does, not as the mount key does" $ do
            -- osv.dev files the PyPI export under "PyPI". Reaching for the mount key would
            -- fetch a directory that does not exist.
            advisories <- advisoriesWith [("ECLUSE_ADVISORIES__OSV_EXPORT_BASE_URL", "https://osv.example.test")]
            csOsvExportUrl (configuredSources advisories (osvEcosystemFor PyPI))
                `shouldBe` "https://osv.example.test/PyPI/all.zip"

    describe "compileSources -- a one-shot run's overrides over the configured pair" $ do
        it "takes both feeds from config when the run overrides neither" $ do
            advisories <- advisoriesWith []
            compileSources advisories bareOptions `shouldBe` configuredSources advisories (osvEcosystemFor Npm)

        it "overrides the export URL alone, leaving the EPSS feed configured" $ do
            advisories <- advisoriesWith []
            let opts = bareOptions{pcoSource = Just "https://pinned.example.test/all.zip"}
            compileSources advisories opts
                `shouldBe` (configuredSources advisories (osvEcosystemFor Npm)){csOsvExportUrl = "https://pinned.example.test/all.zip"}

        it "overrides the EPSS feed alone, leaving the export URL configured" $ do
            advisories <- advisoriesWith []
            let opts = bareOptions{pcoEpssSource = Just "https://pinned.example.test/epss.csv.gz"}
            compileSources advisories opts
                `shouldBe` (configuredSources advisories (osvEcosystemFor Npm)){csEpssFeedUrl = "https://pinned.example.test/epss.csv.gz"}

        it "overrides both when the run pins both" $ do
            advisories <- advisoriesWith []
            let opts =
                    bareOptions
                        { pcoSource = Just "https://a.example.test/all.zip"
                        , pcoEpssSource = Just "https://b.example.test/epss.csv.gz"
                        }
            compileSources advisories opts
                `shouldBe` CompileSources
                    { csOsvExportUrl = "https://a.example.test/all.zip"
                    , csEpssFeedUrl = "https://b.example.test/epss.csv.gz"
                    }

    describe "uploadPlan -- whether a one-shot run publishes" $ do
        it "skips the upload the run did not ask for, store or no store" $ do
            store <- storeAt "s3://advisories"
            uploadPlan bareOptions Nothing `shouldBe` Right UploadSkipped
            uploadPlan bareOptions (Just store) `shouldBe` Right UploadSkipped

        it "uploads to the configured store when the run asks" $ do
            store <- storeAt "s3://advisories"
            uploadPlan bareOptions{pcoUpload = True} (Just store) `shouldBe` Right (UploadTo store)

        it "refuses an asked-for upload with no store, rather than exiting 0 having published nothing" $
            uploadPlan bareOptions{pcoUpload = True} Nothing `shouldBe` Left PilotUploadUnconfigured

    describe "uploadTarget -- where one artifact lands in the store" $ do
        it "keys the artifact on its own file name, dropping the local directory" $ do
            store <- storeAt "s3://advisories"
            uploadTarget store "/var/lib/ecluse/advisories/npm-osv-schema4.db"
                `shouldBe` ("advisories", "npm-osv-schema4.db")

        it "writes the store's prefix ahead of that name, which is where the sync reads" $ do
            store <- storeAt "s3://advisories/ecluse"
            uploadTarget store "/var/lib/ecluse/advisories/npm-osv-schema4.db"
                `shouldBe` ("advisories", "ecluse/npm-osv-schema4.db")
