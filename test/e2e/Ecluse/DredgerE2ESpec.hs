-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Dredger lifecycle evidence from a real Verdaccio store.
Complete version snapshots connect store contents with each cycle's audit records.
-}
module Ecluse.DredgerE2ESpec (spec) where

import Data.Aeson (encode, object, (.=))
import Data.Map.Strict qualified as Map
import Data.Text qualified as T
import System.Exit (ExitCode (ExitSuccess))
import Test.Hspec

import Ecluse.E2E.Fixtures (PkgSpec, dredgerDryRunPkg, dredgerKeepPkg, dredgerPkg, psName, psVersion)
import Ecluse.E2E.Harness
import Ecluse.Test.Log (lineMessage)

-- | Verify store contents and audit records with identity-only rules and no advisory database.
spec :: Spec
spec = do
    unavailable <- runIO e2eUnavailable
    case unavailable of
        Just reason -> it "Dredger end-to-end environment is available" (pendingWith reason)
        Nothing -> aroundAll withGlobalDataPlane $ aroundAllWith withSeededStore $ do
            it "walks the seeded store through listPackagesIn, including scoped base-name buckets" $ \(_, e2e) -> do
                verdaccioSnapshot e2e `shouldReturn` seededVersions
                names <- verdaccioListing e2e
                names `shouldMatchList` Map.keys seededVersions
                verdaccioNamesUnder e2e "" `shouldReturn` sort names
                verdaccioNamesUnder e2e "e" `shouldReturn` sort names
                verdaccioNamesUnder e2e "z" `shouldReturn` []

            it "deletes every denied version and preserves all other versions, including first-party versions" $ \(plane, e2e) -> do
                initial <- verdaccioSnapshot e2e
                run <- runDredgerOnce plane ["--once"] (sweepEnv dredgerPkg)
                assertFullSweep "deleting " dredgerPkg initial run
                verdaccioVersions e2e (psName dredgerPkg) `shouldReturn` []
                finalStore <- verdaccioSnapshot e2e
                finalStore `shouldBe` Map.delete (psName dredgerPkg) initial
                verdaccioNamesUnder e2e "" `shouldReturn` Map.keys finalStore

            it "reports a dry run's would-delete count and preserves the complete store snapshot" $ \(plane, e2e) -> do
                initial <- verdaccioSnapshot e2e
                run <- runDredgerOnce plane ["--once", "--dry-run"] (sweepEnv dredgerDryRunPkg)
                assertFullSweep "dry run, would delete " dredgerDryRunPkg initial run
                dredgerOutput run `shouldSatisfy` T.isInfixOf "rehearsing only: this run deletes nothing"
                verdaccioSnapshot e2e `shouldReturn` initial

            it "refuses missing consent, names the key, and leaves every version intact" $ \(plane, e2e) -> do
                initial <- verdaccioSnapshot e2e
                run <- runDredgerOnce plane ["--once"] (sweepEnv dredgerPkg <> [(consentKey, "false")])
                (dredgerExit run, dredgerOutput run) `shouldSatisfy` ((/= ExitSuccess) . fst)
                dredgerOutput run `shouldSatisfy` T.isInfixOf (consentKey <> " is not set")
                sweepMessages run `shouldBe` []
                verdaccioSnapshot e2e `shouldReturn` initial

            it "protects every first-party version even when an identity deny names one" $ \(plane, e2e) -> do
                initial <- verdaccioSnapshot e2e
                let rules = identityRule (publishDredgerName <> "@" <> publishVersion)
                    guardCount = length (Map.findWithDefault [] publishDredgerName initial)
                run <- runDredgerOnce plane ["--once"] [("ECLUSE_RULES", rules), ("ECLUSE_MOUNTS__NPM__FIRST_PARTY", publishScope)]
                (dredgerExit run, dredgerOutput run) `shouldSatisfy` ((== ExitSuccess) . fst)
                sweepMessages run `shouldBe` ["mirror sweep cycle complete: examined 0, deleted 0, kept 0, guard-skipped " <> show guardCount]
                verdaccioVersions e2e publishDredgerName `shouldReturn` firstPartyVersions
                verdaccioSnapshot e2e `shouldReturn` initial

withSeededStore :: ((GlobalDataPlane, E2E) -> IO ()) -> GlobalDataPlane -> IO ()
withSeededStore action plane =
    withE2EWith defaultE2EConfig{ecExtraEnv = publishTargetEnv} seed plane
  where
    seed e2e = do
        for_ mirroredPackages $ \pkg -> do
            verdaccioVersions e2e (psName pkg) `shouldReturn` []
            void $ npmInstall e2e (psName pkg) >>= shouldSucceed
            verdaccioHasVersion e2e (psName pkg) (psVersion pkg) `shouldReturn` True
        for_ firstPartyVersions $ \version -> do
            void $ withPublishProject e2e publishDredgerName version npmPublishIn >>= shouldSucceed
            verdaccioHasVersion e2e publishDredgerName version `shouldReturn` True
        for_ (Map.keys seededVersions) $ \name -> do
            unlisted <- verdaccioAwaitListed e2e name
            whenJust unlisted (expectationFailure . toString)
        action (plane, e2e)

mirroredPackages :: [PkgSpec]
mirroredPackages = [dredgerPkg, dredgerKeepPkg, dredgerDryRunPkg]

seededVersions :: Map Text [Text]
seededVersions = Map.fromList ((publishDredgerName, firstPartyVersions) : [(psName pkg, [psVersion pkg]) | pkg <- mirroredPackages])

firstPartyVersions :: [Text]
firstPartyVersions = [publishVersion, "2.0.0"]

consentKey :: Text
consentKey = "ECLUSE_MOUNTS__NPM__MIRROR_TARGET__VERDACCIO__PERMIT_DELETION"

sweepEnv :: PkgSpec -> [(Text, Text)]
sweepEnv pkg =
    [ ("ECLUSE_RULES", identityRule (psName pkg))
    , ("ECLUSE_DREDGER__FULL_WALK", "true")
    , ("ECLUSE_MOUNTS__NPM__FIRST_PARTY", publishScope)
    ]

identityRule :: Text -> Text
identityRule name = decodeUtf8 (toStrict (encode (object ["revoke-swept" .= object ["type" .= ("DenyByIdentity" :: Text), "identity" .= name]])))

assertFullSweep :: Text -> PkgSpec -> Map Text [Text] -> DredgerRun -> Expectation
assertFullSweep opening pkg initial run = do
    let versions = Map.findWithDefault [] (psName pkg) initial
        guardCount = length (Map.findWithDefault [] publishDredgerName initial)
        examined = sum (map length (Map.elems initial)) - guardCount
        fields =
            [ "examined " <> show examined
            , "deleted " <> show (length versions)
            , "kept " <> show (examined - length versions)
            , "guard-skipped " <> show guardCount
            ]
    (dredgerExit run, dredgerOutput run) `shouldSatisfy` ((== ExitSuccess) . fst)
    versions `shouldBe` [psVersion pkg]
    sweepMessages run `shouldMatchList` (map auditLine versions <> ["mirror sweep cycle complete: " <> T.intercalate ", " fields])
  where
    auditLine version =
        opening
            <> psName pkg
            <> "@"
            <> version
            <> ": blocked by DenyByIdentity (identity "
            <> psName pkg
            <> " is revoked by operator); advisory generation none"

sweepMessages :: DredgerRun -> [Text]
sweepMessages run = filter isSweepMessage (mapMaybe lineMessage (T.lines (dredgerOutput run)))

isSweepMessage :: Text -> Bool
isSweepMessage message = any (`T.isPrefixOf` message) ["deleting ", "dry run, would delete ", "mirror sweep cycle "]
