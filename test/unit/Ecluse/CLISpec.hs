-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.CLISpec (spec) where

import Options.Applicative (ParserResult (..), defaultPrefs, execParserPure, helper, idm, info)
import Test.Hspec

import Ecluse.CLI (AppCommand (..), commandParser)
import Ecluse.Composition.Types (MirrorRole (MirrorOnly, ServeAndMirror, ServeOnly))
import Ecluse.Dredger.Plan (
    DredgerOptions (DredgerOptions, doMode, doRepetition),
    SweepMode (SweepDeletes, SweepRehearses),
    SweepRepetition (SweepContinuously, SweepOnce),
 )
import Ecluse.Pilot (PilotCompileOptions (..))

parseCLI :: [String] -> ParserResult AppCommand
parseCLI = execParserPure defaultPrefs (info (commandParser <**> helper) idm)

spec :: Spec
spec = do
    describe "CLI commandParser" $ do
        it "defaults to the serve-and-mirror role when no arguments are provided" $ do
            case parseCLI [] of
                Success cmd -> cmd `shouldBe` RunService ServeAndMirror
                _ -> expectationFailure "expected Success (RunService ServeAndMirror)"

        it "parses 'proxy' as the serve-and-mirror role (the worker stays embedded)" $ do
            case parseCLI ["proxy"] of
                Success cmd -> cmd `shouldBe` RunService ServeAndMirror
                _ -> expectationFailure "expected Success (RunService ServeAndMirror)"

        it "parses 'proxy --no-worker' as the serve-only role" $ do
            case parseCLI ["proxy", "--no-worker"] of
                Success cmd -> cmd `shouldBe` RunService ServeOnly
                _ -> expectationFailure "expected Success (RunService ServeOnly)"

        it "parses 'mirror' as the worker-only role" $ do
            case parseCLI ["mirror"] of
                Success cmd -> cmd `shouldBe` RunService MirrorOnly
                _ -> expectationFailure "expected Success (RunService MirrorOnly)"

        it "rejects --no-worker on the dedicated worker, which has no worker to drop" $ do
            case parseCLI ["mirror", "--no-worker"] of
                Success cmd -> expectationFailure ("expected a parse failure, got " <> show cmd)
                _ -> pure ()

        it "parses 'pilot' as RunPilot" $ do
            case parseCLI ["pilot"] of
                Success cmd -> cmd `shouldBe` RunPilot
                _ -> expectationFailure "expected Success RunPilot"

        it "parses 'dredger' as the shipped invocation: cycling, and deleting" $ do
            case parseCLI ["dredger"] of
                Success cmd -> cmd `shouldBe` RunDredger DredgerOptions{doMode = SweepDeletes, doRepetition = SweepContinuously}
                _ -> expectationFailure "expected Success RunDredger"

        it "parses 'dredger --once --dry-run' as one rehearsed cycle" $ do
            -- Both flags only narrow what one invocation does, so they compose.
            case parseCLI ["dredger", "--once", "--dry-run"] of
                Success cmd -> cmd `shouldBe` RunDredger DredgerOptions{doMode = SweepRehearses, doRepetition = SweepOnce}
                _ -> expectationFailure "expected Success RunDredger"

        it "parses 'pilot compile' with the default ecosystem and canonical source" $ do
            case parseCLI ["pilot", "compile", "--out", "/tmp/osv"] of
                Success cmd ->
                    cmd
                        `shouldBe` RunPilotCompile
                            PilotCompileOptions
                                { pcoEcosystem = "npm"
                                , pcoSource = Nothing
                                , pcoEpssSource = Nothing
                                , pcoOutDir = "/tmp/osv"
                                , pcoUpload = False
                                }
                _ -> expectationFailure "expected Success RunPilotCompile"

        it "parses 'pilot compile' with ecosystem, both source overrides, and upload" $ do
            case parseCLI ["pilot", "compile", "--ecosystem", "npm", "--source", "http://127.0.0.1:9/all.zip", "--epss-source", "http://127.0.0.1:9/epss.csv.gz", "--out", "out", "--upload"] of
                Success cmd ->
                    cmd
                        `shouldBe` RunPilotCompile
                            PilotCompileOptions
                                { pcoEcosystem = "npm"
                                , pcoSource = Just "http://127.0.0.1:9/all.zip"
                                , pcoEpssSource = Just "http://127.0.0.1:9/epss.csv.gz"
                                , pcoOutDir = "out"
                                , pcoUpload = True
                                }
                _ -> expectationFailure "expected Success RunPilotCompile"

        it "rejects 'pilot compile' without --out" $ do
            case parseCLI ["pilot", "compile"] of
                Success cmd -> expectationFailure ("expected a parse failure, got " <> show cmd)
                _ -> pure ()
