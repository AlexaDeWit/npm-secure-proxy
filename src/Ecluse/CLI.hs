-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.CLI (
    AppCommand (..),
    commandParser,
    execCLI,
) where

import Options.Applicative

import Ecluse.Composition.Types (MirrorRole (MirrorOnly, ServeAndMirror, ServeOnly))
import Ecluse.Core.BuildIdentity (productVersion)
import Ecluse.Core.Registry.Sweep.Types (SweepMode (SweepDeletes, SweepRehearses))
import Ecluse.Dredger.Plan (
    DredgerOptions (DredgerOptions),
    SweepRepetition (SweepContinuously, SweepOnce),
 )
import Ecluse.Pilot (PilotCompileOptions (..))

data AppCommand
    = -- | The mirror pipeline in the selected role: @proxy@, @proxy --no-worker@, or @mirror@.
      RunService MirrorRole
    | RunPilot
    | RunPilotCompile PilotCompileOptions
    | -- | @ecluse dredger@, with the repetition and the mode its flags settled.
      RunDredger DredgerOptions
    | RunCheckConfig
    deriving stock (Eq, Show)

commandParser :: Parser AppCommand
commandParser =
    hsubparser
        ( command "proxy" (info (RunService <$> proxyRoleParser) (progDesc "Run the Écluse proxy server"))
            <> command "mirror" (info (pure (RunService MirrorOnly)) (progDesc "Run the Écluse mirror worker alone, for a worker fleet scaled on queue depth"))
            <> command "pilot" (info pilotCommandParser (progDesc "Run the Écluse Pilot (OSV ingestion pipeline)"))
            <> command "dredger" (info (RunDredger <$> dredgerOptionsParser) (progDesc "Run the Écluse Dredger (mirror pruning worker)"))
            <> command "check-config" (info (pure RunCheckConfig) (progDesc "Validate the configuration and print the resolved posture, then exit (0 valid, 2 refused)"))
        )
        <|> pure (RunService ServeAndMirror)

-- Absent, the proxy embeds the worker, which is what the in-memory queue requires.
proxyRoleParser :: Parser MirrorRole
proxyRoleParser =
    flag
        ServeAndMirror
        ServeOnly
        (long "no-worker" <> help "Serve without the embedded mirror worker; needs a durable ECLUSE_QUEUE__URL and an 'ecluse mirror' fleet to drain it")

{- Both flags narrow what one invocation does, so absent they give the shipped behaviour: cycle
for the life of the process, and delete what a named decisive deny condemns. -}
dredgerOptionsParser :: Parser DredgerOptions
dredgerOptionsParser =
    DredgerOptions
        <$> flag
            SweepDeletes
            SweepRehearses
            (long "dry-run" <> help "Report what a cycle would delete and delete nothing; it writes no walk marker either")
        <*> flag
            SweepContinuously
            SweepOnce
            (long "once" <> help "Run one cycle, then exit: 0 when it completed, 1 when it halted")

-- A bare @pilot@ keeps its serve-and-export meaning. @pilot compile@ selects the
-- one-shot mode.
pilotCommandParser :: Parser AppCommand
pilotCommandParser =
    hsubparser
        ( command
            "compile"
            (info (RunPilotCompile <$> pilotCompileOptionsParser) (progDesc "Compile one ecosystem's OSV export into a local osv.db artifact, then exit"))
        )
        <|> pure RunPilot

pilotCompileOptionsParser :: Parser PilotCompileOptions
pilotCompileOptionsParser =
    PilotCompileOptions
        <$> strOption (long "ecosystem" <> metavar "ECOSYSTEM" <> value "npm" <> showDefault <> help "Ecosystem whose OSV export to compile")
        <*> optional (strOption (long "source" <> metavar "URL" <> help "OSV export URL (defaults to the configured osvExportBaseUrl for ECOSYSTEM)"))
        <*> optional (strOption (long "epss-source" <> metavar "URL" <> help "EPSS feed URL (defaults to the configured epssFeedUrl)"))
        <*> strOption (long "out" <> metavar "DIR" <> help "Directory the artifact is written into")
        <*> switch (long "upload" <> help "After compiling, upload the artifact to the configured advisory store (one full sync cycle)")

execCLI :: IO AppCommand
execCLI =
    execParser $
        info
            (commandParser <**> helper <**> versionOption)
            ( fullDesc
                <> progDesc "Écluse - supply-chain resilience proxy"
                <> header "ecluse - a configurable policy gate for package registries"
            )
  where
    versionOption = infoOption (toString productVersion) (long "version" <> help "Show version")
