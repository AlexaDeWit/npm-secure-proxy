-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Écluse: a supply-chain policy proxy for package registries.

Écluse (package @ecluse@) sits between clients (developers, CI) and a package
registry. It applies a configurable resilience policy before any dependency reaches
a build, and it hosts no packages itself. The name is French for a canal lock: a
chamber whose gates never open at once. Every dependency is held and cleared
through that controlled passage before it enters a build.

The goal is __resilience, not malware detection__. Shrink the blast radius of a bad
publish (a hijacked maintainer account, a race-to-publish, a typosquat), rather than
promise to recognise malice.

Écluse is __not a registry__. The operator's own backend stores the packages (AWS
CodeArtifact, GCP Artifact Registry). Écluse governs only what may be fetched from,
and mirrored to, those backends. npm is the first ecosystem. The domain model is
ecosystem-agnostic, so PyPI and RubyGems can follow.

== How a request is cleared

Écluse speaks a registry's native protocol across three read-path registries: the
client's, a /private upstream/ of already-vetted packages, and the /public/
registry. The two request shapes use them differently:

* Écluse gates a __tarball__ request for that one version. It streams a
  private-upstream hit unfiltered, because it is already vetted. On a miss, the
  proxy fetches the version's public metadata and evaluates the rules. It then
  streams the version from public __and enqueues an asynchronous mirror job__, or
  returns a denial.
* A __packument__ (metadata) request is a /merge/. Écluse fetches the private and
  public upstreams in parallel, filters the public versions through the rules, and
  trusts the private ones. It then combines the two into one document. Private wins
  a version collision, Écluse flags an integrity divergence as a supply-chain
  signal, and @latest@ repoints to the newest survivor.

Two properties run through both shapes. The rules engine is __deny by default__: a
version is admitted only if some rule allows it and none denies it. __Mirroring is
demand-driven__, so Écluse mirrors only the versions a client actually pulls, never
on the request's critical path.

== How the code is organised

Écluse is a __functional core with effects at the edges__. The policy and protocol
logic is pure and easy to test, and a thin shell confines @IO@. Swappable
backends sit behind /handles/, records of functions chosen at a single composition
root. A new cloud or a new ecosystem is then one more implementation behind an
existing handle, not a structural change.

The library's vocabulary, roughly from the pure core outward:

* __Domain model__: "Ecluse.Core.Package" (the ecosystem-agnostic package vocabulary
  the rules reason over), "Ecluse.Core.Version" (version identity and per-ecosystem
  ordering), and "Ecluse.Core.Ecosystem" (the ecosystem tag the rest dispatches on).
* __Policy__: "Ecluse.Core.Rules" (deny-by-default evaluation) over the rule types
  in "Ecluse.Core.Rules.Types".
* __Protocol boundary__: "Ecluse.Core.Registry" (the registry-protocol handle),
  "Ecluse.Core.Registry.Npm.Wire" and "Ecluse.Core.Registry.Npm.Project" (the lenient npm
  wire decoders and their projection onto the domain model),
  "Ecluse.Core.Registry.Npm.Route" (the npm path grammar), and "Ecluse.Core.Server.Route"
  (the shared serve-action 'Route' set and the injected route classifier).
* __Cloud handles__: "Ecluse.Core.Credential" (minting the mirror-target write token)
  and "Ecluse.Core.Queue" (the durable mirror-job hand-off to the worker).
* __Mirror worker__: "Ecluse.Core.Worker" (the supervised consume loop that fetches,
  verifies against the job's integrity digest, and publishes an approved artifact).
* __Supervision__: "Ecluse.Core.Supervision" (the one background-loop combinator every
  long-running task runs under) and, in this module, the typed process perimeter
  ('superviseProcess' and its 'exitCodeFor' table).

'run' is the entry point the @ecluse@ executable invokes (see "Main"). It lives
in the library, not in @app\/Main.hs@, so the composition root is a single
importable unit. @app\/Main.hs@ stays a thin shell that only calls it.

== Further reading

@docs\/architecture.md@ is the systems-design index: the vision, the end-to-end
request lifecycle, and a map to the per-concern design documents. @CONTRIBUTING.md@
covers the codebase layout and testing strategy, and @STYLE.md@ the coding and
documentation conventions.
-}
module Ecluse (
    -- * Entry point
    run,

    -- * The typed process supervisor
    ProcessOutcome (..),
    superviseProcess,
    exitCodeFor,

    -- * The separately deployable services
    runServer,
    runWorker,

    -- * npm front door
    mountBindingFor,

    -- * Composition glue (exposed for direct testing)
    orExit,
    BootAborted (..),
) where

import Control.Exception (AsyncException (ThreadKilled, UserInterrupt), SomeAsyncException)
import Control.Exception qualified as Exception
import Data.Text.IO qualified as TIO
import System.Exit (ExitCode (ExitFailure, ExitSuccess))

import Ecluse.Boot
import Ecluse.CLI (AppCommand (..), execCLI)
import Ecluse.CheckConfig (runCheckConfig)
import Ecluse.Composition.BootError (renderBootErrors)
import Ecluse.Composition.Credential (initCredentialProviders)
import Ecluse.Composition.Executable (
    PrunerWiring,
    RoleWiring (MirrorPipelineWiring, PilotWiring, StorePrunerWiring),
    epRoleWiring,
    planExecutable,
 )
import Ecluse.Composition.Maintenance (buildStoreMaintenance)
import Ecluse.Composition.Plan (BootPlan (bpS3Endpoint))
import Ecluse.Composition.Types (
    BootRole (BootMirrorPipeline, BootStorePruner, BootWithoutPipeline),
    MirrorRole (MirrorOnly, ServeAndMirror, ServeOnly),
 )
import Ecluse.Config (Config (configApp))
import Ecluse.Core.Text (displayExceptionT)
import Ecluse.Dredger (runDredger)
import Ecluse.Dredger.Plan (DredgerOptions)
import Ecluse.Mirror
import Ecluse.Pilot
import Ecluse.Proxy
import Ecluse.Runtime.Telemetry.Tracing (tracingPortOf)
import Ecluse.Service

run :: IO ()
run = do
    cmd <- execCLI
    outcome <- superviseProcess (runCommand cmd)
    -- A non-zero status is representable only beside its reason ('ProcessExit'), so reporting
    -- here covers every one of them.
    traverse_ (TIO.hPutStrLn stderr) (exitReasonFor outcome)
    exitWith (exitCodeFor outcome)

{- Dispatch one subcommand under the process perimeter. Each arm names its role once, and the
plan carries it from there. check-config runs outside 'withBootEnv': no logger, no services. -}
runCommand :: AppCommand -> IO ProcessOutcome
runCommand = \case
    RunCheckConfig -> shutdownAfter runCheckConfig
    RunService role -> withBootEnv (BootMirrorPipeline role) (startPlannedRole noDredgerOptions)
    RunPilot -> withBootEnv BootWithoutPipeline (startPlannedRole noDredgerOptions)
    RunDredger opts -> withBootEnv BootStorePruner (startPlannedRole (Just opts))
    -- A one-shot compile vets under the Pilot's role and then does its own work rather than
    -- that role's long-running one, so it is the one boot whose behaviour the plan cannot name.
    RunPilotCompile opts ->
        withBootEnv BootWithoutPipeline $ \bootEnv ->
            shutdownAfter (void (runPilotCompile (beLogEnv bootEnv) (beTelemetry bootEnv) (bpS3Endpoint (beBootPlan bootEnv)) (configApp (beConfig bootEnv)) opts))
  where
    -- Only 'RunDredger' carries sweep options, and only it boots the deleting role.
    noDredgerOptions = Nothing

{- Plan the role's runtime, then start the behaviour that plan carries. Every role plans through
the one phase, so this is where a boot spends its last refusal whichever role it started. -}
startPlannedRole :: Maybe DredgerOptions -> BootEnv -> IO ProcessOutcome
startPlannedRole dredgerOptions bootEnv = do
    plan <-
        planExecutable
            (beLogEnv bootEnv)
            (tracingPortOf (beTelemetry bootEnv))
            mountBindingFor
            buildMirrorQueue
            initCredentialProviders
            buildStoreMaintenance
            (beBootPlan bootEnv)
            >>= orExit renderBootErrors
    case epRoleWiring plan of
        MirrorPipelineWiring mirror -> shutdownAfter (withServiceRuntime bootEnv plan mirror runMirrorPipeline)
        -- Only 'RunDredger' names the deleting role, so it is the only command that reaches here
        -- and the options it settled are always in hand.
        StorePrunerWiring pruner -> maybe (pure ShutdownRequested) (sweepUnder bootEnv pruner) dredgerOptions
        PilotWiring exportPlan -> shutdownAfter (runPilot bootEnv exportPlan)

{- Run the Dredger and report what it ended on. A one-shot cycle that halted is a service ending
rather than a shutdown, so a scheduler reads the outcome from the exit status. -}
sweepUnder :: BootEnv -> PrunerWiring -> DredgerOptions -> IO ProcessOutcome
sweepUnder bootEnv pruner opts = maybe ShutdownRequested ServiceExited <$> runDredger bootEnv opts pruner

shutdownAfter :: IO () -> IO ProcessOutcome
shutdownAfter act = ShutdownRequested <$ act

{- Pick the entry point the assembled runtime's own role names. Both halves run over the one
assembly, so the dedicated worker composes the wiring the serve path embeds. -}
runMirrorPipeline :: ServiceRuntime -> IO ()
runMirrorPipeline runtime = case svcRole runtime of
    MirrorOnly -> runMirror runtime
    ServeAndMirror -> runProxy runtime
    ServeOnly -> runProxy runtime

{- | How one whole service run ended. Each constructor owns one exit code ('exitCodeFor'), so
an orchestrator reads the ending from the status alone.
-}
data ProcessOutcome
    = -- | The services drained and returned (a graceful shutdown): exit 0.
      ShutdownRequested
    | -- | A service failed up with the carried rendered fault: exit 1.
      ServiceExited Text
    | -- | The boot aborted ('BootAborted') with the carried rendered refusal: exit 2.
      BootFault Text
    | -- | The run was cancelled from outside (a kill, an interrupt): exit 3.
      RunCancelled
    deriving stock (Eq, Show)

{- | Run the service under the typed process perimeter and classify its ending. The base
'Exception.try' and 'Exception.throwIO' are deliberate: what leaves here async must leave async.
-}
superviseProcess :: IO ProcessOutcome -> IO ProcessOutcome
superviseProcess service =
    Exception.try service >>= \case
        Right outcome -> pure outcome
        Left err
            | Just (BootAborted rendered) <- fromException err -> pure (BootFault rendered)
            | Just (code :: ExitCode) <- fromException err -> Exception.throwIO code
            | Just (killed :: AsyncException) <- fromException err ->
                pure $ case killed of
                    ThreadKilled -> RunCancelled
                    UserInterrupt -> RunCancelled
                    -- StackOverflow / HeapOverflow: resource exhaustion is a
                    -- fault of the run, not a cancellation.
                    other -> ServiceExited (displayExceptionT other)
            | Just (_ :: SomeAsyncException) <- fromException err -> Exception.throwIO err
            | otherwise -> pure (ServiceExited (displayExceptionT err))

{- How a run ends. A failing status is representable only beside the reason it reports, so
'run' cannot exit non-zero in silence. -}
data ProcessExit
    = ExitedCleanly
    | ExitedWith ExitCode Text

-- The status and the report one outcome owns. Both 'run' and 'exitCodeFor' read the ending here.
processExitFor :: ProcessOutcome -> ProcessExit
processExitFor = \case
    ShutdownRequested -> ExitedCleanly
    ServiceExited detail -> ExitedWith (ExitFailure 1) ("ecluse: service exited: " <> detail)
    -- The boot phase rendered the whole aggregated block, which reports here unprefixed.
    BootFault rendered -> ExitedWith (ExitFailure 2) rendered
    RunCancelled -> ExitedWith (ExitFailure 3) "ecluse: run cancelled"

-- | The process exit status each 'ProcessOutcome' owns.
exitCodeFor :: ProcessOutcome -> ExitCode
exitCodeFor outcome = case processExitFor outcome of
    ExitedCleanly -> ExitSuccess
    ExitedWith code _ -> code

-- What an outcome reports before exiting. A graceful shutdown is the only one with nothing to say.
exitReasonFor :: ProcessOutcome -> Maybe Text
exitReasonFor outcome = case processExitFor outcome of
    ExitedCleanly -> Nothing
    ExitedWith _ reason -> Just reason
