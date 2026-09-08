# Getting started

How to set up a development environment and run the inner loop. For the contribution *process*
(conventions, sign-off, AI policy), see [`CONTRIBUTING.md`](../CONTRIBUTING.md). For the test tiers
and coverage, see [Testing Strategy](testing.md).

## Local development

**Nix (with flakes) is a hard dependency.** The whole toolchain (GHC 9.10, Cabal, fourmolu, hlint,
Semgrep) comes from the dev shell, pinned by `flake.lock`. There is no supported system-level build.
Enter the shell with `nix develop` (or let `direnv` do it), then run everything through `task`, the
entry point shared by local development and CI. Running `task` from outside the shell works, but it
re-enters the shell per target, so keep that for one-offs.

Run `task --list` for the targets. The underlying commands live in
[`Taskfile.yml`](../Taskfile.yml), so local and CI never drift.

**Before you push,** run `task check` clean. What it runs, what `task gate` adds, and what only
CI runs are in [Testing Strategy](testing.md).

### Reproducible build and checks (Nix)

`task build` / `task test` wrap `cabal` for the incremental inner loop. For a hermetic build from the
exact Nix-store closure (GHC and C libraries from `flake.lock`), use the Nix outputs:

| Task | Command |
|------|---------|
| Build the `ecluse` binary | `task nix-build` (`nix build`) → `./result/bin/ecluse` |
| Evaluate the flake and build its checks | `task nix-check` (`nix flake check`) |

`nix flake check` builds the `docs`, `freeze-sync`, `amazonka-lockstep`, and
`saerskriven` checks. The first builds library Haddock. The next two verify
the dependency locks described below.
The last runs the pinned Saerskriven CLI against this flake's libraries,
including PDF rendering. Test suites, formatting, and linting run through
separate `task` targets. The authoritative CI tiers and their
external-service requirements are in [Testing Strategy](testing.md#what-gates-and-what-doesnt).

> **Flakes only see git-tracked files.** `git add` new sources before `nix build` /
> `nix flake check`. Otherwise they're invisible, and a build that references them (via the cabal
> file) fails on the missing modules.

### Dependency locking

One version authority, two build paths:

| Path | Resolver | Lock |
|------|----------|------|
| Nix / hermetic build (the shipped artifact) | nixpkgs GHC 9.10 set + the flake overlay | `flake.lock` |
| `cabal` (dev shell + the CI gate) | Hackage, held to the same versions | `cabal.project.freeze`, generated from the Nix set |

`callCabal2nix` does not read `cabal.project` or `.freeze`. Instead `task freeze` generates the
freeze *from* the Nix package set, backed by the flake's `cabal-freeze` output. The cabal path
therefore resolves the exact dependency closure the shipped artifact is built from. The `freeze-sync`
flake check fails CI whenever the committed freeze drifts from the set. The `index-state` in
`cabal.project` caps the Hackage snapshot the solver may see. It only needs to contain every pinned
version, so advance it with `task bump-index-state` only when cabal reports a pinned version as
unknown. The one source pin held in two places is amazonka: `amazonkaRev` in `flake.nix`, and the
`source-repository-package` tag in `cabal.project`. The `amazonka-lockstep` flake check keeps them
equal.

Move the pins deliberately: run `nix flake update` (or merge Renovate's weekly `flake.lock` refresh),
then `task freeze`, and commit both together. When the weekly Renovate PR moves Haskell versions,
`freeze-sync` reds it, and a single `task freeze` commit on that branch completes the refresh.
Renovate widens the *bounds* in `ecluse.cabal`, only the few explicit `>= && <` ranges its manager
can parse. Versions themselves move only through the flake.

### Threat modelling tools

The default and CI shells include the released Saerskriven CLI. Its locked
flake input follows Écluse's nixpkgs and flake-utils inputs. Saerskriven owns
the binary version, asset hashes, and Nix package definition.

```bash
nix develop --command saerskriven --version
nix develop .#ci --command saerskriven validate threat-modelling/ecluse.json
```

The current source remains `threat-modelling/ecluse.json`. The site still uses
`site-gen` to render its threat register. The CLI is available for the later
migration to Saerskriven's model and rendering workflow.

After Saerskriven publishes and reviews a packaging update, update its input
with `nix flake update saerskriven` and review `flake.lock` in a PR. Run
`task nix-check` to test the package against Écluse's pinned libraries.
[Saerskriven's Nix guide](https://github.com/AlexaDeWit/Saerskriven/blob/main/docs/nix.md)
records the upstream release update process and platform execution coverage.

---

## Codebase layout

[`docs/style.md`](style.md) → "Module organisation" holds the *principles*: types with their
functions, one `Ecluse.<Area>` namespace per area, and when a `.Types` split is justified. This
section records the current layout and one project-specific pattern.

- **Three application libraries behind one `ecluse.cabal`.** `ecluse-core` (`core/src`,
  `Ecluse.Core.*`) owns the capability core. `ecluse-runtime` (`runtime/src`, `Ecluse.Runtime.*`)
  owns runtime adapters such as cloud clients, telemetry, logging, and server hosting.
  `ecluse` (`src`, `Ecluse.*`) owns configuration and composes those capabilities into executable
  roles. `app/Main.hs` is the executable entry point. Tool and test-support libraries are separate
  from these three application libraries. The core unit suite cannot depend on the application
  library. See
  [README, Project structure](../README.md#project-structure).
- **Handles are records of functions, selected at one composition root.** A swappable backend
  (registry protocol, mirror queue, credential provider) is a record whose fields are functions: the
  *Handle pattern*. A per-backend smart constructor builds it (e.g.
  `newSqsQueue :: SqsConfig -> IO MirrorQueue`). Adding a backend means a new constructor behind the
  *existing* record, wired into the single composition root, never provider selection smeared across
  call sites. See
  [Cloud backends](architecture/cloud-backends.md#cloud-backends).

For the module list, read the [published Haddock](https://ecluse-proxy.com/api/) module index and the
root [`Ecluse`](../src/Ecluse.hs) synopsis. Tests mirror this hierarchy (e.g.
`Ecluse.Core.Rules` → `core/test/unit/Ecluse/Core/RulesSpec.hs`).
