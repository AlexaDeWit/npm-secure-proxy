# Testing strategy

Where a test belongs, what each tier gates, and how CI measures coverage. One thing decides a
test's tier: **the external collaborator the code under test needs**, and so how deterministic the
test can be. Three kinds:

- **unit** needs no collaborator (pure logic or in-process doubles),
- **integration** needs an *emulable* service, reached through a container,
- **smoke** needs an *un-emulable* live service.

The first two are hermetic and **gate** merges. Smoke makes live calls and is **allowed to fail by
design**. Two further gating tiers, residency and end-to-end, sit alongside them, for seven `cabal`
test-suites in all. One rule spans every tier (see *What gates, and what doesn't*), so read that
before you choose a new test's home.

## Unit tests: `ecluse-core-unit`, `ecluse-runtime-unit`, `ecluse-unit` (gating)

Pure, fast, deterministic `hspec` and `hedgehog` tests over all pure logic: the rules engine,
parsers, and configuration. No IO, no Docker. They run on every push in milliseconds. Properties
exercise the rules engine: deny-by-default, deny-precedence over allows, and per-rule predicates.
This tier tests the credential provider's refresh, cache, and expiry policy with an injected clock
and a fake `mintToken`. The real mint runs only in smoke (see that caveat below).
Proxy request-lifecycle tests run against an in-process WAI stub, so they assert the full
fetch → parse → rules → mirror path without a network.

The tier is three suites, split by which library a spec may link. Each suite's `build-depends`
enforces the split:

- **`ecluse-core-unit`** covers `Ecluse.Core.*` (depends on `ecluse-core` only).
- **`ecluse-runtime-unit`** covers the `Ecluse.Runtime.*` capabilities that need no
  application library: the cloud adapters, the telemetry SDK wiring, and logging.
- **`ecluse-unit`** covers the composition shell and the app-tier specs. It depends on
  the `ecluse` app library, so it can drive runtime handles through
  `runServer`/`runWorker`, which is why the `Ecluse.Runtime.Server` and
  `Ecluse.Runtime.Env` specs live here.

Each tests its tree in isolation, mirrored under `core/test/unit`, `runtime/test/unit`, and
`test/unit`. A spec module is the tested module's full name with `Spec` appended, and its file sits
at the tested module's path under the suite's source directory, library prefix included, so
`Ecluse.Core.Cve.Slot` is tested by `core/test/unit/Ecluse/Core/Cve/SlotSpec.hs`, module
`Ecluse.Core.Cve.SlotSpec`. The prefix stays in the name, so a spec states which library it tests
without the reader knowing which suite holds it. A suite outside the unit tier puts its tier token
before `Spec`: `IntegrationSpec`, `E2ESpec`, `SmokeSpec`, `ResidencySpec`. The integration spec for
`Ecluse.Core.Server.Pipeline.Tarball` is therefore
`Ecluse.Core.Server.Pipeline.TarballIntegrationSpec`, and the unit spec beside it keeps the bare
`Spec`. Run all three: `cabal test ecluse-core-unit ecluse-runtime-unit ecluse-unit`.

## Integration tests: `ecluse-integration` (gating)

Exercise cloud-backed code (the `MirrorQueue` and `CredentialProvider` handles) against a real
emulator, driven by `testcontainers`. The AWS backend runs against a **ministack** container, a
lightweight LocalStack alternative, with `amazonka` pointed at `http://<container>:4566` and
throwaway credentials. The telemetry specs run a real OTLP **Collector** container the same way. Both
are hermetic: no real cloud account, no real credentials.

The tier needs a running Docker daemon. CI's `ubuntu-latest` provides one. Locally, install Docker:
Nix ships the toolchain, not the daemon. Run: `cabal test ecluse-integration` (or
`task test-integration`).

> **Token-mint caveat.** No emulator covers the managed-registry token API (CodeArtifact's
> `GetAuthorizationToken`). The only un-emulable part is the `mintToken` leaf of the
> `CredentialProvider`, so this tier mocks it at that handle. The unit tier covers the generic
> refresh, cache, and expiry policy around it with an injected clock. The real mint runs end-to-end
> only in the non-gating smoke tier.

## Residency gate: `ecluse-residency` (gating)

The bounded-memory streaming gate streams a 1 MiB and a 100 MiB artifact through the tarball relay.
It covers both the trusted private-hit leg and the gated public leg. It asserts that peak live bytes
stay invariant in artifact size within a fixed margin. It is its own suite, not an
`ecluse-integration` spec, because the measurement needs process isolation and the RTS statistics
flag (`-with-rtsopts=-T`) in its `ghc-options`. It runs outside coverage too. No Docker, loopback
WAI stubs only. Run: `cabal test ecluse-residency` (or `task test-residency`). `task check` includes
it via `cabal-checks`.

## Smoke tests: `ecluse-smoke` (allowed to fail, non-gating)

Make live calls to public registries (npm today) to confirm our JSON decoding and protocol handling
match reality. They depend on uncontrolled external services, so an occasional failure is normal
and never blocks a merge. The CI `gate` does not depend on them. Treat a failure as a
prompt to investigate (protocol drift or flakiness?), not a blocker. Run: `cabal test ecluse-smoke`.

This tier is also where the one un-emulable cloud surface runs end-to-end: the real token *mint*
(`CredentialProvider`'s `mintToken`) against the live cloud. It needs real external access, so it is
allowed to fail and stays isolated to one small function, an accepted residual risk.

The store walk sits here for the same reason. No emulator carries the CodeArtifact control plane, so
a live repository is the only place `listPackagesIn` pages a real `ListPackages` result. The case is
read-only: it lists packages and publishes, deletes, and tags nothing. Run it with
`ECLTEST_SMOKE_CODEARTIFACT_REGION`, `_DOMAIN`, `_DOMAIN_OWNER`, and `_REPOSITORY` set, and the
standard AWS credential chain pointed at an identity holding `codeartifact:ListPackages` on that
repository and nothing else. The repository needs two npm packages, seeded once by hand: the case
forces one package per page, because the production request sets no page size and the service's own
default is not a number we choose. Without the four variables it pends, which is what it does in CI,
where no workflow carries AWS credentials.

The telemetry Datadog check lives here too. With Datadog API credentials in the environment, it emits
a uniquely stamped span and metric through the real export path. It then polls the Datadog API until
they appear. It is secret-gated (skipped without credentials) and non-gating, so a Datadog outage or
ingestion lag never blocks a merge. It is the only telemetry check that reaches the Datadog SaaS.

The hermetic span and metric assertions run in `ecluse-integration`. A request drives an in-process
Écluse, and a real Collector container asserts the spans and metrics arrived. The unit tier covers
config parsing, the denial span-attribute mapping, the JSONL scribe, and the metric-label guard.

## End-to-end tests: `ecluse-e2e` (gating)

The only tier that assembles the whole system through the real composition root and drives it with
the real `npm` CLI. It runs the published OCI image (`nix build .#dockerImage`), an nginx
public-upstream stub, and a Verdaccio private upstream and mirror target as containers on a Docker
network. It then asserts client- and mirror-observable outcomes:

- an allow-listed package installs,
- Écluse blocks a rules-denied package and never mirrors it,
- an installed package round-trips server → worker to the private mirror,
- a tampered artifact fails the integrity gate and never publishes.

It catches composition-root and cross-component regressions nothing else does. The mount rewrites a
served `dist.tarball` to an absolute installable URL under `ECLUSE_SERVER__PUBLIC_URL`, because
`npm` cannot install the path-relative form.

It gates as its own parallel job the CI `gate` depends on. It is far heavier than the rest of the
gate: an image build, multiple containers, and the npm CLI. But it is hermetic. The nginx and
Verdaccio upstreams are local, so unlike smoke it has no external dependency to flake on, which
makes gating safe. Its weight keeps it out of the local `task gate` and `task check`. Run
`task test-e2e` on demand to build the image, load it, and run the suite. It needs a Docker daemon
and the npm CLI, and skips every case as `pending` when `ECLTEST_E2E_IMAGE` is unset.

The egress guard refuses internal addresses on the public path. So the containers run on
the RFC 5737 documentation subnet `203.0.113.0/24`, which the guard treats as external. The real
default-build image runs unmodified, with no production escape hatch.

This tier runs the real `npm` CLI against real packages, so an upstream lifecycle script
(`preinstall`/`install`/`postinstall`/`prepare`) could execute arbitrary code inside our own CI. The
harness therefore sets `npm_config_ignore_scripts` for every npm child it spawns. The committed
root `.npmrc` carries the same `ignore-scripts=true` for in-repo npm and Renovate. That file cannot
reach the throwaway projects outside the repo tree, hence the env var. A gating case installs a
probe whose `postinstall` would write a sentinel, and asserts the sentinel never appears, so the
guard cannot rot silently. `ignore-scripts` skips lifecycle scripts only, so it leaves the
resilience scenarios alone.

## OSV advisory fixtures

Advisory-shaped test data has one source of truth: the committed OSV JSON under `test/fixtures/osv/`
(`v1/`, plus the `v2/` delta). A suite derives everything it consumes from those files at test time.
No `osv.db` is ever committed as a binary, so a fixture cannot drift from the artifact contract
(`Ecluse.Core.Osv.Schema`). Helpers in `ecluse-test-support` assemble the osv.dev-shaped zip, plus
*hostile* artifacts for rejection tests. They compile the corpus through the real OSV pipeline
(`Ecluse.Core.Osv.Compile`, in `ecluse-core`, so `ecluse-core-unit` can link it). The corpus carries
versions, so shadow-swap tests observe an ETag change and a rule-outcome flip.
`Ecluse.Test.OsvSpec` pins each version's rows exactly, so editing the corpus updates the pin in the
same PR.

## Tests and Docker

The integration and end-to-end tiers are the only ones that start Docker containers. Integration goes
through `testcontainers` (ministack, the OTLP collector). The e2e tier goes through the raw `docker`
harness: the proxy image plus its nginx/Verdaccio data plane. Both stamp every container with two
labels: `com.ecluse.test` = `integration` | `e2e`, and `com.ecluse.test.scope` = a **per-worktree**
id. That id comes from `ECLTEST_SCOPE`, which every container-running target sets:
`task test-integration`, `task test-e2e`, and the `coverage` tier `task check` runs.

Every harness and CI variable uses the `ECLTEST_` prefix, never `ECLUSE_`. The config loader claims
the whole `ECLUSE_` prefix and aborts the boot on any variable under it that is not a config key, so
a harness variable on that prefix would stop the very proxy the tests are booting.

Both harnesses tear their own containers down on a normal exit, and the `docker run`s carry `--rm`.
The gap is a **hard kill** (SIGKILL, OOM, a timed-out command), which runs no cleanup and leaves the
topology behind. Two reaping commands close it, both driven by `scripts/test-containers.sh`:

- **`task test-clean`** removes only *this worktree's* test containers and networks (keyed on
  `com.ecluse.test.scope`), so it is safe to run while other worktrees have suites running. The
  container-running targets run it automatically before and after the suite.
- **`task test-clean-all`** removes *every* Écluse test container/network/image on the
  daemon regardless of scope. Reach for it only when no other suite is running.

Inspect what is lingering with `docker ps --filter label=com.ecluse.test`. The label writer
is `Ecluse.Test.Containers`, kept in lock-step with the reaper.

**Every image the test tiers pull is fully digest-pinned (`name@sha256:...`), and a mutable tag is
never pulled.** A tag can be re-pointed to a poisoned image between pulls, while a digest is
immutable. A *type* enforces it: a pull site accepts only a validated `PinnedImageRef`
(`Ecluse.Test.Container.Image`), so an unpinned pull is unrepresentable and aborts the suite before
pulling. Every pin lives in that same module beside the validator, and a harness names the pin
rather than the digest. To absorb Docker Hub throttling on the shared runners, the CI jobs warm those
exact references first through `scripts/docker-prepull.sh`. The `ci.yml` comments own that rationale.

## What gates, and what doesn't

Two things are easy to get backwards:

- **The integration tier is not "the tier for thorough tests."** A test goes to integration because
  its collaborator can only be a *real* (emulated) service, not because the test is broad. A
  cross-component test that needs no live external service is a **unit** test, even when it wires the
  whole pipeline. The proxy request-lifecycle runs against an in-process WAI stub in `ecluse-unit`.
  Put a test wherever its subject runs *deterministically*.
- **The smoke tier is a drift *detector*, never a correctness *guarantee*.** It depends on
  uncontrolled external services, so it cannot gate, and nothing we rely on for correctness may live
  *only* there. Every load-bearing behaviour owes a deterministic, gating mirror in the unit or
  integration tier. A smoke test only confirms the model still matches the live world. Version
  ordering is the template. The gate checks it offline against a committed fixture, and the smoke
  suite also regenerates that fixture from the live oracles as a differential check.

Beyond the test tiers, two static-analysis jobs gate. **`weeder`** reports library code not reachable
from the entry point (`Ecluse.run`). **`stan`** runs HIE-based partial-function and bug analysis at
the floor in `.stan.toml`. Each is its own parallel job the CI `gate` depends on, and a finding above
its floor blocks the merge. Among the always-on jobs, only `smoke` is non-gating.

A PR that edits documentation only skips the Haskell jobs. The `changes` job classifies it
against an allow-list of documentation paths in
[`scripts/ci-classify-change.sh`](../scripts/ci-classify-change.sh), which fails closed: an
unlisted path runs everything. The static checks run on every PR either way, because the site
build reads the very files such a PR edits, and it fails on a broken internal link or anchor.
The `gate` job accepts a skipped job from that filter and from nothing else, so a job that
silently never ran still fails the gate. Such a PR uploads no coverage, so the required
`codecov/project` status stays pending by design, and the repo owner merges it by
administrator bypass.

## Coverage: Codecov (gating)

CI measures coverage per gating suite and reports it to [Codecov](https://about.codecov.io/).
Generation is local and tool-agnostic. A suite is built instrumented: HPC, in an isolated
`dist-coverage/` that leaves the normal build cache alone. Then `hpc-codecov` converts the
`.tix`/`.mix` output to Codecov's native JSON. `scripts/coverage.sh` produces one tier. The Taskfile
`coverage` task assembles the merged view inline.

**Codecov is the merged authority, and `task coverage` reproduces it.** Codecov merges the per-flag
uploads into one project total. A single tier's number therefore *under-counts* the modules the
others exercise: only integration covers the SQS `MirrorQueue` and the worker's fetch/publish path.
`task coverage` runs the three instrumented unit suites plus `ecluse-integration` and
`hpc combine --union`s them into `coverage/combined.json`, so it agrees with the dashboard. It runs
the integration tier, so it needs a Docker daemon. Without one it fails and points at the fast path.
For a quick, Docker-free loop, `task coverage-unit` (default `SUITE=ecluse-unit`, or another suite)
measures one tier and prints loudly that it is a partial view.

**What CI uploads.** The build-test job runs `task cabal-checks`, which runs `task coverage`. That
writes four per-suite JSONs as a byproduct: `ecluse-core-unit`, `ecluse-runtime-unit`, and
`ecluse-unit` (all under the Codecov flag `unit`), and `ecluse-integration` (flag `integration`). CI
uploads each under its flag. Codecov waits for all four (`notify.after_n_builds: 4` in
[`codecov.yml`](../codecov.yml)) before it computes the total, so a partial upload cannot fire a
transient "coverage decreased" status. The smoke and e2e tiers upload nothing: they are not built
with HPC, so a line only they exercise reads as uncovered. Never reason "the e2e test covers it". A
path that needs coverage needs a unit or integration test.

The combined command removes a *reporting* confusion, a local single-tier read that disagrees with
the merged dashboard. It does not paper over gaps. If the *merged* report still shows a module's
error arms red (e.g. `Worker.hs`'s fail-closed integrity-mismatch branch), that is a genuine
uncovered path a test owes.

The gate is Codecov's two commit statuses, both in [`codecov.yml`](../codecov.yml).
`codecov/project` allows no regression versus the PR base, within a 1% threshold. `codecov/patch`
requires new and changed lines at ≥ 85%, a floor that verifies behaviour rather than a number to
chase. Uploads use GitHub OIDC (`use_oidc: true`), so there is no `CODECOV_TOKEN` to leak. Coverage
measures library code only. It excludes `app/**`, `bench/**`, and `test/**`, and drops every
`Ecluse.Test.*` module of `ecluse-test-support` from the HPC report too.
[`docs/style.md`](style.md) → "Data types and deriving" decides which derived instances the 85%
patch bar treats as accepted partials.

**References:** [testcontainers](https://hackage.haskell.org/package/testcontainers) ·
[ministack](https://github.com/ministackorg/ministack) (local AWS emulator, image
`ministackorg/ministack`, port 4566).

## Style

Tests are documentation too, so keep them as readable as the code.

- **Structure with `hspec`**: `describe` per function/area, `it` with a full-sentence
  expectation.

  ```haskell
  describe "evalRule" $ do
      it "AllowScope allows a matching scope" $
          evalRule ctx (AllowScope (mkScope "myorg")) (pkg (Just "myorg") 0)
              `shouldSatisfy` isAllow
  ```

- **Name fixtures and helpers, and give them signatures** (`now :: UTCTime`,
  `pkg :: Maybe Text -> Integer -> PackageDetails`). A small builder that fills defaults and
  exposes only the axis under test keeps each case to one line.
- **Add small predicate/extractor helpers** (`isAllow`, `approvedBy`) instead of inlining
  pattern matches in assertions.
- **Express invariants as `hedgehog` properties** under `describe "properties"` with `forAll`
  and `(===)`: an invariant that must hold for *every* input (order-independence, a round-trip
  law) belongs here.
- **Share cross-suite helpers through `ecluse-test-support`** (`test/support/`). A helper more
  than one suite needs lives there, never copied per suite. Its modules mirror the main-library
  namespace, so a helper for `Ecluse.X` lives in `Ecluse.Test.X`: the digest fixtures and
  `unsafeHash` for `Ecluse.Core.Package` live in `Ecluse.Test.Package`. Cross-cutting helpers
  live in `Ecluse.Test.Support`. A helper only one suite uses stays local.
