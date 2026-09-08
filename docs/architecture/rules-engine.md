# Rules engine and responses

> Part of the [Écluse architecture overview](../architecture.md).

How Écluse decides whether to serve a package version, and what a denied request looks like on
the wire.

## Rules engine

**Deny by default. The boot order decides.** Each rule carries a configurable integer
precedence. At boot the rule set becomes one total order: highest precedence first, then rule
name ascending as the deterministic tiebreak. Evaluation walks that order and takes the first
decisive result. If nothing is decisive, the proxy denies the package. A precedence tie breaks
by name, not by a deny-over-allow priority, so shuffling the configured set yields the same
decision. Built-in deny rules default above allow rules, so "any deny overrides any allow" holds
out of the box. An operator can still rank a specific allow above a specific deny, say to let a
trusted internal scope through an install-script deny.

A rule evaluates one `PackageDetails` snapshot, the ecosystem-agnostic per-version view an
adapter produces (see [The internal domain model](registry-model.md#the-internal-domain-model)).
A rule never sees a registry wire format. Rule names track the agnostic concept, not one
ecosystem's mechanism: the install-time code-execution signal, not npm's `hasInstallScript`.
Where the signal a rule reads is absent for an ecosystem, the rule yields no decision, the
no-op under deny-by-default, never a configuration error.

A `Rule` is closed `Eq`/`Show` data with no evaluation. `evalRule` is the single dispatch over
it ([`Ecluse.Core.Rules`](../../core/src/Ecluse/Core/Rules.hs)). Keeping `Rule` closed is a
security boundary: untrusted config can only name a built-in constructor, never supply an
evaluator. A rule is **pure or effectful** by whether it carries a resilience policy, which
depends only on where its signal lives. So `DenyInstallTimeExecution` is pure for npm's
`hasInstallScript` but effectful for a RubyGems native `extensions` signal that appears only
inside the `.gem`.

### Evaluation model

Each rule applied to a `PackageDetails` yields a `RuleVerdict`, a deterministic answer, never a
fault:

- **`Allow`** and **`Deny`**: admit the version, or block it. Decisive.
- **`NoDecision`**: no opinion. A no-op, but the engine keeps the reason for the audit trail.
- **`CannotVet alignment`**: the rule reached the version but cannot vet it deterministically
  and in-process. Today that means no advisory database is loaded. It carries its own failure
  alignment (below). There is deliberately no fail-allow: a check that cannot vet must never
  admit unvetted bytes.

Under its resilience harness a rule either returns a decided verdict, taken at face value, or
the harness synthesises `Unavailable`. That means no verdict at all: the IO faulted, it timed
out, or the breaker is open. The engine walks the boot order and credits the winning rule by
name. With nothing decisive it collects each non-decisive reason, in boot order, so the denial
can explain what the engine considered. The
[`Ecluse.Core.Rules`](../../core/src/Ecluse/Core/Rules.hs) Haddock holds the full verdict and
harness vocabulary. The proxy logs the boot order at start-up (see
[Configuration → rule policy](configuration.md#rule-policy)).

### Effectful-rule failure

An effectful rule does IO that can fail or hang. Each carries a short per-attempt timeout with
bounded retry and backoff, and a per-source circuit breaker. After repeated failures the
breaker trips and the rule fast-fails for a cooldown. A sustained outage then neither adds
latency to every request nor hammers a down service. The shipped defaults are a 2-second
per-attempt timeout, two retries at 100ms then 250ms. The breaker trips after 5 consecutive
failures and cools for 30 seconds.

A fault the harness observes becomes `Unavailable`. A rule reports a deterministic in-process
absence as `CannotVet`, for example no advisory database loaded. The harness takes that at face
value: no retry, no breaker count, since no retry could change it. The rule's failure alignment
governs either one:

- **`FailDeny` (fail-closed, the default)**: decisive. The gate refuses a version a needed rule
  could not vet, whether the scanner is down or the advisory database is not yet loaded.
- **`FailNoDecision` (fail-open)**: a no-op, for a remediation or allow-direction rule where a
  missing signal should not block availability. There is deliberately no fail-allow.

The blast radius is small. Only packages not yet in the private mirror reach this path.
Already-approved versions serve from the private upstream with no rules. How a fail-closed
failure surfaces depends on the request shape. On a packument the pipeline filters the version
out like a denied one, with no error unless nothing survives. On a concrete artifact it
surfaces through the [error model](web-layer.md#error-model) as `503` with `Retry-After` when
transient, and `500` when not. A fail-closed undecidable result logs at WARNING with the denial
audit fields. A breaker trip logs nothing and moves the `ecluse.rule.breaker.state` gauge instead.

### Applying verdicts to a packument

Evaluation decides one version, but a metadata request returns a whole packument, so the
pipeline applies verdicts across it. For the cross-upstream merge, see
[Registry model → Packument merge](registry-model.md#packument-merge-across-upstreams).

- **Resolve `dist-tags.latest`: keep unless denied, prefer stable.** `latest` stays as published
  while that version survives, so `npm install <pkg>` resolves to the maintainer's chosen
  release. The pipeline repoints `latest` only when the chosen version is itself denied or
  removed, and then to the highest stable surviving version. It falls back to the highest
  prerelease survivor only if no stable version survives. "Stable vs prerelease" is
  ecosystem-specific (`Ecluse.Core.Version.isStable`), so the core stays agnostic by calling the
  predicate. The pipeline drops other tags (`next`, `beta`) at a removed version rather than
  repointing them. The rule never promotes a higher prerelease over a chosen stable `latest`.
  Repointing downward is a deliberate downgrade, so a withheld release does not silently remain
  the default install.
- **No survivors → 503, 502, 500, or 403.** If nothing survives, the status follows the most
  recoverable cause. `503` (with `Retry-After`) when any rejection was transient or a needed
  upstream was unavailable. `502` when an upstream returned a document Écluse could not use.
  `500` when an exclusion is a permanent inability and none is retryable. `403` with the
  collected denial reasons when every rejection is by policy. Never `404`: the package exists,
  and Écluse withheld its versions. The HTTP status mapping belongs to the
  [error model](web-layer.md#error-model).

Because the filtered body differs from upstream's, the proxy computes its own `ETag` over it
(see [Web layer](web-layer.md#web-layer)).

### Initial rule set

The rule catalogue, each rule's type and parameters, lives in
[`config/default.yaml`](../../config/default.yaml) and the operator manual's
[rule policy](https://ecluse-proxy.com/docs/configuration/#rule-policy).

The **default precedence ladder** climbs from most-passive to most-decisive:

```text
AllowIfOlderThan (100) < AllowIfRemediatesCve (150) < AllowScope (200) <
DenyIfCve = DenyIfEpss (225) < AllowByIdentity (250) <
DenyInstallTimeExecution (300) < DenyByIdentity (400)
```

`DenyInstallTimeExecution` and `DenyByIdentity` default strictly above every allow, so "any deny
overrides any allow" holds for them out of the box. The two advisory denies are the deliberate
exception. They share a rung **below** `AllowByIdentity` (225 against 250), so an operator's
exact-identity allow overrides either. That is the explicit "I have decided this version must ship"
escape hatch. Both still sit above the passive age gate, the remediation lane, and a scope
allow-list, and configured together they tie, which the boot order resolves by name. An operator may
raise a specific allow above a specific deny, or the reverse, with an explicit precedence.

The [default policy](configuration.md#the-default-policy) records which rules ship enabled: the
pure `AllowIfOlderThan` quarantine (`min-age`) and the `AllowIfRemediatesCve` fast lane. The
fast lane abstains when no advisory database is configured, so only the quarantine governs.
Every other rule is off by default and opts in by name.

## CVE subsystem

The advisory subsystem reads a synced local copy rather than calling an advisory API per
evaluation. The `CveLookup` handle ([`Ecluse.Core.Cve`](../../core/src/Ecluse/Core/Cve.hs))
reads the synced `osv.db` SQLite artifact on local disk, never the network, on the hot path. It
models an advisory's affected set faithfully: range bounds (inclusive `introduced`, exclusive
`fixed` or inclusive `last_affected`) and exactly-enumerated versions as points. Each advisory also
carries a numeric CVSS base score and, where the EPSS feed scores one of its identifiers, an EPSS
probability. Each evaluation brackets its own acquisition, so the
[shadow-swap](#local-polling-decoupled-ingestion) can retire a superseded artifact the moment no
evaluation still reads it. Two rules read it in opposite directions.

### `AllowIfRemediatesCve`, remediation fast-track

A publish-age quarantine would also hold back the security patch that fixes an in-the-wild
vulnerability, delaying remediation by exactly the window meant to catch typosquats.
`AllowIfRemediatesCve` removes that tension. For version *V* of *P*:

- **`Allow`** when an advisory names *V* as its exact fixed version and no advisory's affected
  range still contains *V*. The reason names the remediated advisory IDs.
- **`NoDecision`** otherwise (including before a first sync), and a fail-open `Unavailable` when
  a lookup against a loaded database faults. An allow that cannot confirm a remediation **fails
  open**, unlike a deny, which fails closed. The version then falls back to the normal
  quarantine instead of being admitted on an unverified claim.

It ranks above the quarantine allow, so the rule admits a fix immediately. It ranks below the
scope allow-list, so a trusted scope never pays the probe. The fix test is a deliberate exact string
match on the advisory's canonical `fixed` version. A fix published under any other string waits
out the quarantine, with `AllowByIdentity` as the operator's workaround. The rule decides range
membership in Haskell with the same per-ecosystem ordering as
[`compareVersions`](registry-model.md#the-internal-domain-model). Every unprovable comparison
counts as affected, so the lane only opens on evidence.

### `DenyIfCve`, the deny direction

`DenyIfCve` reads the same lookup to block version *V* of *P* when an advisory affects *V* at or
above a configured CVSS `minCvss`. It is **opt-in** and does two jobs against the npm feed.
Most of that feed is the malware feed: `MAL-*` advisories that carry no CVSS score and name the
bad version exactly. A smaller share is CVSS-scored CVEs. An unscored advisory counts as **above
every threshold**, so the rule always denies malware while `minCvss` governs the scored CVEs.

- **`Deny`** when some advisory affects *V* and clears the threshold. The reason names the
  deciding advisories.
- **`NoDecision`** when no affecting advisory clears it.
- **`CannotVet`** when no advisory database is loaded, and the harness's **`Unavailable`** when a
  loaded-database lookup faults. Both align by `onUnavailable`. **`FailDeny`** (the default)
  refuses the version with a retryable `503`. **`FailNoDecision`** skips the rule and logs
  loudly. This is the inverse of `AllowIfRemediatesCve`: neither an allow nor a deny that cannot
  confirm safety may admit.

Enabling it on a cold mirror can deny historical versions an existing build depends on, so it
ships off. Warm the mirror first, as
[Onboarding the advisory denies](https://ecluse-proxy.com/docs/configuration/#onboarding-the-advisory-denies)
sets out.

### `DenyIfEpss`, the exploitability direction

Severity states how bad a vulnerability would be. It does not state whether anyone is exploiting it.
FIRST.org's Exploit Prediction Scoring System (EPSS) estimates the probability that a vulnerability
is exploited in the wild within the next 30 days, and a moderate CVE under active exploitation is a
worse risk to a build than a critical one nobody has weaponised. `DenyIfEpss` denies version
*V* of *P* when an advisory affects *V* and its EPSS score is at or above the configured `minEpss`.

It is the twin of `DenyIfCve`: the same lookup, the same verdict vocabulary, the same failure
alignment, and the same precedence rung. Only the score it compares differs. An advisory the
artifact carries no EPSS score for counts as **above every threshold**, the same fail-closed
direction as an unscored CVSS advisory. That is not a rare case on the npm feed. EPSS keys on CVE
ids, the artifact's rows key on the advisory id, and the join runs through the advisory's `aliases`
array, so an advisory with no CVE alias, which includes the whole `MAL-*` malware feed, arrives
unscored. An operator should read the rule as "deny on exploitability, and on anything whose
exploitability cannot be established", and enable it alongside `DenyIfCve` rather than instead of it.

Pilot supplies the score. It fetches the EPSS daily feed each compile pass, joins it onto the
advisories through their aliases, and writes the result to the artifact's `epss_score` column
([`Ecluse.Core.Osv.Epss`](../../core/src/Ecluse/Core/Osv/Epss.hs)). The download is bounded twice, on
the served stream and again on its gzip expansion, so neither an endless stream nor a compression
bomb can hang or exhaust the pass. A feed past either bound is refused whole rather than truncated,
because a short table is indistinguishable from a complete one downstream. A pass that cannot fetch
the feed, or that decodes no scores from it at all, fails rather than publishing an artifact whose
scores all read as absent, which every EPSS rule would then read as a deny.

### Local polling, decoupled ingestion

Parsing raw JSON advisory dumps on the proxy costs heavy GC pressure and memory spikes. So
Écluse decouples that work into **Écluse Pilot**, a standalone service. Pilot pulls OSV's
per-ecosystem exports, compiles them into a read-only SQLite database (`osv.db`), and pushes it
to a private object store. `advisories.url` names that store as `s3://bucket[/prefix]`, its
scheme picking the provider the way `queue.url` does. Unset, the advisory stack is off.

OSV retains withdrawn records in its [GCS exports](https://google.github.io/osv.dev/faq/#how-does-osvdev-handle-withdrawn-records).
Pilot excludes records carrying a withdrawal timestamp before it emits affected ranges or exact versions.
Their retained ranges cannot justify an advisory deny, a remediation exception, or Dredger deletion after a replacement artifact syncs.
Independent active advisories still supply their own evidence.

This selection fix keeps epoch 4 because the meaning of each emitted row remains unchanged.
[Deployment](../../web/content/docs/deployment.md) covers replacement artifacts and older publishers during rollout.

The proxy runs one supervised sync task per configured mount ecosystem
([`Ecluse.Runtime.Cve.Sync`](../../runtime/src/Ecluse/Runtime/Cve/Sync.hs)). Each task polls the
store's stable per-ecosystem key for ETag changes at `advisories.pollInterval`. That interval
is deliberately shorter than Pilot's compile interval, since matching them would nearly double
the worst-case advisory age. The tasks are independent, so one ecosystem's missing artifact
never holds back another's.

The proxy downloads a newly detected `osv.db` to a temp file, byte-bounded by
`limits.maxAdvisoryDatabaseBytes`. It treats the file as untrusted even behind the store's access
controls. It accepts the file only after a cheapest-first verification: epoch stamp, integrity
scan, the required tables' strict-schema conformance, ecosystem. It then renames the accepted
file atomically and shadow-swaps it into the read path
([`Ecluse.Core.Cve.Slot`](../../core/src/Ecluse/Core/Cve/Slot.hs)). The swap waits for the
displaced generation's readers to drain, so pruning is the kernel's reclamation, never a
mistimed delete. The proxy discards a refused artifact and remembers its ETag. The last-good
generation keeps serving. [Readiness](web-layer.md#meta-routes-ping-health-and-search) waits
for each ecosystem's first sync while the listener serves throughout. An absent database only
abstains into deny-by-default.

Polling removes the one external dependency that would otherwise sit under the fail-closed gate:
an advisory-source outage becomes sync lag, not per-package blocking. Lookups also leave the hot
path, since Écluse checks a version only before mirroring it and serves it rule-free after.

#### The artifact contract

The object key is stable per ecosystem and embeds the table-schema epoch,
`<ecosystem>-osv-schema<N>.db` (currently `npm-osv-schema4.db`). That stability is what makes
ETag polling work. The epoch is a hand-bumped constant shared by the Pilot writer and the proxy
reader ([`Ecluse.Core.Osv.Schema`](../../core/src/Ecluse/Core/Osv/Schema.hs)), stamped inside
the artifact as SQLite's `user_version`. A mismatch keeps the last-good database and alarms.

The artifact is **immutable and rebuilt from scratch** on every compilation, so there are no
migrations, only a read-compatibility contract. Advance the epoch for an incompatible table shape
or an incompatible meaning of stored values, even if the columns remain unchanged. A compatible
addition does not bump it, because readers select explicit columns. What the reader requires is a
separate question from what the epoch names: within epoch 4
the reader requires `severity` and `epss_score` on `package_vulnerability_ranges`, so an artifact
missing a required column, or carrying it under a different declared type, fails schema
conformance (`CveDbSchemaNonConformant`) and the last-good database keeps serving.

Epoch 4 stores canonical package names: PEP 503 for PyPI, verbatim for npm and RubyGems.
Rules query the same canonical key for denial and remediation. Dredger parses the stored keys
and store names into the same package identity before evaluating the shared rules.
Display spelling remains available for decision messages.

The [OSV schema](https://github.com/ossf/osv-schema/blob/main/docs/schema.md#defined-ecosystems)
requires normalised PyPI names. The sampled records
[GHSA-m2qf-hxjv-5gpq](https://api.osv.dev/v1/vulns/GHSA-m2qf-hxjv-5gpq) and
[PYSEC-2021-142](https://api.osv.dev/v1/vulns/PYSEC-2021-142) use `flask` and `pyyaml`.
Those samples do not establish feed-wide conformance. Pilot applies the existing package
canonicalisation itself because configured exports can carry other spellings. Epoch 3 did not
enforce this stored meaning, so epoch 4 consumers reject those artifacts despite their matching
table shape. Unknown ecosystems retain their package spelling.

Pilot also decodes a version sentinel: OSV writes "affected from the beginning" as an `introduced`
of `0`, which semver rejects, so the compile records no lower bound and leaves the `fixed` or
`last_affected` bound beside it unchanged. A version at or above the fix then computes as
admitted and one below it as denied.

A bound the ecosystem's version grammar cannot parse is a signal rather than a filter. The
compile counts those rows, names one on a warning line, and carries the count on its summary
line and its span, so an operator sees a feed going wrong without an advisory going missing.

The reader keeps two readings of such a bound apart. A range whose endpoint no grammar can
order stays fail-closed and denies every version of its package, since nothing can place a
version against it. A segment whose lower and upper bound are the same unorderable string
names one exact version, which is how OSV writes an enumerated version, so it matches that
string and nothing else. A bound the grammar does parse keeps the ordered comparison
throughout.

Pilot filters rows to the target ecosystem, so an advisory spanning two ecosystems does
not leak foreign package rows. Each denial's audit log records the advisory database ETag live
at emit (`active_advisory_db_etag`). That is deliberately the ETag live at emit rather than the
one the rule evaluated against, since a shadow-swap can land mid-request.

### Point-in-time gating, a known limitation

CVE gating happens at ingestion. Écluse checks a version once, before it enters the mirror, and
serves it rule-free thereafter. So the gate does not catch a CVE disclosed after the version
reaches the mirror. The [threat model](https://ecluse-proxy.com/docs/threat-model/) catalogues
the post-ingestion disposition: operator scanning, a hard deny-by-identity revocation, and
operator purge, *deny-then-purge*. Holding the dataset locally keeps a periodic mirror re-scan
straightforward to add later.

## Denial responses

When Écluse denies a request, because no allow rule matched or a deny rule fired:

- The agnostic serve layer decides the HTTP status: 403 for policy denials. See
  [Web layer → Error model](web-layer.md#error-model).
- The response body shape is the ecosystem's. The route contract supplies the typed response
  constructor and codec, so the agnostic pipeline holds no body shape of its own. For npm the
  codec ([`Ecluse.Core.Registry.Npm.Serve`](../../core/src/Ecluse/Core/Registry/Npm/Serve.hs))
  emits the npm error object:
  ```json
  {
    "error": "Package @evil/pkg@1.0.0 was denied: AllowIfOlderThan, published 3 hours ago, minimum age is 7 days. Contact #platform-eng on Slack for assistance."
  }
  ```
- Every denial carries its reason: which rule decided, and why.
- The ecosystem-neutral `appendHelp` adds `ECLUSE_SERVER__HELP_MESSAGE`, if configured, to
  every denial before the renderer wraps the body.
