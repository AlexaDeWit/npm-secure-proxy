# Configuration and authentication

> Part of the [Écluse architecture overview](../architecture.md).

Why Écluse's configuration has the shape it has: two layers, a derived mount, safety floors that
fail closed, and client authentication at the edge.

## Configuration

> **Operators:** [`config/default.yaml`](../../config/default.yaml) documents every key and its
> default, and [the operator manual](https://ecluse-proxy.com/docs/) covers the environment-variable mapping,
> client setup, and the network-egress checklist. This document holds the design rationale.

Configuration has two layers. Environment variables carry process-level and secret values. A
structured YAML document carries the two things too expressive for flat env vars: the **rule
policy** and the **mount map**. The rule policy earns the document its keep: per-rule
precedence and value overrides, layered over a built-in default (see [Rule policy](#rule-policy)).

A mount's shape is **derived, not declared**. Any operator-supplied key under `mounts.<ecosystem>`
activates it, and a declared `mirrorTarget`, not a mode flag, makes it mirrored. A mirrored mount
then requires a `privateUpstream` so the mirror reads back.

Each endpoint a mount names is one **tagged target**: an object with exactly one key, the tag, and
under it the keys that tag admits there. The tag names the store backend and the load checks the
URL against it, so a `codeArtifact:` endpoint whose host is not a CodeArtifact endpoint refuses at
load naming the key. There is no bare-URL shorthand, because one fact with two spellings drifts.
The operator manual carries the admission matrix. Two consequences fall out of the layering rule.
Layers union objects, so an environment variable under a tag the document did not use leaves two
tags on the endpoint and refuses as such: a layer fills keys under a tag, it never switches one.
And two endpoints that name one registry under different tags refuse for every role, because one
store has one backend.

Secrets never live in the structured config. A token is always an environment variable. A mirror
target under the minting tag holds none: the worker mints a short-lived token from ambient cloud
credentials instead (see [Outbound registry credentials](#outbound-registry-credentials)).

### Registry endpoints must be https

Every registry endpoint must be an `https://` URL: the private and public upstreams, the mirror
target, and the publication target. A plain-HTTP endpoint fails closed at boot with an error naming
the URL.

Certificate validation is the endpoint-authentication boundary. The shipped image is distroless
and has no system trust store: it pins `SSL_CERT_FILE` to a bundle of public roots in the Nix
store. To use a private registry on an internal CA, mount a bundle that holds your chain beside
those public roots and point `SSL_CERT_FILE` at it. The proxy pre-bakes no custom CA trust. It
upgrades a plaintext `dist.tarball` to https when the legacy upstream advertises it on its own
host. It drops a plaintext tarball on any other host and skips that version.

### Upstream composition (optional)

`mounts.npm.privateUpstream` may point at a single registry, or at one that aggregates
others: a CodeArtifact repository with upstream relationships to the mirror-target and first-party
repos. One fetch then returns the whole trusted set. This is an optimisation, never a precondition,
because Écluse [merges packuments across upstreams](registry-model.md#packument-merge-across-upstreams)
itself. One rule keeps it safe: the aggregator must not add a direct connection to the public
registry, which would route unvetted packages around the gate. The proxy always fetches and gates
the public upstream itself.

### Outbound registry credentials

A **mirrored** mount holds a credential to write its mirror target. That write is Écluse's only
standing credential. It runs on the async worker under Écluse's own identity, and reads carry none
of it. A serve-only mount, or a deployment with no mirrored mounts, mints nothing.

A credential is always its own key, never part of an endpoint. Écluse refuses a registry URL
carrying userinfo, a query string, or a fragment at load, and the error names the key. That refusal
lets the boot-time configuration echo, the endpoint-collision warnings, and the mount posture lines
print a configured endpoint as written.

The tag is the declaration: it names the store behind an endpoint, and the load checks the URL
against it, so Écluse can never pair a credential with an endpoint it was not scoped for. The
`codeArtifact` tag requires a host of the shape
`{domain}-{owner}.d.codeartifact.{region}.amazonaws.com`, which encodes the whole mint identity, so
the worker mints a short-lived token scoped to that domain and the tag admits no static one. The
two non-minting tags each require a `token` under a mirror target.

A tag never moves the credential posture. Reads stay per-caller passthrough under every tag, the
public upstream stays anonymous, the mirror write stays Écluse's one standing credential, and a
`publicationTarget` token stays the fallback Écluse forwards only when the publishing client sends
none.

The CodeArtifact mint is per
domain, so mounts whose resolved identities coincide share one
[`CredentialProvider`](cloud-backends.md#the-credential-mint): one mint, one refresh, one breaker.

### Outbound egress safety

Écluse constrains its own outbound fetches. It applies an https-only host allowlist, a literal
internal-range block on the `dist.tarball` host, and certificate validation that authenticates the
dialled host. Network egress is still a shared responsibility: the deployment must also fence
egress at the platform layer, with security groups, `NetworkPolicy`, or Istio egress policy. See
[Securing network egress](https://ecluse-proxy.com/docs/deployment/#network-egress).

One application-level knob adjusts threat tolerance, and it only tightens: it widens the fixed
internal-range set with operator-supplied CIDRs. The tarball-host gate derives from the mount's own
endpoints and takes no operator setting. See the
[configuration reference](https://ecluse-proxy.com/docs/configuration/#the-configuration-reference)
for the names and values.

### Runtime sizing: cores and heap ceiling

The resolved posture seeds a second derivation, the **memory plan**. It partitions the effective
heap ceiling between named tenants whose sum it bounds:

- a runtime reserve
- the metadata cache
- the materialisation working space
- the publish-body aggregate
- the in-memory queue tenant, when selected
- the enqueue buffer
- the mirror-artifact envelope, when any mount mirrors

The mirror-artifact tenant covers the transient the mirror worker holds. That worker buffers a
fetched tarball and base64-encodes it into a publish document. The bytes, the base64 text, and the
serialised document coexist before collection. The derivation sets the worker fetch cap
(`maxArtifactBytes`) so that this envelope is what the tenant charges. An explicit config value
wins its own bound, and otherwise the shipped fallbacks apply.

A pod too small for the tenants' floors sheds in a documented order and always boots. The
mirror-artifact cap goes first, to zero, so the background back-fill leg gives way before the serve
hot path. The cache goes next, also to zero, and each step logs a loud warning. The boot and
`check-config` alike refuse only an explicit override that breaks the plan.

The structural hostile-input counts (`maxVersionCount`, `maxArtifactCount`, `maxNestingDepth`) stay
pinned policy. They bound document shape, not bytes, and do not scale with RAM. The resolution is role-agnostic and
binds proxy, Pilot, and Dredger alike. The Operator Manual carries the [per-pod
arithmetic](https://ecluse-proxy.com/docs/operations/#appendix-runtime-sizing-arithmetic).

### Rule policy

The rule policy is a named map of rules layered over a built-in default that ships with the binary.
An entry whose name the default already defines is a **patch**: it overrides precedence, values, or
both. An entry with a new name must carry a full `type`, and it **adds** a rule. Any entry may set
`"enabled": false` to **suppress** a default rule. With no rule config, the default policy applies
unchanged.

This top-level policy applies to every mount. A multi-ecosystem deployment may give an individual
mount its own [refinement](web-layer.md#multi-ecosystem-mounts) that merges over it.

```yaml
rules:
  min-age:
    ageSeconds: 1209600
  deny-scripts:
    type: DenyInstallTimeExecution
    precedence: 200
```

Here `min-age` names a default rule, so it overrides that rule's value. `deny-scripts` is a new name
carrying a `type`, so it adds a rule. Each rule may set an integer `precedence`, where higher wins.
Omit it for the type's default.

[Rules engine → Evaluation model](rules-engine.md#evaluation-model) is the canonical home for the
precedence values, the single total order the rules resolve into, and the evaluation model. This
document owns only the document-merge schema above.

#### The default policy

The shipped default enables two rules. `min-age` (`AllowIfOlderThan`, 7 days) admits a public
version that survived a quarantine window, the core defence against race-to-publish typosquatting
and dependency confusion. `remediation-fast-track` (`AllowIfRemediatesCve`) ranks above it, so
Écluse admits a release fixing a known CVE at once rather than waiting out the quarantine (see
[Rules engine](rules-engine.md#allowifremediatescve-remediation-fast-track)).

Every other built-in rule is off and opts in by name. The advisory denies (`DenyIfCve` and
`DenyIfEpss`) in particular can deny historical versions an existing build depends on, if an
operator enables them before the mirror is warm. Read their
[onboarding steps](https://ecluse-proxy.com/docs/configuration/#onboarding-the-advisory-denies) first.

### Advisory database sync

The remediation fast lane and the two advisory denies read a synced local advisory database, not an
API per request. The compilation, ETag polling, and atomic shadow-swap are under [Rules engine → CVE
subsystem](rules-engine.md#cve-subsystem). The operator knobs (the store URL, the poll interval, the
OSV export and EPSS feed sources, and the download size cap) are in the
[configuration reference](https://ecluse-proxy.com/docs/configuration/#the-configuration-reference).
With no store configured, the fast lane abstains and the age quarantine governs alone.

### Validation: fail fast, reject the unknown

Écluse validates the whole config at startup and refuses to start on any problem, never running in
a degraded state. It aggregates the errors, so one run reports every issue. An unknown name is an
error, not a silent skip:

- Écluse rejects an unknown rule `type`, and an unknown field or key. An operator authors the
  config alongside the binary, and deny-by-default protects you only if the policy you wrote is the
  policy that loaded. A typo must fail the load rather than silently stop blocking. The same
  reasoning reaches inside a rule: a rule reads only its own type's parameters, so a threshold or
  an `onUnavailable` written under a type that does not read it is refused rather than ignored.
  Ignoring it would leave an operator believing they set a gate's failure direction.
- Malformed values (bad URL, non-integer precedence, unparseable JSON) fail the same way.
- Merge references must resolve. Écluse rejects a `rules` entry that neither names a known default
  nor supplies a complete new rule.
- Écluse rejects a mount incoherent with its derived mode: a mirrored mount with no
  `privateUpstream`. The error names the offending key, and one report covers every incomplete
  mount.
- An endpoint must carry exactly one tag and only the keys that tag admits there. The mirror-write
  credential falls out of that: the minting tag admits no static token and the two non-minting tags
  require one. Écluse still rejects a CodeArtifact identity that cannot mint an initial token.
- A `codeArtifact` endpoint's URL must match its tag. Écluse rejects a host that is not a
  CodeArtifact endpoint on any endpoint, and on a mirror target it also rejects a path that is not
  the repository endpoint for the mount's own ecosystem (`/npm/{repository}/` for an npm mount) and
  an ecosystem CodeArtifact carries no package format for. Each refusal names the key path.
- A static publish credential requires a verifiable edge. A `token` under a `publicationTarget`
  tag without `ECLUSE_SERVER__AUTH_TOKEN` is refused as
  `PublishStaticCredentialNeedsEdge`. That pairing would let any unauthenticated client publish
  under Écluse's own identity.
- Endpoints that hold different registry roles must not name one registry. Every role refuses a
  `publicationTarget` on any mount's `publicUpstream` host, a `publicationTarget` equal to another
  mount's `privateUpstream`, `mirrorTarget`, or `publicationTarget`, and a `mirrorTarget` on any
  mount's `publicUpstream` host. `ecluse dredger` deletes from each mount's `mirrorTarget`, so it
  also refuses a `mirrorTarget` equal to any mount's `privateUpstream` or to its own mount's
  `publicationTarget`. `ecluse proxy` and `ecluse mirror` boot on those three and warn once per
  collapsed pair, and the operator prunes that mirror by hand. One combinator turns each detected
  collision into the outcome the booting role earns, so a refusal on one path and a warning on
  another always come from the same rule. The comparison is by full registry URL, not by host,
  because repositories of one CodeArtifact domain differ only in path, and a repository's per-format
  endpoints are separate stores. It folds the authority to lower case and applies the default port,
  so neither a capital letter nor an explicit `:443` defeats a refusal. Applying the default port
  keeps the port in the key rather than dropping it, so `:8443` stays a separate store. The path is
  compared exactly, which is what keeps those per-format endpoints apart.
- Every mount's `mirrorTarget` needs a store maintenance backend. `ecluse dredger` reads the tag,
  so it refuses a target whose tag names a store this build carries no control plane for. The
  refusal names the mount key and the reason. Only the Dredger deletes, so only the Dredger refuses:
  the other roles boot on such a target and log nothing, and `ecluse check-config` names the
  Dredger's refusal.

Most of those refusals are decided as the configuration loads. The mount-adapter rule, the
publish-policy pairing, the endpoint-disjointness rules, and the store maintenance backend are
decided after it, by one pure pass over the loaded configuration and the environment snapshot that
load read. The pass takes the booting role and accumulates, so one run reports every refusal and
every advisory that role earns, and the advisories reach the log even when a refusal stops the
boot. One decision sits outside it: a memory-plan override is judged against the resolved mirror
runtime, so a refused queue URL reports without it. The refusals `ecluse check-config` does not
reach are the ones a live environment settles. These are the steps that raise them:

- minting a CodeArtifact identity's first token
- building the mirror-queue backend
- preparing each mount ecosystem's advisory sync
- resolving a mount's mirror-write provider
- building the client the Dredger sweeps each mirror store with

The same validation runs without a boot. `ecluse check-config` runs the full resolution chain:
config load, runtime plan, sizing and memory-budget resolvers, mirror-queue selection, and the
ambient `AWS_ENDPOINT_URL` override. It prints every decision, one provenance line per resolved
key, secrets redacted, precedence environment > document > default. It exits `0` on a valid
configuration, and `2` with the same aggregated report a boot would log. Both entry points call
the one pure pass, so a role's verdict on one set of inputs is the same on either side of it. The
inputs are not the same value. A boot passes the runtime posture it measured after applying it,
and the checker passes the posture `appliedRuntimePlan` predicts an application would reach. Where
an application falls short of that prediction, the boot sizes the memory plan against the smaller
measured posture, so it can refuse an explicit override the checker cleared.

The checker picks no subcommand, so it runs the pass once per role. It runs no mirror pipeline and
prunes no store, so its own pass vets under the writing roles' severities, and that pass decides
the exit status. A refusal only some roles earn prints as a warning naming the command that earns
it: `ecluse proxy --no-worker` and `ecluse mirror` over the bounded in-memory queue, `ecluse mirror`
where no mount declares a `mirrorTarget`, and `ecluse dredger` on a collapsed endpoint pair or on
a `mirrorTarget` this build has no maintenance backend for. A configuration one role refuses and
another boots is a normal deployment, which is why those do not fail the check.

What the checker does not reach is the environment-dependent tier those refusals sit in. A boot
builds it and the checker makes no cloud call, which is also why allocating each mount's rule state
waits for a boot. Two types keep that boundary visible. The pure pass yields the boot plan, which is
the artefact the checker prints and the last one it can reach. A boot then runs an effectful
planning phase over that plan, which spends every remaining refusal and yields an executable plan.

Every role runs that phase, and each has its own arm in it. The three mirror-pipeline halves
settle the mount wiring, the advisory sync, and the queue backend there, and one run reports every
refusal all of that earns. `ecluse dredger` settles the credential its stores answer to, the
advisory sync its rules read, and one maintenance handle per cleared mirror store there, so a store
whose client cannot be built reports at the gate rather than on the first call against it. `ecluse
pilot` settles its export loop there, one compile cycle per mounted ecosystem, and refuses where an
advisory store is configured and no mount is. So an executable plan carries the role's own wiring,
and a boot spends its last refusal in one place whichever role it started.

Nothing downstream of an executable plan refuses to boot. Holding one means the assembly below it
only builds and allocates, so a role's runtime cannot reject a configuration the boot already
cleared. A listener that fails to bind and an upstream that stops answering are still possible, and
those are runtime faults for supervision rather than refusals.

## Client authentication

Inbound auth (client to proxy) is the edge half of the credential model. Écluse authenticates to
the upstreams per [Credential flow and authority](registry-model.md#credential-flow-and-authority),
and the client's credential never reaches the public upstream.

Cloud IAM cannot be the edge: npm clients speak Bearer tokens, not SigV4, mTLS, or OIDC.

Two edge modes ship. The **open** mode leaves `ECLUSE_SERVER__AUTH_TOKEN` unset and delegates
access to the network layer. The **static token** mode sets `ECLUSE_SERVER__AUTH_TOKEN`, and the
client presents it as `Bearer <token>` or as an `.npmrc` `_authToken`, which standard npm tooling
supports.
