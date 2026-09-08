+++
title = "Configuring Écluse"
description = "Where every Écluse setting lives, which layer wins, where secrets go, and how the rule policy decides what a build may install."
weight = 4
+++

Every choice Écluse makes at the gate traces back to a setting on this page. The binary embeds
every default, so you write down only what you change: a wider quarantine, a mirrored mount, a
policy of your own. Start with where a setting lives, because there are two places and one always
wins.

## Two layers, one spelling rule

Configuration has two layers. **Environment variables** carry process and secret values. An
optional **config document** (YAML) carries the two things flat variables express badly: the rule
policy and the mount map. A value resolves as defaults < config document < environment variable,
so the environment wins. The boot log carries one `config:` line per resolved key, naming the layer
that supplied it and redacting secrets, and `ecluse check-config` prints the same dump.

> **One spelling rule.** Environment variables are the mechanical transliteration of the document
> schema: `__` descends into an object and `_` joins a camelCase word. So `ECLUSE_CACHE__MAX_BYTES`
> spells `cache.maxBytes`, and `ECLUSE_MOUNTS__NPM__MIRROR_TARGET__CODE_ARTIFACT__URL` spells
> `mounts.npm.mirrorTarget.codeArtifact.url`.

Écluse owns the whole `ECLUSE_` prefix. Every `ECLUSE_*` variable is read as a key of that schema,
and one naming no key aborts the boot rather than resolving to a default, so a typo surfaces at
startup. Only two families are consumed before the resolver sees them and therefore name no key:
`ECLUSE_CONFIG`, and the `_FILE` secret indirections under [Secrets](@/docs/configuration.md#secrets).
Keep your own unrelated settings out of the prefix.

Mounts are off until you declare them. Mentioning one anywhere, whether through an
`ECLUSE_MOUNTS__<ECOSYSTEM>__*` variable or a key under `mounts.<ecosystem>` in the document,
switches it on. Declaring `mirrorTarget` then makes the active mount **mirror**, and a mirrored
mount requires its private upstream, so the mirror reads back. Omit `mirrorTarget` and the mount is
serve-only. Each boot logs one posture line per mount. Endpoint collisions can warn or refuse
startup, as listed below. The design rationale is in
[Configuration and authentication](https://github.com/AlexaDeWit/Ecluse/blob/main/docs/architecture/configuration.md#configuration).

Écluse also reads three ordinary AWS-SDK variables from the process environment. They are not
document keys, and each one has a deliberately narrow reach:

| Variable | Écluse reads it for | Never affects |
|---|---|---|
| `AWS_REGION` | Scoping SQS, and only under an `AWS_ENDPOINT_URL_SQS` override, because a real SQS URL carries its own region. The AWS SDK still reads it on its own to region every other client | CodeArtifact, whose region comes from the mirror-target host |
| `AWS_ENDPOINT_URL_SQS` | The SQS endpoint, and it forces the SQS reading of `queue.url` | S3 |
| `AWS_ENDPOINT_URL` | The S3 advisory client, including against an emulator or a VPC endpoint | SQS |

Both endpoint values get the same hygiene as every other URL: whitespace is trimmed, and a value
with userinfo, a query, a fragment, or a malformed port fails the boot. The error names the
variable but never the value, because the value can carry a credential.

## Endpoint collisions

This table describes the implemented checks. Registry comparisons use the configured repository
URLs. Host comparisons also match distinct repository paths on the same host. Any refusal wins
when more than one row applies.

| Compared endpoints | Scope | Comparison | Proxy and mirror | Dredger |
|---|---|---|---|---|
| Mirror target and public upstream | Any mount pair | Host | Refuse | Refuse |
| Publication target and public upstream | Any mount pair | Host | Refuse | Refuse |
| Mirror target and private upstream | Any mount pair | Registry | Warn | Refuse |
| Mirror target and publication target | Same mount | Registry | Warn | Refuse |
| Publication target and another mount's private, mirror, or publication target | Other mounts | Registry | Refuse | Refuse |
| Private and public upstream | Same mount | Registry | Refuse | Refuse |
| One registry declared under different backend tags | Any endpoints | Registry | Refuse | Refuse |

A publication target may equal its own mount's private upstream unless another refusal applies.
Distinct repositories sharing a CodeArtifact host are not otherwise collapsed by the registry
comparison. A mount's private and public upstreams must name distinct repositories, because
the private leg forwards caller credentials and admits versions without the public rules.
Boot and `check-config` refuse this collision, naming both configuration keys and the repository.
Configurations that previously logged the private/public warning now refuse to start.

## The configuration reference

The binary embeds the defaults below, and every key appears with its default and its meaning:

{{ config_reference() }}

## The configuration document

The document is a YAML file at `/etc/ecluse/config.yaml`. `ECLUSE_CONFIG` relocates it, and is the
one process-level setting with no document key. With `ECLUSE_CONFIG` set, a missing file is a boot
error, but an absent document at the default path is fine. The document carries only what you
change: the **rule policy** (see [Rule policy](@/docs/configuration.md#rule-policy)) and, for
multi-mount deployments, the **mount map**. A single-mount npm deployment on the default policy
needs no document at all. The schema is the
[embedded default](@/docs/configuration.md#the-configuration-reference) above, and an unknown key
anywhere in the document is a boot error.

Here is a worked document for a mirrored npm deployment. Reads resolve against a private
CodeArtifact endpoint, approved public packages mirror into a separate CodeArtifact store, and the
quarantine widens to fourteen days. Keeping the read endpoint and the mirror store distinct is the
[recommended topology](@/docs/deployment.md#the-recommended-topology).

```yaml
server:
  publicUrl: https://ecluse.example.internal
  helpMessage: Contact the ACME platform team for access

queue:
  url: https://sqs.us-east-1.amazonaws.com/123456789012/ecluse-mirror

advisories:
  url: s3://acme-ecluse-advisories

mounts:
  npm:
    privateUpstream:
      codeArtifact:
        url: https://acme-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/internal/
    publicUpstream:
      registry:
        url: https://registry.npmjs.org
    mirrorTarget:
      codeArtifact:
        url: https://acme-123456789012.d.codeartifact.us-east-1.amazonaws.com/npm/mirror/

rules:
  min-age:
    ageSeconds: 1209600
```

Delete the `mirrorTarget` block and the same mount is serve-only. It still merges the private
upstream with the gated public registry, but it never writes, so `queue` goes unread. Delete
`privateUpstream` as well and you are back to the pure public gate of the
[quick start](@/docs/quick-start.md), in document form. `enabled: true` is then the only key it
needs, because `publicUpstream` already has a default.

No token appears above, because the `codeArtifact` tag mints the mirror-target write credential
from its host. Every other secret is an environment variable.

## Store tags

Each of `publicUpstream`, `privateUpstream`, `mirrorTarget`, and `publicationTarget` is an object
with exactly one key, the **tag**, and under it the keys that tag admits for that endpoint. The tag
names the store backend, and the boot checks the URL against it. There is no bare-URL shorthand,
because one fact with two spellings is one fact too many.

| Tag | The store | Where it applies |
| --- | --- | --- |
| `registry` | Any host that speaks the ecosystem's protocol, such as Artifactory, Nexus, or a public registry | Every endpoint. The only tag `publicUpstream` admits |
| `codeArtifact` | An AWS CodeArtifact repository endpoint. Écluse mints its write token from the host | Every endpoint but `publicUpstream` |
| `verdaccio` | A Verdaccio development store, on a static token | Every endpoint but `publicUpstream` |

The keys each tag admits depend on the endpoint, because the endpoints hold different credentials.

| Endpoint | `registry` | `codeArtifact` | `verdaccio` |
| --- | --- | --- | --- |
| `publicUpstream` | `url` | not admitted | not admitted |
| `privateUpstream` | `url` | `url` | `url` |
| `mirrorTarget` | `url`, `token` | `url`, optional `tokenDuration` | `url`, `token`, optional `permitDeletion` |
| `publicationTarget` | `url`, optional `token` | `url`, optional `token` | `url`, optional `token` |

Three rules explain the table. A read forwards the caller's own credential, so no read target
carries one. The mirror write is Écluse's one standing credential, so `codeArtifact` mints it and
admits no `token`, while the two non-minting tags require one. The publication token is a fallback
forwarded only when the publishing client sends none, which every tag admits.

`permitDeletion: true` is your consent for `ecluse dredger` to delete from a Verdaccio store, and
it exists on no other tag. Without it the Dredger refuses that store, and every other role ignores
the key. Verdaccio has no vendor API, so the Dredger sweeps it with the ecosystem protocol's own
listing and unpublish requests rather than a control plane of its own.

Two rules govern how the layers combine. A layer fills keys under a tag, it never switches one: an
environment variable written under a tag your document did not use leaves the endpoint carrying two
tags, and the boot refuses it naming both. And two endpoints that name the same registry under
different tags are refused for every role, because one store has one backend.

## First-party namespaces

A mount's `firstParty` key names the namespaces your deployment owns. Set it when your own
packages live behind Écluse. The privilege then reaches every path that could confuse one of your
names with a public one.

| Path | What the privilege decides |
| --- | --- |
| Publish | Only a first-party name may be published through the relay. Every other name is a `403`. |
| Serve | A first-party name resolves from `privateUpstream` alone. Écluse never fetches it from `publicUpstream` and never merges a public document into it. A private miss is a `404`. |
| Mirror | Nothing first-party is mirrored, because nothing first-party is fetched from the public leg. The worker drops, and does not mirror, a job that was already on the queue when you declared the namespace. |

The shape follows the ecosystem, and an empty or malformed list is refused at boot.

| Ecosystem | An entry is | Example |
| --- | --- | --- |
| npm | A scope | `@acme,@beta` |
| PyPI | A distribution name, or a prefix written as a separator then `*` | `acme,acme-*` |

A PyPI entry reads through PEP 503 normalisation, so `Acme_Tools` and `acme-tools` are one name. A
prefix stops at the separator, so `acme-*` covers `acme-tools` and not `acmeco`, which is a name
you do not own. The star has to follow a separator, and `acme*` is refused, because a prefix that
ran past the separator would privilege names you do not own. Declare the bare `acme` too if you
publish a distribution under that exact name.

Setting `firstParty` on an npm mount narrows what a scoped install reaches. A name under one of
your scopes that the private upstream does not have answers `404`, and Écluse does not fall back to
the public registry for it. That refusal is the point: a public package published under a scope you
own is a dependency-confusion attack.

A private upstream that is unreachable answers `404` for a first-party name too, rather than the
`503` a merged name gets. The private upstream is that name's one authority, so an origin Écluse
cannot read leaves nothing that may answer for it.

This is a privilege over names, not authentication. It says which names are yours, never who may
use them, so the private upstream stays the authority on every caller.

## Secrets

Secrets never live in the config document: client and registry tokens are always env vars. A
`codeArtifact` mirror target needs none, because Écluse mints its short-lived write token from the
container's ambient AWS credentials. The two non-minting tags take the `token` key under the target,
so a Verdaccio mirror write reads `ECLUSE_MOUNTS__NPM__MIRROR_TARGET__VERDACCIO__TOKEN`. A
**mirrored** mount therefore holds one write credential, and a serve-only mount never writes, so it
holds none.

The secret-typed variables also accept the container-secret file pattern. Set the `_FILE` form
(`ECLUSE_SERVER__AUTH_TOKEN_FILE`, `ECLUSE_MOUNTS__NPM__MIRROR_TARGET__VERDACCIO__TOKEN_FILE`,
`ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__CODE_ARTIFACT__TOKEN_FILE`) to a file path, and the file's
contents, with trailing newlines stripped, become the value, so the token never enters the
environment. Setting both a variable and its `_FILE` form, or naming an unreadable file, is a
fail-loud boot error.

A registry URL never carries a token either. Écluse refuses an endpoint written with userinfo
(`https://user:token@host/`), a query string, or a fragment at boot, and the error names the key.
The same refusal covers `server.publicUrl`, `advisories.osvExportBaseUrl`, and `queue.url`, and it
is why the `config:` boot echo and `ecluse check-config` print each endpoint in full. What Écluse
does with a client's own token is under
[Edge authentication](@/docs/deployment.md#edge-authentication-and-client-credentials). The credential model is in
[Credential flow and authority](https://github.com/AlexaDeWit/Ecluse/blob/main/docs/architecture/registry-model.md#credential-flow-and-authority) and
[Outbound registry credentials](https://github.com/AlexaDeWit/Ecluse/blob/main/docs/architecture/configuration.md#outbound-registry-credentials).

## Validation

Écluse validates the configuration in full at startup and refuses to start on any problem. An
unknown rule type, a bad URL, or an unresolved policy reference all stop the boot, so a
misconfiguration is a loud, immediate failure rather than a quietly mis-enforced policy.
`ecluse check-config` runs the same validation without starting anything, once for every role, so a
refusal only one command earns prints as a warning naming that command instead of failing the
check. It decides everything the configuration alone decides and makes no cloud call. The
validation model is in [Validation: fail fast, reject the unknown](https://github.com/AlexaDeWit/Ecluse/blob/main/docs/architecture/configuration.md#validation-fail-fast-reject-the-unknown).

## Rule policy

The policy is a named map of rules over the deny-by-default gate described in
[The policy](@/docs/how-it-works.md#the-policy). It lives in the config document's `rules` object.
`ECLUSE_RULES` carries the same object as JSON, which suits a one-rule tweak, and the document
stays the reviewable home for a real policy.

Écluse ships eight built-in rule types, catalogued below. A shipped name patches the rule it names,
`enabled: false` suppresses it, and a new name with a `type` adds a rule. A rule reads only its own
type's knobs, and a knob written under a type that does not read it fails the load:

| Name | Type | On by default | What it decides | Key knobs |
|---|---|---|---|---|
| `min-age` | `AllowIfOlderThan` | Yes | Admits public versions older than the quarantine window, the core defence against race-to-publish typosquatting and dependency confusion. | `ageSeconds` (7 days by default) |
| `remediation-fast-track` | `AllowIfRemediatesCve` | Yes | Admits a release a synced advisory names as its exact fixed version ahead of the quarantine, provided no other advisory still affects it. Abstains until a first advisory database syncs (set `ECLUSE_ADVISORIES__URL` and run Pilot), so without one only the quarantine governs. | (none) |
| yours to add | `AllowScope` | No | Admits every version under an npm scope you already trust, past the quarantine and without reaching the advisory database. Sits above `min-age` and below every deny. | `scope` (the scope without its leading `@`) |
| yours to add | `AllowByIdentity` | No | Explicit rules-engine escape hatch for a package or `package@version`. A bare name matches all versions. Sits above both advisory denies and below `DenyInstallTimeExecution` and `DenyByIdentity` by default. | `identity` |
| yours to add | `DenyByIdentity` | No | Hard-denies a specific package or `package@version` (the `revoke` shape). | `identity` |
| yours to add | `DenyInstallTimeExecution` | No, because many legitimate packages ship install scripts | Denies install-time code execution. | (none) |
| yours to add | `DenyIfCve` | No | Blocks a version a synced advisory records as affected at or above the CVSS threshold. The npm malware feed carries no score and counts as above every threshold, so enabling it also blocks known-malicious packages. Sits just below `AllowByIdentity`, so an identity pin overrides it. | `minCvss` (0-10). `onUnavailable` (`deny` by default, or `skip`) decides what happens when the advisory database cannot answer. |
| yours to add | `DenyIfEpss` | No | Blocks a version a synced advisory records as affected when that advisory's EPSS score is at or above the threshold. EPSS is FIRST.org's estimate of the probability a vulnerability is exploited in the wild within 30 days, so this gates on likelihood where `DenyIfCve` gates on severity. An advisory with no EPSS score counts as above every threshold. Shares `DenyIfCve`'s precedence. | `minEpss` (0-1). `onUnavailable` as for `DenyIfCve`. |

Before you enable `DenyIfCve` or `DenyIfEpss`, read
[Onboarding the advisory denies](@/docs/configuration.md#onboarding-the-advisory-denies).

Precedence defaults per type, and an integer `precedence` overrides it. The policy below patches
`min-age`, suppresses the fast-track, and adds six more by name:

```yaml
rules:
  min-age:
    ageSeconds: 1209600
  remediation-fast-track:
    enabled: false
  deny-scripts:
    type: DenyInstallTimeExecution
  revoke-bad:
    type: DenyByIdentity
    identity: bad-package
  pin-fix:
    type: AllowByIdentity
    identity: left-pad@1.3.0
  trust-our-scope:
    type: AllowScope
    scope: acme
  deny-known-cves:
    type: DenyIfCve
    minCvss: 8
  deny-exploitable-cves:
    type: DenyIfEpss
    minEpss: 0.5
```

The precedence values, the patch/add/suppress merge model, and the strict validation are in
[Rule policy](https://github.com/AlexaDeWit/Ecluse/blob/main/docs/architecture/configuration.md#rule-policy) and
[Rules engine](https://github.com/AlexaDeWit/Ecluse/blob/main/docs/architecture/rules-engine.md#evaluation-model).

## Onboarding the advisory denies

`DenyIfCve` and `DenyIfEpss` can break a cold deployment, because a freshly stood-up mirror
still needs historical versions your existing builds depend on, and an advisory may since have
covered them. Enable them *after* you warm your private mirror:

1. Leave both out of your policy and run Écluse normally, so your CI and developers pull the
   versions you depend on. Each lands in the trusted store, which the rules never re-gate once the
   version is there.
2. Once your must-have builds have mirrored, add `DenyIfCve` with a `minCvss` you are
   comfortable with. A threshold of 8 blocks high and critical CVEs, and malware blocks regardless
   of the threshold.
3. If Écluse then denies a specific version you must keep, pin it with an `AllowByIdentity` rule,
   which outranks both. That covers a false positive or a risk you accept.

Add `DenyIfEpss` alongside `DenyIfCve`, not instead of it. EPSS estimates exploitation probability,
not severity or proof of exploitation. Missing scores currently count as above every threshold,
so sparse EPSS coverage can make this rule restrictive even when known scores are low.

Set `onUnavailable: skip` to let another allow decide when an advisory lookup is unavailable.
The default `deny` refuses instead. This also applies to mirror admission: a skipped check can
precede an admission that remains trusted after the lookup recovers. Removing the allow later
does not revoke that copy unless a named deny becomes decisive. See
[Revoking a mirrored version](@/docs/operations.md#revoking-a-mirrored-version-internal-yank).

Do not rely on a per-package warning for every skipped check. Some unavailable results do not
reach the fault logger. [Operational monitoring](@/docs/operations.md#alerting-on-error) describes
the current signals and their limits. Admission evidence and ERROR-level outage reporting are
tracked in [#1230](https://github.com/AlexaDeWit/Ecluse/issues/1230).

Maximum source-age enforcement is not implemented. The agreed change in
[#1221](https://github.com/AlexaDeWit/Ecluse/issues/1221) will refuse stale OSV evidence even with
`onUnavailable: skip`. Individual missing EPSS scores currently deny, as the table states.
[#1225](https://github.com/AlexaDeWit/Ecluse/issues/1225) will change those cases to abstention.
