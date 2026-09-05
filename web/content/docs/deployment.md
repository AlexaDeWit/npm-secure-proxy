+++
title = "Deploying Écluse"
description = "Which roles of the one container image to run, which stores to put behind them, and how to fence the edge and the network so builds cannot step around the gate."
weight = 3
+++

You reach this page when the quick start has proven the gate and you want a deployment your builds
can depend on. Most of the work is not in the container: it is in the stores behind it, the edge in
front of it, and the network around it.

## The image and its roles

Écluse ships as one reproducible container image, a multicall executable, so the container command
selects the role:

- **`ecluse proxy`** (default): the HTTP proxy on `ECLUSE_SERVER__PORT` (default `8080`) plus the
  mirror worker. It scales horizontally behind a load balancer.
- **`ecluse mirror`**: the mirror worker on its own, for a worker fleet you scale separately. See
  [Splitting the proxy from the mirror worker](#splitting-the-proxy-from-the-mirror-worker).
- **`ecluse pilot`**: the OSV advisory ingestion pipeline.
- **`ecluse dredger`**: deletes mirrored versions your rules now deny, and the only role that
  deletes. It refuses a configuration that would put the wrong store in its blast radius: a mount's
  `mirrorTarget` that is also any mount's `privateUpstream` or its own mount's `publicationTarget`,
  and one whose tag names a store this build carries no control plane for. The other roles start
  and warn on the collapsed pairs instead. See [Running the Dredger](@/docs/dredger.md).
- **`ecluse check-config`**: validates the shared configuration and prints the resolved posture
  without starting anything (exit `0` valid, `2` refused). It checks every role, so a refusal only
  one command earns (`ecluse proxy --no-worker` or `ecluse mirror` without a durable queue,
  `ecluse mirror` where no mount declares a `mirrorTarget`, `ecluse dredger` on a collapsed
  endpoint pair or on a `mirrorTarget` it has no maintenance backend for) prints here as a warning
  naming that command. Run it in CI or before a rollout.

All roles share one configuration. The proxy and the mirror worker scale. Run Pilot as a singleton,
because multiple instances race and duplicate API calls.

**Give the advisory stack a writable volume.** Once `advisories.url` is set, the proxy lands each
synced database under `advisories.dataDir` (default `/var/lib/ecluse/advisories`) and Pilot
compiles there. The image runs as uid `65532` and sets no working directory, so mount a volume at
that path on every role that reads or writes advisories, and let uid `65532` write it. In
Kubernetes an `emptyDir` is enough: the artifact re-syncs after a restart, and Écluse sweeps the
partial downloads an interrupted run left behind. On a mirror-pipeline role (`ecluse proxy`, `ecluse
proxy --no-worker`, `ecluse mirror`) the boot refuses without the mount, naming
`ECLUSE_ADVISORIES__DATA_DIR` and the error it hit. Pilot creates the directory when it first
compiles, so there a missing mount surfaces as a runtime fault instead.

### Splitting the proxy from the mirror worker

By default one `ecluse proxy` process does both jobs: it serves clients and drains the mirror
queue. The two loads are unrelated. Request rate follows your builds, while queue depth follows how
many novel versions those builds pull, so a burst of new packages can make a proxy fleet sized for
traffic look busy for the wrong reason.

Split them when you want to size each on its own signal:

1. Point `ECLUSE_QUEUE__URL` at a durable queue. This is required, not advisory: the in-memory
   queue holds its jobs inside one process, so a split deployment would strand every one of them.
   Écluse refuses both split roles at boot without it and tells you which key to set.
2. Run the proxy fleet as `ecluse proxy --no-worker`. It still admits versions and still enqueues a
   mirror job for each one. It just does not drain the queue.
3. Run a second fleet as `ecluse mirror`. It boots the same configuration and the same rules, so a
   worker's re-evaluation of a job reaches the same verdict the proxy did. It serves no registry
   paths, only its health probes on `ECLUSE_SERVER__PORT`.
4. Scale the worker fleet on queue depth (KEDA's SQS scaler, or an Auto Scaling policy on
   `ApproximateNumberOfMessagesVisible`) and the proxy fleet on request rate.

Both fleets need the mirror-write credential and the advisory store, because the worker
re-evaluates policy before it publishes. Neither `ecluse mirror` nor `ecluse proxy --no-worker`
changes what gets mirrored, only which process does the work.

Health-check a worker pod on `GET /livez`. It reports the consume loop's last successful poll
beside the verdict, so you can alert on staleness as well as on the `503`.

A Pilot pod does not need to idle between syncs. `ecluse pilot compile --out DIR` runs one OSV
compilation and exits: it fetches an ecosystem's advisory export, writes
`<ecosystem>-osv-schema<N>.db` (e.g. `npm-osv-schema3.db`) into `DIR`, and exits non-zero on
failure. `--out DIR` is required. The rest are optional:

- `--ecosystem` selects the export (default `npm`).
- `--source URL` overrides the configured `advisories.osvExportBaseUrl`.
- `--epss-source URL` overrides the configured `advisories.epssFeedUrl`.
- `--upload` also publishes the artifact to the advisory store, a full sync cycle in one
  invocation. Without a configured store it aborts at once.

A corrupt or truncated export aborts the compile without publishing, so a running proxy keeps its
last-good database. Run the one-shot as a Kubernetes `CronJob` with `concurrencyPolicy: Forbid`,
which keeps it a singleton, and schedule it less often than the proxy polls. Give the pod
`s3:PutObject` through IRSA or workload identity rather than mounted keys.

Pin the image by digest and verify its provenance and SBOM attestations before you run it. The
recipe is in [Verifying the image](https://github.com/AlexaDeWit/Ecluse/blob/main/README.md#verifying-the-image).

## The recommended topology

{{ diagram(name="topology", alt="Clients and CI call the Écluse proxy, which reads the private upstream union of the publication and mirror stores, fetches gated content from the public registry, and queues admitted versions for the mirror worker to write to the mirror target.", caption="Only gated public content enters the union: the mirror write is the single path public packages take into the trusted stores, and no edge runs from the public registry into them.") }}

This is the posture the [threat model](@/docs/threat-model.md) treats as canonical. Aim for it
unless you have a specific reason to diverge.

1. **Run three registries, not one.** Give the three roles distinct backends: the publication
   target is a first-party store, the mirror target is a public-derived store, and
   `ECLUSE_MOUNTS__NPM__PRIVATE_UPSTREAM__CODE_ARTIFACT__URL` is a pull-through read endpoint that
   unions both.
   Separating provenance keeps the mirror auditable. One rule is hard: the aggregating endpoint
   unions **trusted** stores only, never a direct public upstream, because raw ungated packages
   would otherwise reach clients as trusted and bypass the gate. See
   [registry-level composition](https://github.com/AlexaDeWit/Ecluse/blob/main/docs/architecture/registry-model.md#registry-level-composition-the-recommended-topology).
2. **Let callers use their own identity.** The default forwards each caller's credential to the
   private upstream and publication target, with nothing to set: access then matches your registry
   IAM exactly, and Écluse holds no standing read credential. See
   [Credential flow and authority](https://github.com/AlexaDeWit/Ecluse/blob/main/docs/architecture/registry-model.md#credential-flow-and-authority).
3. **Mint the mirror-write token from the container role.** Declare the mirror target under the
   `codeArtifact` tag (`ECLUSE_MOUNTS__NPM__MIRROR_TARGET__CODE_ARTIFACT__URL`), and the worker
   mints a short-lived token under the task or instance role instead of carrying a static secret.
   Scope that role **write-only** to the mirror store, and keep
   `ECLUSE_MOUNTS__NPM__MIRROR_TARGET__CODE_ARTIFACT__TOKEN_DURATION` short, because this is Écluse's only
   standing credential and it writes the trusted store. Scope the mirror queue the same way.
   Anyone who can write the queue can force a write to the trusted store, so grant only the serve
   role `SendMessage`, and only the worker
   `ReceiveMessage`/`DeleteMessage`/`ChangeMessageVisibility`. `ChangeMessageVisibility` is
   load-bearing, not optional: the worker uses it to hold a long publish and to back a
   **dead-lettered** poison message off so the message rides your redrive policy to the DLQ.
   Without the grant an over-cap artifact silently churns on the ordinary visibility cadence
   instead.
4. **Let the edge own access, and leave `ECLUSE_SERVER__AUTH_TOKEN` off.** Écluse is not your
   access boundary. Front it with a gateway, mesh, or IAP, and restrict reachability **both**
   north-south and east-west (pod-to-pod), because an ingress-only allow-list that leaves the pod
   reachable inside the cluster is a common vulnerability. See
   [Edge authentication](@/docs/deployment.md#edge-authentication-and-client-credentials).
5. **Fence egress, keep metadata reachable.** Default-deny outbound, then allow only your
   upstreams, the mirror target, the metadata endpoint, and the advisory store when
   `ECLUSE_ADVISORIES__URL` is set (the proxy needs `s3:GetObject` to sync it). Require IMDSv2
   with hop limit 1, and do not block the metadata endpoint, because Écluse needs it to mint
   credentials. See [Network egress](@/docs/deployment.md#network-egress).
6. **Make the proxy unbypassable.** Deny CI runners (and, where practical, workstations) outbound
   access to the public registries. See
   [Locking down CI egress](@/docs/deployment.md#locking-down-ci-egress).
7. **Verify what you run.** Pin the image by digest and verify its attestations
   ([Verifying the image](https://github.com/AlexaDeWit/Ecluse/blob/main/README.md#verifying-the-image)).

The reasoning behind each choice, and the residual risks it accepts, is in the
[threat model](@/docs/threat-model.md) and
[Security posture](https://github.com/AlexaDeWit/Ecluse/blob/main/docs/architecture/security.md#trust-assumptions--credential-posture).

## What a deviation costs

Écluse still runs if you diverge, but every deviation trades away a protection, and one of them is
**silent**: Écluse cannot detect it, so nothing warns you.

| Deviation | What you lose | Does anything warn you? |
|---|---|---|
| One store for two roles: a `mirrorTarget` equal to the private upstream, or a `publicationTarget` onto either | Provenance separation and clean post-incident scoping. The perimeter holds, but first-party and public-derived packages share one store | Yes, for four pairs. The proxy logs a boot warning when the mirror target resolves to the same registry as the private upstream, the public upstream, or the publication target, and when the private upstream resolves to the same registry as the public upstream. A publication target equal to the private upstream is the documented publish arrangement, so it raises nothing |
| A private upstream that itself draws from public, say a CodeArtifact repo with the stock `npm-store` upstream to npmjs | The rules, integrity floor, and freshness quarantine, all nullified. Raw ungated packages reach clients through the trusted read path, behind the gate instead of through it | **No. Écluse cannot detect this one.** |
| An open edge: `ECLUSE_SERVER__AUTH_TOKEN` unset | Écluse's own authentication layer. Access control leans entirely on your network boundary | Nothing fires, but the posture is your own explicit setting |
| A static publish credential without an edge token | Nothing at runtime, because it never boots | Yes. The boot fails closed |
| A static mirror-write secret | The short-lived token minted from the container role | Nothing fires. The secret is visible in the configuration you wrote |

The silent row has one remedy: aggregate **trusted stores only** into the private upstream. The
[threat model](@/docs/threat-model.md) records both store-level deviations.

## Edge authentication and client credentials

Edge authentication to the proxy ships in two modes:

1. **Open**: `ECLUSE_SERVER__AUTH_TOKEN` unset. The network layer (VPC, service mesh) owns access
   control, so this is appropriate only on a closed network.
2. **Static token**: `ECLUSE_SERVER__AUTH_TOKEN` set. Clients send it as
   `Authorization: Bearer <token>`. For an npm-protocol client that is the `_authToken` line, keyed
   by the mount's host and path:

   ```ini
   # .npmrc
   registry=https://ecluse.example.internal/npm/
   //ecluse.example.internal/npm/:_authToken=${NPM_EDGE_TOKEN}
   ```

Écluse holds no read credential of its own. Reads run **passthrough**: Écluse forwards the
caller's own credential to the private upstream, which stays the authority on what that caller may
see. With `ECLUSE_SERVER__AUTH_TOKEN` set, the value a client presents both satisfies the edge
gate and travels upstream. A deployment therefore cannot combine the static-token recipe above
with the passthrough recipes below. Before the anonymous public fetch Écluse strips the
credential, so a client token never leaves for a public registry, and it never caches the private
origin across callers, so one caller's read can never answer another's.

A `publish` forwards the publisher's own token the same way. Opt into a static `token` under the
publication target's tag (`ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__CODE_ARTIFACT__TOKEN`) and
Écluse publishes as itself instead. That opt-in
needs `ECLUSE_SERVER__AUTH_TOKEN` in place, or the boot refuses
(`PublishStaticCredentialNeedsEdge`), because the pairing would let any unauthenticated client
publish under it. `ECLUSE_MOUNTS__NPM__FIRST_PARTY` names the scopes you own, and only a
name under one of them may be published (see
[First-party namespaces](@/docs/configuration.md#first-party-namespaces)). The reasoning is in
[security posture](https://github.com/AlexaDeWit/Ecluse/blob/main/docs/architecture/security.md#a-static-publish-credential-is-fail-closed) and
[Publishing first-party packages](https://github.com/AlexaDeWit/Ecluse/blob/main/docs/architecture/registry-model.md#publishing-first-party-packages-the-publication-target).

### What a client configures

Écluse serves one endpoint per mount, and installs and publishes both go to it. The client's whole
obligation is to supply a credential the private registry accepts, keyed to the proxy's URL in
whatever per-registry auth configuration that client keeps. Écluse forwards it to the private
upstream, which authorises the caller, so what someone reaches through the proxy is what your
registry already grants them. A caller holding no credential still installs public packages through
the gate. The private set is what the credential unlocks.

Two rules hold whatever ecosystem the client speaks:

- **Key the credential to the proxy's URL.** A client resolves a credential from the URL it is
  about to call, so a URL-keyed entry stays with the proxy. An unkeyed global credential travels
  to whichever host the client reaches next.
- **Bind no name to another registry.** A client pointed at Écluse needs no per-scope or
  per-package registry override, because the one endpoint already covers every name. An override
  takes its names around the gate, and in some clients it decides where a publish goes as well
  ([Keeping publishes on the proxy](@/docs/deployment.md#keeping-publishes-on-the-proxy)).

For an npm-protocol client those two rules are a default registry line and a URL-keyed token line.
The recipes here assume the open edge that the
[recommended topology](@/docs/deployment.md#the-recommended-topology) sets:

```ini
# .npmrc
registry=https://ecluse.example.internal/npm/
//ecluse.example.internal/npm/:_authToken=${NPM_TOKEN}
```

### Where the client credential comes from

The credential belongs to the private registry, so issuing it is that registry's business rather
than Écluse's. A long-lived credential goes into the client's auth configuration once. Prefer a
short-lived one minted from an identity the caller already holds: a developer mints against their
own cloud identity, and a CI job mints against a role it assumes through its platform's OIDC
federation, so no static registry secret sits in the job's settings.

Both write the same URL-keyed line, and only the minting command differs by registry. AWS
CodeArtifact is one example of the pattern:

```bash
export NPM_TOKEN="$(aws codeartifact get-authorization-token \
  --domain acme --domain-owner 123456789012 --region us-east-1 \
  --query authorizationToken --output text)"
```

Google Artifact Registry and other backends slot into the same shape with their own command.
Whatever issues it, a minted credential expires, so put the refresh in a shell hook or a job step
rather than in a developer's memory.

**Mint the credential and write the auth line yourself.** A registry vendor's login helper rewrites
the client's default registry to point at that vendor, and some also write per-name bindings.
Either one routes traffic around the proxy, which is what the two rules above exist to prevent.

### Keeping publishes on the proxy

Écluse accepts a publish on the same mount endpoint it serves installs from and relays it to the
publication target under the publisher's own credential. Two failures can take a publish off that
path, and they are not alike.

A publish that reaches Écluse when the mount declares no publication target is refused with
`405 Method Not Allowed`. The failure is loud and immediate. Écluse relays a publish only to a
destination you declared, so a misconfigured client cannot mis-publish through the proxy.

A publish that never reaches Écluse is the quiet one. A client that resolves its publish
destination from some other part of its configuration sends it straight to that registry, and the
proxy sees nothing to refuse. Name-to-registry bindings are the usual cause, because in some
clients such a binding outranks the per-package publish setting as well as the install route. Keep
them off a client pointed at Écluse and let the one endpoint carry both directions.

## Network egress

Écluse fetches from the registries you point it at, and some URLs it follows (a version's
`dist.tarball`) come from upstream responses. Egress control therefore runs in two layers: Écluse
provides the first in the application, with an origin-aware trust model, and your platform provides
the second.

**Untrusted origins** are the public upstream and every `dist.tarball`. Three application controls
gate them:

- A host+port **allowlist**. An upstream URL with no explicit port authorises port 443 alone, so
  write a nonstandard port out (`https://repo.internal:8443`) to authorise exactly that
  `host:port`. A non-HTTPS upstream, or a port outside `1..65535`, fails closed at boot.
- **HTTPS-only fetching with TLS certificate validation.** Certificate validation is the guarantor
  against the resolve-to-internal and DNS-rebinding SSRF class, because no address a name steers to
  can present a CA-trusted certificate for the host.
- **Response-size limits** on the metadata bodies Écluse decodes and on the artifact bytes the
  mirror worker ingests before it publishes them. The client-facing tarball relay streams rather
  than buffers, so no byte ceiling applies to it.

A **literal internal-range block** adds defence in depth: loopback, link-local including the
`169.254.169.254` metadata endpoint, RFC1918, CGNAT, and IPv6 ULA. Écluse refuses a `dist.tarball`
whose host is an internal-address literal, and `ECLUSE_EGRESS__ADDITIONAL_BLOCKED_RANGES` extends
the block. The trusted private origin (`mounts.npm.privateUpstream`) is deliberately
**not** subject to it, because a private registry legitimately lives on your internal network.

**The artifact host gate.** Upstream chooses where an artifact lives, so Écluse fetches one only
from the same allowlisted host that served the listing, comparing host **and port** as a pair, or
from a host the ecosystem serves artifact bytes from by design. It upgrades a plaintext artifact URL
to https on its own host. A file the gate refuses, for its scheme or for its host, is **dropped from
the listing** rather than listed and refused at download, so the listing and the download gate agree
file by file. A release disappears when no file of it survives. No configuration widens that.

**Écluse identifies itself on every registry and mirror-target request.** The `User-Agent` is `ecluse/<version>`,
naming the running build. An upstream, a WAF, or a forward proxy that filters on the agent has to
allow it.

Provide the second layer at the platform, default-denying egress and allowing only your registries,
mirror target, and the metadata endpoint:

- **AWS**: security-group egress rules or network ACLs to the upstream and mirror CIDRs. Reach
  CodeArtifact and S3 over VPC endpoints. **Require IMDSv2 with hop limit 1**
  (`httpPutResponseHopLimit: 1`).
- **GCP**: VPC firewall egress rules and, where applicable, VPC Service Controls.
- **Kubernetes**: a default-deny `NetworkPolicy` with an explicit egress allowlist. Allow your
  private upstream's internal range.
- **Service mesh (Istio/Linkerd)**: sidecar outbound policy `REGISTRY_ONLY`, each upstream a
  `ServiceEntry`, constrained by a `Sidecar` egress listener and an egress `AuthorizationPolicy`.

Each role needs a different slice of that allowance, and only the proxy needs ingress at all:

| Role | Ingress | Egress allowlist | Credentials held |
|---|---|---|---|
| `ecluse proxy` | Client traffic, behind the edge you front it with | The upstreams, the mirror target, the metadata endpoint, and the advisory store when `ECLUSE_ADVISORIES__URL` is set | The mirror-write credential, plus the advisory-store read (`s3:GetObject`) when that store is set. Nothing more |
| `ecluse mirror` | None public (health probes only, for the orchestrator) | The public upstream, the mirror target, the mirror queue, the metadata endpoint, and the advisory store when `ECLUSE_ADVISORIES__URL` is set | The same as the proxy: the mirror-write credential and the advisory-store read |
| `ecluse pilot` | None public | The OSV export host in `ECLUSE_ADVISORIES__OSV_EXPORT_BASE_URL` (default `osv-vulnerabilities.storage.googleapis.com`), the EPSS feed host in `ECLUSE_ADVISORIES__EPSS_FEED_URL` (default `epss.empiricalsecurity.com`), the metadata endpoint, and your object store | `s3:PutObject` to upload the advisory database |
| `ecluse dredger` | None | The mirror target, the metadata endpoint, the advisory store when `ECLUSE_ADVISORIES__URL` is set, and the STS endpoint where the identity comes from there | The mirror-write credential, minted the same way the proxy mints it, because the Dredger reads and deletes through it, plus the delete permission on the mirror repository and the advisory-store read. [Running the Dredger](@/docs/dredger.md) has the action list |

**Do not block the metadata endpoint or internal ranges for the proxy itself.** Écluse reaches
metadata through the AWS SDK to mint its instance-role credentials, so denying it breaks those
credentials. IMDSv2 with hop limit 1 keeps the minting working while stopping a neighbour or
forwarded request from reaching metadata through extra hops. The trust assumptions behind the
credential split are in
[Security posture](https://github.com/AlexaDeWit/Ecluse/blob/main/docs/architecture/security.md#trust-assumptions--credential-posture).

Two Pilot details matter to the platform. It names the uploaded object
`<ecosystem>-osv-schema<N>.db` under whatever prefix `advisories.url` carries, a key stable per
ecosystem, so bucket policies and the proxy's ETag polling can target it. On an export-host
`5xx`/`408`/`429` it retries with capped, jittered backoff, so a transient outage cannot get your
NAT address rate-limited.

## Locking down CI egress

The controls above secure Écluse's own egress. This one secures your consumers'. If you control CI,
**deny runners outbound access to the public registries** (`registry.npmjs.org` and the equivalents
for other ecosystems), and let them reach only Écluse and your internal services. A misconfigured
job then fails instead of pulling an unvetted package, because a stray `--registry` flag, a
committed `.npmrc`, or a tool that ignores your settings cannot route around a network that only
reaches Écluse. That makes the policy _unbypassable_ rather than merely _default_
([MOTIVATION, The bar](https://github.com/AlexaDeWit/Ecluse/blob/main/MOTIVATION.md#the-bar-a-chokepoint-you-cant-step-around)). The same idea
extends to developer workstations, a softer control than CI.
