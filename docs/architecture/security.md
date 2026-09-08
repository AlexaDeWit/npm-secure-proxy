# Security posture

> Part of the [Écluse architecture overview](../architecture.md).

Écluse builds outbound HTTP requests (private upstream, public upstream, mirror target) from
client-supplied package identifiers and upstream-supplied artifact locations. The operator
manual states what a deployment must fence around that
([Securing network egress](https://ecluse-proxy.com/docs/deployment/#network-egress)). This document
records the deployment assumptions the threat model rests on and the credential posture. It also
records the two floors that fail closed: the integrity digest and a static publish credential.

> The full STRIDE threat register lives in the OWASP Threat Dragon model
> ([`threat-modelling/ecluse.json`](../../threat-modelling/ecluse.json)), published readably
> at [Threat model](https://ecluse-proxy.com/docs/threat-model/). The threat statements and
> dispositions live there, not here.

<!--
  Do not re-grow this into a full threat enumeration. The authoritative register is
  the Threat Dragon model (threat-modelling/ecluse.json), rendered to the Pages site
  from web/content/docs/threat-model.md. Add or revise threats in the model, not here.
-->

## Trust assumptions & credential posture

This section records the deployment
assumptions the [threat model](https://ecluse-proxy.com/docs/threat-model/) rests on. It also
records the consequences of the canonical posture: per-caller passthrough credentials, the
three-registry topology, and CodeArtifact over VPC endpoints.

**Edge access is an operator concern.** `ECLUSE_SERVER__AUTH_TOKEN` is off by default, so the
deployment's access edge decides who may reach the proxy. That edge must hold east-west as well
as north-south. An ingress-only allow-list that leaves pod-to-pod traffic open is the usual gap.
Passthrough softens this: a caller with no forwarded token gets no private read or publish. An
edge breach then exposes only the public-gated view plus the untrusted-egress and DoS surface,
never private packages.

**Passthrough relocates credential risk to the proxy runtime.** Forwarding each caller's own
credential ([credential flow](registry-model.md#credential-flow-and-authority)) leaves Écluse holding no standing read or publish
credential. It does hold every in-transit caller's credential in memory, transiently. So
Écluse's own runtime and supply-chain integrity are a first-class control: the attested,
reproducible image ([release supply chain](release-supply-chain.md)). The token-stripping
boundary and the no-redirect-with-credential invariant are load-bearing, because real caller credentials cross them.

**The outbound controls guard the downloads an attacker can influence.** The host allowlist and
the internal-range block apply to the public packument and to every public `dist.tarball`.
That holds on the serve path and on the worker's back-fill fetch alike. They are absent from a trusted,
operator-declared destination (the private upstream, the mirror and publication targets, SQS,
S3, the OTLP collector), which goes where the configuration says. Https-only with certificate
validation applies to every registry endpoint regardless.

**The mirror-target write token is the one standing credential a mirrored deployment holds.** A
serve-only deployment holds none. The token is also the sharpest privilege, since it writes the
trusted store. Scope it to mirror publication and the repository reads needed for the presence
probe. Token-mint permission is separate from both. Prefer container-role minting over a static
secret and minimise its TTL. Dredger needs a different action set: reads and deletion, not
publication. The [operator permission table](https://ecluse-proxy.com/docs/dredger/#permissions)
owns those action and resource scopes.

The mirror queue is part of the same trust boundary. A job is unauthenticated and directs the
worker to fetch-and-publish, so anyone who can enqueue can make the worker write the trusted
store. Scope its IAM too: only the serve role enqueues, and only the worker consumes. The worker
narrows what a forged or stale job can do. It re-forms the artifact URL into its https-only
`RegistryUrl` witness at wire decode, and re-checks the fetch host against the tarball-host gate
at ingest. It re-decides the version through the shared admission gate. The fetched bytes must
match the digest of the artifact that gate re-admits before any publish.

**Registry separation is defence-in-depth and auditability, not the perimeter.** The
three-registry topology
([registry-level composition](registry-model.md#registry-level-composition-the-recommended-topology))
keeps first-party and public-derived inventory physically separable. That gives per-provenance
rule-sets, scanning, and clean post-disclosure scoping. Collapsing toward one registry degrades
auditability and mitigation depth but doesn't move the trust perimeter. The public-to-trusted
admission gate is identical at one registry or three. Storage-layer scanning is out of scope for
Écluse. It's ecosystem- and backend-specific, the operator's to configure.

## Integrity floors

**Public artifact admission and metadata listings require a strong digest by default.** Both
trust contexts default to SHA-256 or stronger. The public floor cannot be lowered, while the
trusted listing floor can. A conventional private npm artifact hit bypasses metadata admission
and therefore has no serve-time floor.

The check runs **per file**. A release ships several in most ecosystems, an sdist beside its
wheels on PyPI, so a release keeps the files that clear the floor and loses the ones that do
not, and disappears only when no file of it survives. The surviving set is what the merge plan
carries into the served listing, so the listing and the download gate refuse the same files. A
release whose file set is a singleton, npm's, either survives entire or drops entire.

- The public (untrusted) floor is a hard SHA-256 boundary (`ECLUSE_INTEGRITY__MIN_PUBLIC`,
  default `sha256`). An operator may raise it to `sha384`, `sha512`, or `blake2b` but never
  lower it. Config load rejects a sub-floor or
  unknown value, and never clamps it. The floor refuses a public version with no digest, or
  one below it, such as a legacy SHA-1 `dist.shasum` with no SRI. The artifact gate
  answers `403` and the metadata path filters the file from the listing, so a client
  never sees a file it couldn't verify. SHA-1 and MD5 have practical collisions, so a
  match can't prove the bytes weren't substituted.
- The trusted (private) floor carries the same `sha256` default
  (`ECLUSE_INTEGRITY__MIN_TRUSTED`), so Écluse drops a SHA-1-only or hashless private version
  exactly as a public one. But an operator can loosen it below SHA-256, down to
  `sha1`/`md5`, for a legacy private mirror. There, trust in the operator's own vetted source
  substitutes for cryptographic strength. That's the only way Écluse serves a sub-SHA-256
  digest, and only on the trusted private origin. On the serve path the trusted floor filters
  the private listing. The private tarball leg is a
  [conventional stable read](registry-model.md#serving-a-tarball) with no serve-time floor,
  so Écluse still serves a below-floor private artifact. The client and the mirror worker
  verify its bytes.

The asymmetry is the point: trust may substitute for cryptographic strength on the operator's
own vetted source, never on untrusted public bytes. The types enforce it. No code can
construct `MinIntegrity` (public) below SHA-256, while `MinTrustedIntegrity` (trusted) can go
lower, so no config or constructor path lowers the public floor. The floor admits by
algorithm strength, and the digest is computable for every algorithm it admits. The worker's
tamper gate verifies that digest, so an admitted public artifact is always verifiable and
reaches the mirror.

## A static publish credential is fail-closed

The [first-party publish path](registry-model.md#publishing-first-party-packages-the-publication-target)
relays a client `npm publish` to the publication target. The mount's first-party namespaces
(`ECLUSE_MOUNTS__NPM__FIRST_PARTY`) constrain which package names a client may publish. It
is not authentication and does not verify who is publishing. A deployment may set
a `token` under the publication target's tag, substituting Écluse's own credential for the
authenticated edge token on publishes. If it does, the composition root refuses to boot without a
verifiable inbound edge (`PublishStaticCredentialNeedsEdge`). That makes "static publish
credential plus open edge" unrepresentable. Such a pairing would let any unauthenticated client
publish under the operator's credential within the allowed scopes. `ECLUSE_SERVER__AUTH_TOKEN`
is the verifiable edge Écluse checks today. An external layer (API gateway, mTLS service mesh,
`NetworkPolicy`) is defence-in-depth but can't substitute for it, since Écluse can only verify
its own edge. Pure passthrough (no static token) carries no such floor: the publisher's
forwarded token is the authority.

### The guard-name ≡ write-name ≡ body-name invariant

The npm publish document carries its own declared identity: a top-level `_id` and `name`, and a
`name` per `versions` entry. A publication target that resolves the written package from the
body, the npm-protocol norm, would write a name the scope guard never saw. So an anti-shadowing
guard that validated only the URL-path name while relaying the document byte-for-byte would be
bypassable. A crafted `PUT /@acme/anything` whose body declares `@victim/target` would publish
outside the mount's first-party namespaces, shadowing a public package.

So the guard holds guard-name ≡ write-name ≡ body-name. After the scope check admits the
URL-path name, the guard compares every present declared body name to it: `_id`, top-level
`name`, and each `versions[].name`. Any disagreement is a `403` before any upstream write. The
comparison is `PackageName` equality under the same canonicalisation the route applies
(ecosystem-aware, npm case-sensitive), so an encoding variant (`@acme%2ffoo` vs `@acme/foo`)
can't disagree silently. The guard parses only the names and never decodes the base64
`_attachments`. An absent declared name is not a bypass-grant. The guard refuses only a
present, mismatching name, since a legitimate client always sends names matching its publish
URL. This makes the control sound whether the downstream target keys the write off the body or
the URL.
