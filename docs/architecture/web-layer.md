# Web layer

> Part of the [Écluse architecture overview](../architecture.md).

How Écluse serves HTTP: routing, streaming, caching, admission, and response status. The front door
is a raw `wai` `Application` served by `warp`. It routes a request, streams artifacts in bounded
memory, and applies cross-cutting concerns as middleware.

Routing has two layers. Mount dispatch matches the leading path segment to a mount (see
[Multi-ecosystem mounts](#multi-ecosystem-mounts)) and strips its prefix. The remaining
ecosystem-native path then goes to that mount's router. Deny-by-default is structural. A path no
route claims is a `404`. A tarball name that parses for a different package is a path-confusion
attempt, and the route declines it rather than fabricate a coordinate from it.

## Multi-ecosystem mounts

One Écluse process serves one or more ecosystems from one listener. It mounts each registry under a
path prefix on a shared base URL:

```
https://registry.internal.example.com/npm    → npm mount
https://registry.internal.example.com/pypi   → PyPI mount
```

Each ecosystem gets one mount, and Écluse derives that mount's prefix from the ecosystem
(npm → `/npm`, PyPI → `/pypi`). Nobody configures a prefix, so no two prefixes can collide and
nobody can mistype one. No mount sits at `/`, so adding an ecosystem never changes an existing
consumer's URLs. Each mount also carries an optional per-ecosystem
[rule refinement](configuration.md#rule-policy) merged over the shared policy. A single-npm setup is
the degenerate case, under its own derived prefix.

A mount also carries its ecosystem's credential presentation: the form its clients put a
credential in (npm: `Authorization: Bearer`; PyPI: HTTP Basic under any username). Écluse uses the
same form when it forwards the credential upstream, rendering the recovered pair verbatim. The web
layer compares the secret half of what the mount recovered against the configured edge token in
constant time and refuses anything else.

URL rewriting is load-bearing. Registry responses embed absolute artifact locations: npm's
`dist.tarball`, and on public PyPI, file URLs on a separate host. Forwarded unchanged, those URLs let
a client resolve metadata through the proxy and then download the bytes straight from upstream, past
the gate. So a mount rewrites embedded artifact URLs under its own prefix
(`{mount-base}/{pkg}/-/{file}`) before it serves metadata.

Same-host artifacts have a second benefit. The npm client attaches credentials only to requests on
the registry host. A same-host artifact URL keeps that auth on a tarball fetch. A separate host
would drop the credentials. Rewriting emits absolute URLs, and header inference is unreliable behind
load balancers and TLS terminators. So a mount must know its own externally-visible base URL as
explicit configuration (`server.publicUrl` plus its derived prefix).

## Meta-routes: ping, health, and search

`/livez` and `/readyz` stay distinct for orchestration. Liveness means the process responds.
Readiness means the config is loaded and the listener is serving. Readiness is deliberately lenient
about public-upstream reachability. The proxy still serves private hits while public is down, so an
upstream blip must not pull a healthy pod from rotation. `/-/ping` answers locally, and
`/-/v1/search` returns `501`, a discovery convenience rather than an install path.
The three dist-tag routes, `GET /-/package/{package}/dist-tags` and the `PUT` and `DELETE` of
`/-/package/{package}/dist-tags/{tag}`, return `501` too: a dist-tag is a mutable named pointer,
and Écluse implements none. A `HEAD` reads like its `GET`, so it returns the same `501` with no
body, while a `POST` over those paths takes the deny-by-default `404`.

## OpenAPI spec

Écluse speaks package-registry protocols (npm today), not a bespoke HTTP API.
Clients (`npm`, `pnpm`, `yarn`) hardcode the protocol and never read an API description, so the
published OpenAPI spec is not a client-integration contract. It states which protocols this
server speaks, and what each ecosystem does and does not support. That stops being self-evident as mounts multiply.

### What the spec covers, and what it doesn't

Écluse documents its coverage of each protocol, not the protocol itself:

- **The spec models owned and synthesised responses in full**: the error/denial envelope, the
  meta routes (`/-/ping`, `/-/v1/search`), and the packument Écluse synthesises (see
  [Packument merge](registry-model.md#packument-merge-across-upstreams)). `/livez` and `/readyz`
  are middleware above the mounts, so they sit outside the spec.
- **It describes opaque pass-through instead of re-specifying it**: tarball and artifact responses
  stream verbatim (see [Streaming](#streaming-and-resource-lifetime)). Upstream controls their
  status, media type, and body, so the operation carries a wildcard binary `default` response rather
  than a false finite status set.
- **Unsupported routes are a documented boundary**: `GET /-/v1/search`,
  `GET /-/package/{package}/dist-tags`, and the `PUT` and `DELETE` of
  `/-/package/{package}/dist-tags/{tag}` return `501`, and each read also contributes its
  bodiless `HEAD` operation. The manifest states that, so a reader learns the limit there and
  not from an error response.

### The synthesised-packument schema = the trust boundary

The served packument is Écluse's merged and filtered view: private versions trusted, public gated
(see [Packument merge](registry-model.md#packument-merge-across-upstreams)). No single upstream
produces that document, which makes it the highest-scrutiny piece of the manifest. The manifest
therefore owns its schema and models it as *partial* and *open*. It describes only the fields Écluse
reads and transforms (`versions`, `dist-tags`, `time`, and each version's `dist`).
`additionalProperties: true` everywhere states that every unlisted field relays unchanged from the
contributing upstream (private wins a collision). The schema is a precise statement of what the gate
touches and what it leaves alone.

## Streaming and resource lifetime

The proxy pulls from upstream only as fast as the client drains: constant memory regardless of
artifact size, with backpressure for free.

The proxy streams an artifact through without hashing it. It relies on the client's own integrity
check against the packument's `dist.integrity`, which it preserves unaltered when it
[filters](rules-engine.md#applying-verdicts-to-a-packument) the document (npm always verifies it).
Serve-side verification waits until a weakly-verifying ecosystem (e.g. PyPI) or a non-verifying
client lands. The mirror worker does verify before it publishes to the sanitised home (see
[Mirror queue](cloud-backends.md#mirror-queue)).

A `HEAD` must never run the full-`GET` streaming pump. A bodiless `HEAD` that opened the upstream
connection and pumped a whole body for warp to discard is a DoS-amplification lever. Cheap `HEAD`s
would force arbitrary full-artifact upstream fetches. So dispatch handles `HEAD` explicitly, not the
`Autohead` middleware.

## Metadata cache

A short-TTL, size-bounded, in-memory cache holds the parsed packument metadata, keyed by package, so
concurrent resolutions of a popular package collapse to one upstream call. Each entry is the coherent
pair of the typed `PackageInfo` and the raw document it was decoded from. The cache holds that raw
document as an [opaque carrier](registry-model.md#decision-surface-vs-served-surface)
([`CachedDoc`](../../core/src/Ecluse/Core/Registry/CachedDocument.hs)) and sizes it without reading
it, so the cache stays ecosystem-agnostic.

The cache holds the metadata, not the verdict. The rules engine re-evaluates the rules on every
request, so time-sensitive rules (`AllowIfOlderThan`) stay correct. This is in-memory metadata only.
On-disk artifact caching is out of scope, and the mirror stays the durable store.

The cache holds the anonymous public (gated) origin only. It never holds the private origin: the
serve path fetches that origin per request and never hands it to the cache. No caller's private view
can leak to another inside the TTL, because Écluse forbids a shared private cache. The anonymous public origin crosses no trust boundary, so the cache
holds it freely.

The assembled-representation store beside it memoises the encoded merged document under a content
fingerprint of every input. That fingerprint includes the digest of the private document this
request's own authorised fetch returned. No request shares or skips the private fetch and its authorisation.

## Serve admission and upstream pools

The packument path and a tarball miss's public-metadata gate share one process-wide admission bound.
A request that waits out its budget for a slot is shed with `503` and `Retry-After`. Shedding
instantly would be self-amplifying, because the refusal work competes for the cores the admitted work
needs. Health probes, cheap local routes, and trusted private tarball hits bypass admission. The hit
already streams in constant memory, and holding a metadata slot for a slow download would let clients
starve packument traffic.

The public and private connection pools take independent settings. The private pool takes the larger
share, because a trusted tarball hit streams outside admission, which makes its demand the
steady-state inbound hit fan-out.

## Error model

Every served response renders one serve outcome. A small type (`ServeDecision` in
`Ecluse.Core.Server.Response`) maps each outcome to its status, rather than collapsing everything
into a generic 403 or 500 response. For a concrete artifact request the decision renders directly:

| Outcome | Status |
|---|---|
| Admit | `200` (streamed) |
| Policy denial (incl. deny-by-default) | `403` + denial body |
| Undecidable, transient | `503` + `Retry-After` |
| Undecidable, permanent | `500` |
| upstream miss | `404` (forwarded) |

The rule: return `503` only when the condition should resolve, such as a transient upstream or
advisory condition. Otherwise return `500`, because retrying a permanent inability to decide cannot
help.

A packument request has no single status. Écluse
[merges the document across upstreams](registry-model.md#packument-merge-across-upstreams) and
filters it by provenance (see [Applying verdicts](rules-engine.md#applying-verdicts-to-a-packument)).
The proxy chooses a status only when nothing survives the merge, and the most recoverable cause
wins:

- `503` if any rejection was transient, or a needed upstream was unavailable.
- Otherwise `502` if a responding upstream returned an invalid response: a packument whose
  self-reported name is for a different package (see
  [name validation](registry-model.md#the-route-name-is-the-served-names-validation-authority)).
- Otherwise `500` if none is retryable but an exclusion is a permanent inability.
- Otherwise `403`.

Never `404`: the versions existed and Écluse withheld them, and a genuinely absent package is a
separate upstream miss. (`packumentStatus` in `Ecluse.Core.Server.Response` is the counterpart of
`artifactStatus`.)

The serve-outcome model decides the status, not the body shape: an ecosystem's route contract
supplies the matching response constructor and codec. A request matching no mount is a neutral
`404 Not Found` in `text/plain`. [Rules engine → denial responses](rules-engine.md#denial-responses)
covers the denial-body shape and `ECLUSE_SERVER__HELP_MESSAGE` handling.
