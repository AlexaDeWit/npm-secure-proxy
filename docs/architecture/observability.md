# Observability

> Part of the [Écluse architecture overview](../architecture.md).

What Écluse emits, why each signal exists, and how an operator points it at a backend.

Écluse sits in the install path of someone else's build. An operator must see why it is slow, or
why it refuses a package, without attaching a debugger. The substrate is OpenTelemetry over OTLP, a
vendor-neutral wire protocol. One set of instrumentation feeds any compatible backend: a Collector,
Jaeger, Honeycomb, Grafana Tempo, or a Prometheus scrape. The vendor choice collapses to an
endpoint.

Telemetry is opt-in and off by default. With `ECLUSE_OBSERVABILITY__TELEMETRY` unset, Écluse wires
nothing, opens no spans, and sits the instruments on a no-op meter. An emit then becomes a discarded
measurement rather than a branch.

Datadog is a first-class, tested target and what the maintainer runs. It is never required and
never a lock-in: nothing in the core depends on it, and switching backends is a config change. The
Datadog-specific pieces are optional add-ons on the OTLP baseline: the `dd` trace-correlation object
on a log line, Agent-side sampling.

## What gets traced

The instrumentation maps onto the [request lifecycle](../architecture.md#request-lifecycle). Each
request opens a WAI server span, with a child span for each upstream fetch, private then public.
A child span carries W3C TraceContext to the next hop. Metrics ride the same OTLP pipeline.
Hand-added domain spans carry the decisions operators care about:

- **Rule evaluation**: the verdict, and on denial the `RuleName` and `RejectReason` (the
  [error model](web-layer.md#error-model)). The trace alone explains a 403.
- **Mirror enqueue to worker**: the serve-time enqueue and the worker's probe-to-publish run under
  linked spans. A worker poll mixing jobs from many requests links each back to its own triggering
  request. A job enqueued with tracing off bears no link.
- **Advisory sync**: one `ecluse.advisory.sync.attempt` span per
  [advisory-dataset sync](rules-engine.md#cve-subsystem) attempt, carrying the ecosystem and which of
  the five outcomes the attempt reached. The bucket, object key, ETag, and provenance stay off it.
  That same bounded result labels the attempt metrics below, so a trace and a series join on one
  value.

Sampling is head-based and always-on by default, so Écluse never drops a rare denial or error
trace. `OTEL_TRACES_SAMPLER` and `OTEL_TRACES_SAMPLER_ARG` set a parent-based ratio without a code
change. Against Datadog the node-local Agent resamples, so always-on is not wasteful.

## Metrics

Écluse emits only what it uniquely knows. Queue backlog and DLQ depth are cloud-native metrics
(CloudWatch, Cloud Monitoring), so Écluse does not re-emit them. Names follow OTel HTTP conventions
(`http.server.*`) plus an `ecluse.*` namespace for domain signals. The alarm-worthy signals:

- `ecluse.serve.perimeter.faults` (render/unclassified) and `ecluse.serve.relay.anomalies`
  (odd_shape/non_success) are steady-state zero. Any movement is an invariant break: a pre-commit
  handler escape answered with the neutral 500, or a public relay that was not the admitted
  artifact.
- `ecluse.registry.merge.divergence` is the cross-upstream integrity alarm. It increments per
  contradicting version, and the package and version go on the paired `WARNING` line, never on a
  label. See the [threat model](https://ecluse-proxy.com/docs/threat-model/).
- `ecluse.credential.token.ttl.seconds` alarms a stuck refresh. `ecluse.credential.refresh` carries
  (result, provider). `provider` is the store the mount declared its mirror target under, one of
  `registry`, `codeArtifact`, or `verdaccio`, spelled as the configuration spells the tag, so one
  word filters a dashboard and names the key an operator would edit.
- `ecluse.mirror.jobs.processed` carries (result), one of `published`, `failed`, or `discarded`.
  `discarded` is worth an alarm on its own. It means the worker retired a mirror job that the
  queue redelivered past its budget. That happens only when no dead-letter queue captured the job
  first (see [cloud backends](cloud-backends.md#the-terminus-for-a-job-that-can-never-succeed)).
  The job and the reason stay on the paired `ERROR` line, never a label.
- `ecluse.dredger.versions` (a counter) carries (result), one of `examined`, `deleted`,
  `would_delete`, `kept`, or `guard_skipped`. Every version a sweep cycle examines counts once as
  `examined` and once more under what the cycle did with it, so deletions read as a fraction of what
  was seen. A dry run counts under `would_delete` and never `deleted`, so a rehearsal cannot be
  mistaken for a deletion. A cycle whose `deleted` count jumps is worth an alarm: the deletion cap
  halts such a cycle for the life of the process, and the halt's `ERROR` line names the cap and the
  advisory generation. The package, the version, and the denying rule stay on the sweep's audit
  line, never a label.
- `ecluse.advisory.sync.attempts` (a counter) and `ecluse.advisory.sync.duration` (a histogram, in
  seconds) both carry (ecosystem, result), where result is one of `swapped`, `unchanged`,
  `none_published`, `fetch_failed`, or `refused`. A run of `fetch_failed` or `refused` means that
  ecosystem gates against an ageing advisory database or none at all. Its rules then deny by
  default. Check the bucket, the object key, and the IAM the sync task reads under. The artifact's
  own identifiers stay on the sync log line, never a label.
- `ecluse.advisory.database.age.seconds` (a gauge) carries (ecosystem). It reads the seconds since
  that ecosystem's serving advisory database was installed. Écluse measures it at each collection,
  from the slot that holds the database, so it climbs on its own whether or not a sync task is
  alive. One threshold therefore alarms on a stale database, on a sync that stopped swapping, and
  on a sync task that is crash-looping. Before the first swap it reads from the slot's creation,
  which is process start.
- `ecluse.advisory.compile.accepted` and `ecluse.advisory.compile.dropped` (both counters) carry
  (ecosystem), and the dropped counter adds (cause), one of `oversize` or `malformed`. Pilot records
  both once per compile pass, so a backend computes the drop rate from the pair. The dropped entry's
  own name and bytes stay on the compile log line, never a label.
- `ecluse.advisory.compile.runs` (a counter) carries (ecosystem, result), where result is
  `completed` or `aborted`. An `aborted` run means Pilot judged the feed's drop rate systemic. It
  abandoned the artifact rather than publish one that silently omits advisories. A run of them
  leaves every consumer on its last-good artifact, ageing.

The remaining serving, gate, upstream, cache, publish-budget, and mirror signals populate
dashboards. All of them leave by whichever metrics transport the deployment selected below.

### Cardinality and attributes

An inline proxy sees thousands of distinct packages, so the failure mode is a metric-series
explosion. Two guarantees keep it and the telemetry safe:

- **High-cardinality identifiers stay on spans and logs, never metric labels**. `package`,
  `version`, `scope`, and the full denial message go on the rule-eval span and the log line. Metric
  labels are bounded enums, so such an identifier cannot become a series. `rule` is the one
  operator-bounded label, a small fixed set per deployment.
- **Secrets and PII never appear in any signal**: no tokens, no `Authorization`. The proxy scrubs
  a forwarded client token from anything the WAI or http-client instrumentation captures. See
  [security](security.md).

## Logs

Logs are structured JSON lines through `katip`, stitched to traces by trace-ID injection. The
operator manual's [Logs section](https://ecluse-proxy.com/docs/operations/#logs) states the line shape, the
reserved Datadog attributes, the level floor, and the redaction.

### URL minimisation

An upstream supplies the artifact location. An operator supplies the advisory export URL. Either
can carry a credential in its userinfo or in a pre-signed query string, and both logs and spans
leave the node. The runtime diagnostics listed below reduce URLs to `host:port` through
`Ecluse.Core.Security.Authority`. A value with
no dialable authority renders as `<unresolved>`, never as a fragment of the input. The paths this
covers:

- **Serve.** The packument origin and upstream fields on the degrade warnings, the URL a
  url-formation fault carries, and the artifact URL a dropped-entry record holds.
- **Mirror enqueue and worker fetch.** The `ecluse.mirror.artifact_host` span attribute, the
  worker's tarball-host drop reason, and its artifact-fetch line. A failed fetch's reason names the
  authority and the bounded transport cause, not the client's rendered exception.
- **Advisory sync and export.** The `ecluse.osv.source_host` span attribute on the compile and
  stream spans, the stream's start line, and both source identities stored in artifact metadata.
  Sync logs only parsed compilation time and row count from metadata. It excludes arbitrary
  fields and source values, including complete URLs in older artifacts.

The span attribute names say what they hold: `ecluse.mirror.artifact_host` and
`ecluse.osv.source_host`.

The **boot-time configuration echo** prints a URL whole, by design. The resolved-key provenance
dump, the endpoint-collision warnings, and the mount posture lines print each configured upstream
and mirror URL as the operator gave it. The effective posture then reads straight from the start-up
log. Those lines need no reduction, because a configured registry URL has nothing to reduce. The
loader refuses one carrying userinfo, a query string, or a fragment, and the error names the key.
The credential then sits in a secret-typed key, which the dump redacts
(see [Secrets](https://ecluse-proxy.com/docs/configuration/#secrets)).

## Configuration and deployment

Telemetry is off until an operator sets `ECLUSE_OBSERVABILITY__TELEMETRY`. The operator manual's
[Telemetry section](https://ecluse-proxy.com/docs/operations/#telemetry-opt-in) owns the variables
and the wiring. Five design facts hold regardless:

- **Metrics push or pull, and the pull side gets its own port.** OTLP push is the default and
  shares the traces' pipeline, which suits the Datadog Agent and any Collector. A shop that
  scrapes sets `OTEL_METRICS_EXPORTER=prometheus` instead, and Écluse answers `GET /metrics` on a
  dedicated listener, addressed by `OTEL_EXPORTER_PROMETHEUS_HOST` (default `localhost`) and
  `OTEL_EXPORTER_PROMETHEUS_PORT` (default 9464). The SDK resolves that value to a no-op push
  exporter, so the endpoint is the whole transport. It is never mounted on the proxy's data port,
  because the exposition carries the entire OpenTelemetry resource: host, process, and cloud or
  cluster identity, none of which belongs on the port untrusted clients reach. The bounded labels
  above answer cardinality, not exposure, so the loopback default is what makes reaching the
  exposition off the host a deliberate act. A scrape never enters the request path, so it does not
  appear in the `http.server.*` series it reports. The listener belongs to the telemetry
  lifecycle, not to the front door, so every role opens its own and one scrape covers one role.
- **No agentless export.** Écluse never reads `DD_API_KEY` or `DD_SITE`. It exports to a node-local
  Collector or Agent, never to a vendor's cloud. The OTLP endpoint is an operator-declared
  destination, so it is deliberately not SSRF-classified.
- **Export never touches the request path.** The batch exporter runs asynchronously, and Écluse
  logs a failed export under a throttle.
- **Threaded RTS required.** The OTel SDK's batch span processor aborts under the non-threaded
  runtime, so telemetry needs the threaded runtime the image runs.
- **The resource-attribute header is bounded.** `service.name` travels on `OTEL_SERVICE_NAME`
  alone, because every SDK signal path reads the service name from that variable. The rest is
  admitted against the W3C baggage limits, resolved identity first, so an oversized operator
  configuration cannot cost a key a dashboard joins on. A key the limits exclude warns at boot by
  name, because the SDK's own encoder would otherwise shed it silently and in hash order.

A Dockerised, Datadog-free [integration tier](../testing.md) verifies telemetry against a real
Agent or Collector. It asserts that the spans and metrics arrive.
