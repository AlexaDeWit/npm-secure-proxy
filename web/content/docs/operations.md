+++
title = "Operating Écluse"
description = "What a running instance tells your orchestrator and your log collector, how it drains and exits, and how to size the pod underneath it."
weight = 5
+++

Deployment ends with a running instance, and this page is about living with one. Come here when
you wire probes into an orchestrator, point a collector at the logs, size a pod, or have to pull
a bad version back out of the mirror.

## Health probes

An orchestrator watches two endpoints on the proxy, and they answer for different things, so wire
both:

| Endpoint | What it reports | When it answers `503` |
|---|---|---|
| `GET /livez` | Process liveness: `200` while the process is healthy. On a process that runs no mirror worker that is the listener alone. | When the process is not healthy. Where a mirror worker runs, a stalled consume loop fails it. |
| `GET /readyz` | Config loaded and the listener serving. | In exactly two cases: the instance is draining, or it is still starting up. |

The `/livez` body is a JSON object with two keys, in no guaranteed order: `status`, the same
verdict the status code carries, and `lastPoll`, the mirror worker's last successful poll as an
ISO 8601 instant. A process that runs no mirror worker reports `lastPoll` as `null`. Alert on the
`503`, and read `lastPoll` when you want to see a loop slowing before it crosses the threshold.

Readiness is deliberately lenient about public-upstream reachability, so a transient blip does not
pull a healthy pod from rotation. The starting-up case is the one to plan for. With an advisory
store configured, that startup gate also waits for each ecosystem's first advisory sync, a
one-way flip that never flaps back. Give a cold pod room for that first database download: a
Kubernetes `startupProbe`, or a readiness `failureThreshold` sized for it. Pilot publishes an
artifact for every ecosystem the configuration mounts, and readiness waits for each one's first
sync.

The npm liveness probe `GET /npm/-/ping` answers locally with `200 {}`. `GET /npm/-/v1/search`
returns `501` by design, because search is a discovery convenience, not an install path.
`GET /npm/-/package/{package}/dist-tags` and the `PUT` and `DELETE` of
`/npm/-/package/{package}/dist-tags/{tag}` also return `501`, because Écluse implements no mutable
named pointer. A package's tags are in the metadata document Écluse serves, and the publication
target owns setting and removing them. The mirror and Pilot roles export the same
`/livez` and `/readyz` on `ECLUSE_SERVER__PORT`, and nothing else. With telemetry on, every role
also opens a metrics listener on a second port, which co-located roles must not share
([Telemetry](@/docs/operations.md#telemetry-opt-in)).

## Graceful shutdown and pod drain

On `SIGTERM`/`SIGINT` Écluse drains in-flight work rather than dropping it. `GET /readyz` flips
to `503`, which is the signal a load balancer or mesh watches to stop routing new traffic here,
while `GET /livez` stays `200`, so an orchestrator does not kill a still-draining instance early.
Every response then carries `Connection: close`, and a keep-alive pool reconnects to a ready
instance. In-flight requests and in-progress artifact streams finish before the process exits, so
a half-delivered tarball runs to completion.

`ECLUSE_SERVER__SHUTDOWN_DRAIN_TIMEOUT` bounds the drain at 30 seconds by default. **Set the
platform's termination grace period above it**, so the orchestrator does not `SIGKILL` mid-drain.
On Kubernetes that is `terminationGracePeriodSeconds`. A second `SIGINT` or `SIGTERM` hard-stops
the process wherever it runs: the drain handler fires once, and the runtime default takes the next
signal. `Ctrl+D` forces the same immediate halt, and that path is armed only when standard input is
a TTY.

## Exit codes

The exit status states how a run ended, so an orchestrator can branch without parsing logs:

| Code | Meaning |
|---|---|
| `0` | Graceful shutdown: the drain completed and the services returned. |
| `1` | A service exited abnormally. The last `ecluse: service exited:` line on standard error carries the detail. |
| `2` | The boot aborted: Écluse refused the configuration, refused a role this build cannot run, or could not build what the configuration names in the live environment, and reported every problem. A configuration refusal fails identically on a restart without changes. A report that names a transient AWS or network fault may clear on retry. |
| `3` | Something outside cancelled the run: a kill that bypassed the graceful path. |
| `130` | The local-development halt (Ctrl-D on an interactive terminal). |

## Logs

Écluse writes one JSON object per line by default (`ECLUSE_OBSERVABILITY__LOG_FORMAT=json`). Set
the format to `console` for local development instead. Each JSON line carries these fields:

| Field | Content | Note |
|---|---|---|
| `timestamp` | When the line was emitted. | RFC 3339 UTC. |
| `status` | `debug`, `info`, `warn`, or `error`. | `ECLUSE_OBSERVABILITY__LOG_LEVEL` sets the floor, `info` by default. |
| `message` | The message text. | |
| `service`, `env`, `version` | The resolved identity. | |
| `dd` | `trace_id` and `span_id`. | Present only while a span is in scope. |
| `data` | The emitting call's own fields. | |
| `katip` | The `katip` emitter fields. | These include the emitting process's hostname (`katip.host`), so a collector's own host attribution governs the line's `host`. |

Four of those names matter to Datadog specifically: `timestamp`, `status`, `message`, and
`service` are its reserved log attributes, and its JSON preprocessing reads them unmodified.
`env` and `version` are ordinary attributes any backend indexes.

Bearer tokens render as a redacted placeholder, and on every running path Écluse reduces a URL to
its host and port, so neither token material nor a signed query string reaches a log field. The
boot-time configuration echo is the exception: it prints each configured endpoint as you gave it.
That is safe, because the boot refuses a URL that carries a credential (see
[Secrets](@/docs/configuration.md#secrets)).

## Telemetry (opt-in)

Telemetry stays off until you ask for it. Set `ECLUSE_OBSERVABILITY__TELEMETRY=on`, then give the
instance its identity: `DD_*` (`DD_SERVICE`, `DD_ENV`, `DD_VERSION`, `DD_AGENT_HOST`) for
Datadog, or the standard `OTEL_*` variables for any other backend. `DD_*` wins where both are
set, and the resolved identity stamps both traces and every log line. With no `DD_VERSION` or
`service.version` set, exported traces and log lines carry the running binary's own build
version, so the version tag is never blank.

Écluse exports only to a node-local collector or Agent, at `http://localhost:4318` by default or
wherever `DD_AGENT_HOST`/`OTEL_EXPORTER_OTLP_ENDPOINT` points. That is why `DD_API_KEY` and
`DD_SITE` have no effect. Authenticate a remote collector out of band with
`OTEL_EXPORTER_OTLP_HEADERS`.

Metrics travel either way. They push over OTLP beside the traces by default. Set
`OTEL_METRICS_EXPORTER=prometheus` and Écluse serves them for a scraper to pull instead, in
Prometheus text exposition format, at `GET /metrics` on a listener of its own. It is never on the
proxy port your npm clients reach: that port answers `/metrics` with the same `404` it gives any
other unmounted path, whatever the transport. `OTEL_EXPORTER_PROMETHEUS_HOST` (default
`localhost`) and `OTEL_EXPORTER_PROMETHEUS_PORT` (default `9464`) address the listener. It reads
the instruments at the moment of the scrape, so `OTEL_METRIC_EXPORT_INTERVAL` does not apply to
it, and a scrape never enters the proxy's request path, so it adds nothing to the
`http.server.*` series. The listener runs only while telemetry is on, and a port it cannot bind
is an error in the log rather than a failed start.

**Give every co-located role its own port.** Each role starts its own listener, and they all read
the same variable, so two on one host race for 9464. The loser logs the bind failure and serves
nothing. A scraper pointed at that port then collects one role's series and sees no sign the
others are missing, which reads on a dashboard as quiet rather than broken. So set a distinct
`OTEL_EXPORTER_PROMETHEUS_PORT` per role and scrape each one. A one-shot `ecluse pilot compile`
run beside a live Pilot boots the same way, so it attempts the same bind and logs the same error
before doing its work. That one is harmless.

**Keep that port inside your network.** The exposition carries the whole OpenTelemetry resource,
so it names your host and its machine id, the process owner, executable path, working directory
and container id, and whatever cloud or Kubernetes identity the SDK detected, next to your own
rule names. The `localhost` default reaches nothing off the host. Widening it with
`OTEL_EXPORTER_PROMETHEUS_HOST` publishes that inventory to whoever can reach the port, so pair
the change with something that decides who can.

Traces push over OTLP either way, so the endpoint variables still matter on a scraped deployment.

The W3C baggage limits cap `OTEL_RESOURCE_ATTRIBUTES` at 8192 bytes in total, 4096 bytes per
attribute, and 180 attributes. Écluse admits its own identity first, then your attributes in key
order, and warns once at boot naming every key that did not fit.

## Memory plan and runtime sizing

Every byte-valued bound is a named tenant of the effective heap ceiling, not an independent
multiplier. Seven tenants share the ceiling: the runtime reserve, the fixed enqueue buffer, the
cache aggregate, the materialisation aggregate, the publish aggregate, the in-memory queue depth,
and the mirror-artifact envelope. Each one boot-logs as a `memory plan:` line. The per-response
wire cap is carved from the materialisation aggregate rather than being a tenant of its own. A pod
too small for the tenants' floors **degrades gracefully instead of refusing**: Écluse sheds the
mirror-artifact cap first, then the cache, each to zero if needed, then serves uncached. Each step
is a loud warning, and it always boots. Only an explicit override that breaks the plan refuses
(exit `2`).
The model is in
[Runtime sizing](https://github.com/AlexaDeWit/Ecluse/blob/main/docs/architecture/configuration.md#runtime-sizing-cores-and-heap-ceiling).

Cores and the heap ceiling resolve at boot from config, else the cgroup, else a capped fallback,
and the boot log records each decision with its provenance. The whole-cores guidance, what to set
on a pod with no CPU limit, and the per-pod memory arithmetic are in the
[appendix](@/docs/operations.md#appendix-runtime-sizing-arithmetic).

A cold install against an empty cache hits the proxy with dozens of heavy requests at once, which
causes latency spikes or `503` backpressure. So run one install after starting Écluse and before
production traffic. Once warm, request coalescing absorbs spikes.

## Revoking a mirrored version (internal yank)

The mirror store deliberately resists upstream yanks, so a benign yank does not break your
installs. The cost is that a version later found malicious stays too, because Écluse never
re-gates trusted content. Usually the problem resolves itself: once the public registry yanks the
bad version, re-mirroring cannot reproduce its bytes, and you purge the stale copy at leisure.
When your own scanning is ahead of the public yank, revoke in this order:

1. **Deny the identity** with a `DenyByIdentity` rule. The serve path stops admitting the
   version, and the worker stops re-mirroring it.
2. **Purge that version** from the mirror. `ecluse dredger` does this for you: the deny in step 1
   is what it sweeps on. See [Running the Dredger](@/docs/dredger.md).

The order matters. Purge alone is a treadmill, because the next install re-admits and re-mirrors
a version still live upstream.

## Poison mirror jobs

Some mirror jobs can never succeed: an artifact past `ECLUSE_LIMITS__MAX_ARTIFACT_BYTES`, a
payload that no longer decodes, or a publish target that refuses it every time. On SQS, **attach
a redrive policy with a dead-letter queue** to the mirror queue. The worker leaves such a message
undeleted, your policy moves it to the dead-letter queue, and there you can read it and work out
what happened. At boot, Écluse reads the queue's redrive configuration. A queue with no policy
draws a loud start-up `WARNING` that poison messages have no terminus, and when the probe itself
fails, that warning names the missing `sqs:GetQueueAttributes` permission. In both cases the
process boots.

Without a dead-letter queue, nothing captures such a message. SQS redelivers it, and the worker
re-fetches the artifact each time, until the retention window (up to 14 days) drops it unseen. So
Écluse retires the job itself after `ECLUSE_QUEUE__MAX_RECEIVE_COUNT` deliveries: it writes an
error log naming the job and the reason, and the `ecluse.mirror.jobs.processed` counter records
it at `result="discarded"`. **Alert on that series**, because every discard is a job nothing else
caught. That count is a floor. With a redrive policy attached whose own `maxReceiveCount` Écluse
can read, it runs one delivery above that count, so your dead-letter queue always captures first
and the discard path stays dormant. When the policy's count is unreadable the configured floor
stands alone. A poison job therefore always lands somewhere visible: the dead-letter queue when you
have one, the error log and the discard metric when you do not. Mirroring is demand-driven, so the
next client request
for that artifact re-enqueues the job, and it fails the same way until you fix the cause.

## Appendix: runtime-sizing arithmetic

**Give Écluse whole cores.** A fractional CPU limit, say 3.5, has no good option: claiming 4
capabilities overruns the CFS quota during stop-the-world GC and freezes the process mid-pause,
while flooring to 3 strands the fraction. So pair an integer limit with `requests = limits` (and
exclusive cores where offered) to remove throttling structurally, since Écluse floors the derived
count.

**A pod with no CPU limit is the case to configure.** A CPU **limit** is a cgroup quota Écluse
reads, and it does not shrink the processor count the runtime sees. A CPU **request** is not a
quota. It reaches the container only as a scheduler weight, and the same weight has meant
requests up to 3.4x apart across runc versions, so Écluse will not guess a core count from it.
With no limit set, Écluse falls back to the count the memory limit can feed, and with no memory
limit either it caps at `ECLUSE_RUNTIME__CORES_CEILING` (8). Neither number is your request, and
the boot log warns and says so. On a 32-core node a 2-CPU-request pod with no memory limit
therefore claims 8 capabilities, not 2. Tell it the number with the Downward API:

```yaml
env:
  - name: ECLUSE_RUNTIME__CORES
    valueFrom:
      resourceFieldRef:
        resource: requests.cpu
        divisor: "1"
```

Read `requests.cpu`, never `limits.cpu`: with no limit set, the kubelet substitutes the node's
allocatable CPU, which is the whole-node claim you are trying to avoid. `divisor: "1"` rounds up
to whole cores, so a `500m` request becomes 1.

**Bare metal and dev hosts** have no cgroup limits either, so they take the same ceiling of 8, or
the processor count when that is lower. Raise `ECLUSE_RUNTIME__CORES_CEILING`, or set
`ECLUSE_RUNTIME__CORES`, to use a bigger box fully.

**Size a proxy pod's memory from the RTS numbers.** The binary ships `-A64m -n4m`, a 64 MiB
per-core allocation area in 4 MiB chunks, which trades bounded extra memory for far fewer GCs
under load. Budget roughly `cores x 64 MiB` of nursery, plus the live heap, which the metadata
cache dominates, and add up to one live-heap of copying headroom during a major GC. That
arithmetic gives these worked shapes:

| Pod shape | Setting | Note |
|---|---|---|
| 2 CPU / 512 MiB | none | Runs as-is on the shipped defaults. |
| 2 CPU / 256 MiB | `GHCRTS="-A16m"` | The halved memory also needs the smaller allocation area. |
| 4 CPU / ~750 MiB | none | What four cores want on the default `-A64m`. |
| 4 CPU / 512 MiB | `-A32m` | The smaller per-core area fits four cores in less memory. |

Taller pods amortise the cache and coalescing better, so prefer 4-CPU-ish shapes. Tune the
allocation area with `GHCRTS` and read the effective value back from the boot log. Pilot runs a
different workload, so tune its allocation area separately.
