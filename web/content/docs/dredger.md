+++
title = "Running the Dredger"
description = "The role that deletes mirrored versions your rules now deny: what one cycle does, what bounds it, and the permissions it needs."
weight = 6
+++

`ecluse dredger` is the only role that deletes. It walks each mount's mirror store and removes
versions the mount's own rules now deny. Run it when your mirror must not keep serving a version a
new advisory condemns, and read this page before you point it at a store, because deletion is
permanent.

The Dredger takes no ingress. It exposes only `/livez` and `/readyz` on `ECLUSE_SERVER__PORT`.

## What one cycle does

A mirrored version's metadata never changes after it is published. So a version Écluse once
admitted can become a denied one for only three reasons: a new or changed advisory, an operator
identity deny, or a change to your rule configuration.

The **default cycle** covers the first two, and it is what runs unless you turn the full walk on.
Each cycle:

1. Reads the store's consent marker and its classification. Both are read again every cycle, so
   withdrawing either stops the next cycle without a restart.
2. Lists the store's package names, a page at a time.
3. Keeps only the names the synced advisory database covers, plus the names an identity-deny rule
   pins. Both sides are read through the ecosystem's own name parser, so a spelling difference
   between the advisory database and the store cannot miss a match.
4. Reads each of those packages' metadata **back from the store**, one read per package, and
   evaluates every version the store holds against the mount's whole rule set.
5. Deletes only what a named decisive deny condemns.

A cycle is therefore bounded by the listing for store size, and by advisory hits for metadata
reads. It finishes in minutes to an hour on a large store, a restart re-runs a cheap listing, and
every advisory reaches every affected mirrored version within one cycle of landing.

Set the pace with the `dredger` group in your configuration. `chunkSize` and `chunkPause` set how
many packages one chunk examines and how long it waits between chunks. `cyclePause` sets the wait
between cycles.

## What is deleted, and what never is

A version is deleted **only** on a named decisive deny. Everything else keeps it:

| The rules said | What happens |
|---|---|
| A named rule denies the version | Deleted |
| No rule was decisive (deny by default) | Kept |
| A rule could not be evaluated | Kept |
| The store's own metadata no longer carries the version | Kept |
| The store served no metadata for the package this cycle | Every version of that package is kept |

Deny by default is how the serve path refuses an unknown version, and it is the right answer
there. Here it keeps, because your mirror may hold the only surviving copy of a version the public
registry has already removed.

The first-party belt shields every version under a namespace your `firstParty` key names, and the
Dredger never even reads their metadata.

## Consent, and what the store is

The Dredger deletes from a store only when that store carries the operator's own consent marker,
and only when deleting from it destroys something. It reads both at the start of every cycle,
through the store backend's own handle.

A `codeArtifact` store carries consent as a repository tag. A `verdaccio` store carries it as
`permitDeletion: true` under the mirror target's tag. A `registry` store has no consent form and no
control plane, so the Dredger refuses it at boot and names the tag.

A store that refills itself from an upstream is not swept: deleting from a pull-through cache
changes nothing, and the cycle halts saying so. The halt line names the backend, so an operator
running two of them reads which store refused.

The Dredger also refuses to boot on a collapsed endpoint pair. It compares a mount's `mirrorTarget`
against every mount's `publicUpstream` and `privateUpstream`, and against its own mount's
`publicationTarget`. Two mounts sharing one multi-format repository as their mirror target is a
legitimate deployment and is not refused.

## The deletion cap

`deletionCap` bounds how many versions one cycle may hand over for deletion. It is the breaker
against an advisory database that denies far more than it should.

Reaching it **halts the Dredger for the life of the process**. No further cycle runs, the readiness
probe answers `503`, and an error line repeats at each cycle interval naming the advisory
generation and the count. The process stays up on purpose: exiting would bring a pod restart, and
the restart would begin sweeping the same poisoned generation again.

Investigate the generation that filled the cap. Then either restart the Dredger, or raise the cap
deliberately and restart it.

## The full walk

A rule-configuration change is the one cause a default cycle cannot see, because no advisory and no
identity deny points at the versions it newly denies. The full walk covers it. Turn it on with
`fullWalk: true`.

While it is on, the walk **replaces** the default cycle rather than running beside it, because a
walk over every name is a superset of a candidate cycle. Each completed walk starts a fresh one.
Turn it off once a walk has completed, and the Dredger drops back to candidate cycles with nothing
lost.

The walk covers the name space in prefix buckets, and records each completed bucket in the store
itself, so a restart re-does at most one bucket. **Enabling the full walk is also your decision to
let the Dredger write one thing to your store.** A `codeArtifact` store keeps the record in one
repository tag per ecosystem. A `verdaccio` store has nowhere to keep one, so a walk over it starts
from the beginning after every restart, and the Dredger says so at boot.

Advisory latency during a walk is bounded by the walk's own pace, so do not leave it on
indefinitely.

## Dry run

`ecluse dredger --dry-run` builds the Dredger with no real delete in it. The store handle it holds
carries the backend's own rehearsal where one exists, and a call-nothing stub where none does, so
the run cannot delete because nothing it holds can.

It reads consent and classification and reports them. The belt and the cap apply as logging only,
so a rehearsal reports the full count a real run would reach. It writes no walk marker. Its counter
is `would_delete`, never `deleted`.

Use it before the first real sweep of a store, and after any rule change you are unsure of.

## `--once`

`ecluse dredger --once` runs one cycle and exits. It exits `0` when the cycle completed and `1`
when it halted, with the reason on the same line, so a scheduler reads the outcome from the status.
It composes with `--dry-run`.

## What the Dredger tells you

Every deletion writes a line naming the package, the version, the rule that denied it, and the
advisory generation it was decided under. A deletion decided without a loaded advisory database
reads that generation as `none`.

Whatever stops a cycle repeats an error line at **each cycle interval** until it clears or an
operator restarts the Dredger. Nothing halts silently. That covers a withheld consent marker, a
store that refills itself, a store that stopped answering, and the latched deletion cap.

A store fault is retried once after the delay the fault itself advises, and a fault that survives
that retry halts the cycle. The next cycle re-attempts, so an outage reports once per cycle
interval for as long as it lasts and the sweep resumes on its own when the store answers.

A delete the backend refuses, or one that never reached it, leaves the version in the store. It
counts as kept and writes an error line carrying the backend's own code and message.

The `ecluse.dredger.versions` counter carries one label, `result`, one of `examined`, `deleted`,
`would_delete`, `kept`, or `guard_skipped`. Every version a cycle examines counts once as
`examined` and once more under what the cycle did with it. **Alert on a jump in `deleted`.**

## Permissions

Grant the Dredger the mirror repository and nothing else. It reads a store's metadata and deletes
from it through the same mirror-write credential the proxy mints, so a credential scoped to the
mirror target already scopes the Dredger.

On AWS CodeArtifact, scope the policy to the mirror repository:

- the token mint, `codeartifact:ListPackages`, `ListPackageVersions`, `DescribeRepository`, and
  `ListTagsForResource` for reading,
- `codeartifact:DeletePackageVersions` for the deletion itself.

A deployment that runs only the default cycle needs nothing more. **The full walk needs one extra
permission**, because it writes the resumption marker:

- `codeartifact:TagResource` and `codeartifact:UntagResource` on the mirror repository ARN,
  conditioned on the key family the Dredger writes:

```json
"Condition": {
  "Null": { "aws:TagKeys": "false" },
  "ForAllValues:StringLike": { "aws:TagKeys": "ecluse-dredger-cursor-*" }
}
```

`ForAllValues` is required. `aws:TagKeys` is multivalued, and `ForAnyValue` would admit a request
that also carried the consent tag key. `TagResource` adds and updates the keys it names and
replaces no others, so a marker write cannot disturb your consent tag. Granting neither action
leaves the consent tag outside the Dredger's reach entirely.

On a store reached through the ecosystem protocol alone, least privilege is an account of the
store's own: a user whose package rights cover the mirror store and nothing else.

## Known limits

**One Dredger per store.** There is no lease. Two Dredgers against one store double the cap's blast
radius and interleave their marker writes. On a `verdaccio` store the unpublish reads the package
document, writes it back edited, then deletes the tarball, so a concurrent publish of another
version of the same package can be lost from the document.

**A public version that entered the mirror before you declared its namespace is unreachable.** The
first-party belt shields every version under a declared namespace, so such a version stays and your
private upstream keeps serving it. When you declare a namespace, check the mirror for existing
versions under it and remove them by hand.

**A store that answers a metadata read with an error keeps the package for that cycle.** The read
does not distinguish a package the store no longer holds from a server-side failure, and both keep
every version of that package. A transient failure is re-read on the next cycle rather than retried
within the same one.

**An advisory database that is swapped part way through a bucket defers one cycle.** A package the
new generation newly covers is picked up by the next cycle. Every other difference between the two
generations keeps the version.

**A cycle needs no advisory database.** With an advisory rule active and no generation loaded, the
advisory half of the candidate set is empty, the identity half still sweeps, and the cycle writes
one error line saying the advisory half is unavailable.
