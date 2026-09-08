+++
title = "What Écluse is"
description = "How Écluse decides what a build may install: the quarantine on new public versions, the four registry roles, and the deny-by-default policy."
weight = 1
+++

Écluse is a proxy you put in front of public package registries to protect the builds that install
from them. Point your CI and developer tooling at Écluse instead of at a public registry. Écluse
fetches from that registry on their behalf and decides which versions a build may install. npm
supports reads, mirroring, and first-party publication. PyPI supports project-index and distribution
reads, but not mirroring or publication.

A new public version waits in a quarantine, seven days by default, before a build can install it.
Most malicious publishes are found and pulled within days, so the wait alone sidesteps them, with
no attempt to detect malice. With an advisory database synced, a version that an advisory names
as the exact fix for a vulnerability skips the wait, so the quarantine never delays a security
patch. Everything else is deny by default and opt-in by name.

If you run a private registry, Écluse reads it first and passes your own packages through
untouched. Any https registry that speaks the ecosystem's protocol serves in that role. Écluse can
also mirror each admitted public version into a registry you nominate, so a mirrored version
survives a public outage or yank. You declare each registry under a tag that names the store behind
it. A mirror target under the `codeArtifact` tag mints its own short-lived write token, and the
other tags take a static token you supply. Écluse hosts no packages itself.

Écluse ships as one container image with four roles:

- `ecluse proxy` serves clients and runs the mirror worker.
- `ecluse mirror` runs the mirror worker alone, when you want to scale it apart from the proxy.
- `ecluse pilot` compiles the advisory database the fast lane reads.
- `ecluse dredger` deletes mirrored versions your rules now deny. It is the only role that
  deletes, and [Running the Dredger](@/docs/dredger.md) covers it.

[Deploying Écluse](@/docs/deployment.md) covers all four.

## How it works

### The registry roles

Écluse sees registries by role, and each role is a URL on a mount. Each ecosystem gets its own
path prefix: `/npm/` or `/pypi/`.

| Role | What it does | Trust | Required? |
|------|--------------|-------|-----------|
| Public upstream | The registry Écluse gates | Subject to admission | Defaults to `registry.npmjs.org` for npm and `pypi.org` for PyPI |
| Private upstream | Serves your own packages first | Trusted | No. Without it, a pure public gate |
| Mirror target | Receives admitted npm versions and answers presence probes | Operator-controlled | No. Declaring it makes the npm mount a mirror |
| Publication target | Receives your `publish` requests | Trusted | Opt-in |

These are roles, not necessarily separate servers. The
[recommended topology](@/docs/deployment.md#the-recommended-topology) gives each one its own store
and explains what you lose when two share one.

### A request, step by step

For npm, a client requests a version listing and then a tarball. PyPI reads use project indexes
and distribution files instead, with no mirror or publication step.

{{ diagram(name="request-flow", alt="A client talks only to Écluse, which fetches the private upstream and the public registry in parallel and queues a background mirror job to the mirror target.") }}

1. **The listing.** Écluse fetches the private and the public registry in parallel. It trusts
   every private version that meets the trusted integrity floor, gates every public version
   through the policy, and serves the merged listing. A public version the policy did not admit is
   absent from it, so a resolver never picks it.
2. **The tarball.** A private hit streams through unfiltered, and a private miss is gated on its
   public metadata. When admitted, Écluse streams the tarball from the public registry while a
   mirror job copies it into the mirror target in the background. Mirroring is demand-driven, so
   only a version a client pulls gets mirrored.
3. **A publish.** Publishing stays off until you configure a publication target. With one, Écluse
   refuses any name outside the mount's first-party namespaces before it writes upstream.

Private versions do not re-enter public admission. Private metadata passes the trusted integrity
floor, but a conventional private npm artifact hit bypasses that metadata path.
Those reads rely on the client's integrity checks. Removing an allow does not revoke a mirrored
version unless a named deny becomes decisive. See
[Revoking a mirrored version](@/docs/operations.md#revoking-a-mirrored-version-internal-yank).

Listings omit files whose URLs lack a filename, name `.` or `..`, or have a backslash or control character in the filename.
The check also applies after one percent decode and refuses encoded separators or invalid UTF-8.
A release disappears when no file survives.

The current npm mirror writer omits dependency and executable fields from its published manifest.
[#1205](https://github.com/AlexaDeWit/Ecluse/issues/1205) tracks that defect. Until corrected,
do not assume a fresh install from the mirror reproduces the public package's dependency metadata.

### The policy

The policy is deny by default: a public version reaches a build only when a rule admits it. Rules
run in precedence order and the first decisive one wins. The revoke and the install-time deny sit
above every allow by default.

| Rule | Band | On by default? | What it decides |
|------|------|----------------|-----------------|
| `min-age` | Allow | On | Admits a public version older than seven days: the quarantine |
| `remediation-fast-track` | Allow | On | Admits a version a synced advisory names as the exact fix for a vulnerability, as long as no other advisory still affects it |
| `AllowScope` | Allow | Off | Allow-lists every package under a scope you name |
| `AllowByIdentity` | Allow | Off | Pins a package or a `package@version` by exact name |
| `DenyByIdentity` | Deny | Off | Revokes a package or version |
| `DenyInstallTimeExecution` | Deny | Off | Denies packages that run code at install time |
| `DenyIfCve` | Deny | Off | Denies versions with a known vulnerability above a severity you choose |
| `DenyIfEpss` | Deny | Off | Denies versions with a known vulnerability whose exploitation probability (EPSS) is at or above a threshold you choose |

`remediation-fast-track` abstains until a first advisory database syncs, so without one only the
quarantine governs. The off rules opt in by name, and
[Rule policy](@/docs/configuration.md#rule-policy) has their knobs.

Independent of the rules, Écluse serves a public **file** only if it carries a digest that meets
the public integrity floor, `sha256` by default. The check runs per file, so a release that ships
several, as a Python release ships an sdist beside its wheels, keeps the files that clear the
floor and loses the ones that do not. A release disappears only when no file of it survives. On a
custom or off-spec public upstream this has a gotcha: files without such a digest silently
disappear, and downloading one `403`s. To serve such a source, give it the private upstream role
and loosen the trusted floor below `sha256`. The mechanics are in
[Integrity floors](https://github.com/AlexaDeWit/Ecluse/blob/main/docs/architecture/security.md#integrity-floors).
