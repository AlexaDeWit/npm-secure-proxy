+++
title = "Documentation"
description = "Deploy, configure, and operate Écluse, and read the threat model and the registry protocol it speaks."
sort_by = "weight"
template = "docs-section.html"
page_template = "docs-page.html"
+++

This section is the operator manual. It reads in the order below, and each page also
stands alone.

**New to Écluse?** [What Écluse is](@/docs/how-it-works.md) covers the model on one page:
the quarantine, the four registry roles, and the deny-by-default policy.

**Trying it out?** The [Quick start](@/docs/quick-start.md) puts a serve-only gate in front
of real installs, with no mirror and no cloud account.

**Taking it to production?** Read [Deploying Écluse](@/docs/deployment.md) for the topology
and the network fences, [Configuring Écluse](@/docs/configuration.md) for the layers,
secrets, and rule policy, and [Operating Écluse](@/docs/operations.md) for the probes, logs,
and sizing. [Running the Dredger](@/docs/dredger.md) covers the one role that deletes.

**Looking something up?** [Protocol support](@/docs/protocol-support.md) says exactly what
the server speaks, and the [Threat model](@/docs/threat-model.md) records what Écluse
defends against and what it assumes of your deployment.

If you are reading or extending the code instead, the [API reference](@/api/_index.md)
holds the Haddock for each library.

## Design documents on GitHub

The pages above say how to run Écluse. The design documents in the repository carry the
_why_, and each link below leaves the site for GitHub:

- [Architecture overview](https://github.com/AlexaDeWit/Ecluse/blob/main/docs/architecture.md)
- [Configuration and authentication](https://github.com/AlexaDeWit/Ecluse/blob/main/docs/architecture/configuration.md)
- [Security posture](https://github.com/AlexaDeWit/Ecluse/blob/main/docs/architecture/security.md)
- [Rules engine](https://github.com/AlexaDeWit/Ecluse/blob/main/docs/architecture/rules-engine.md)
- [Multi-ecosystem hosting and URL rewriting](https://github.com/AlexaDeWit/Ecluse/blob/main/docs/architecture/web-layer.md#web-layer)
- [Release and supply-chain operations](https://github.com/AlexaDeWit/Ecluse/blob/main/docs/architecture/release-supply-chain.md)
