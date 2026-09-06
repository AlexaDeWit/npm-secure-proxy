+++
title = "Protocol support"
description = "Which registry protocols an Écluse server speaks, and what each endpoint answers, per ecosystem."
weight = 6
+++

The reference below is what an Écluse server speaks: every endpoint it answers, per
ecosystem, with the responses each one returns. Écluse renders the page from the OpenAPI
document it publishes as JSON, so the page and the document always agree.

## Supported registries

| Registry | Status |
| --- | --- |
| npm | Served, mirrored, and published |
| PyPI | Served |
| RubyGems | Planned |

A **served** registry answers reads: the metadata a client resolves against and the artifact
bytes it installs, both gated by the same rules, integrity floors, and egress controls.

A `pypi` mount serves reads and nothing else. It writes nothing, so a `publicationTarget` or a
`mirrorTarget` on it refuses the boot naming the ecosystem and the key, and its upload endpoint
answers `405`. Mirroring and first-party publishing for PyPI land in later releases.

A **planned** registry is already a valid `mounts` key, but no adapter answers its routes yet,
so activating one refuses the boot.

{{ openapi_reference() }}

The raw OpenAPI document is published at [/api/openapi.json](/api/openapi.json).
