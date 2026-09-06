-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The vocabulary of the ecosystem adapter registry: the capability record an ecosystem
registers ('RegistryAdapter') and the serve surface it carries. The three slices a consuming
pipeline's deps record embeds live in "Ecluse.Core.Registry.Adapter.Capability".

A 'RegistryAdapter' holds no URL, credential, limit, or policy: it is a static fact of the
build. It lives apart from the registration ("Ecluse.Core.Registry.Adapter"), the cycle-breaking
@.Types@ extraction STYLE.md sanctions, so an adapter module never imports that registry.
-}
module Ecluse.Core.Registry.Adapter.Types (
    -- * The capability record
    RegistryAdapter (..),

    -- * The serve surface
    AdapterServe (..),

    -- * The embedded slices
    AdapterMetadata (..),
    AdapterArtifact (..),
    AdapterPublish (..),
    AdapterMaintenance (..),
    ProjectName,
) where

import Ecluse.Core.Ecosystem (Ecosystem)
import Ecluse.Core.Registry.Adapter.Capability (
    AdapterArtifact (..),
    AdapterMaintenance (..),
    AdapterMetadata (..),
    AdapterPublish (..),
    ProjectName,
 )
import Ecluse.Core.Registry.Request (CredentialMapping)
import Ecluse.Core.Server.Context (MountRouter)
import Ecluse.Core.Server.RouteSpec (RouteSpec)

{- | One ecosystem's complete capability record, which the composition root wires every
consuming pipeline from. 'Ecluse.Core.Registry.Adapter.adapterFor' resolves it (npm's is
'Ecluse.Core.Registry.Npm.Adapter.npmAdapter').
-}
data RegistryAdapter = RegistryAdapter
    { adapterEcosystem :: Ecosystem
    {- ^ The ecosystem this record serves. The registry key must agree with it, so no record can
    register under a foreign ecosystem.
    -}
    , adapterServe :: AdapterServe
    -- ^ The web-facing serve surface: the route grammar and response contracts.
    , adapterMetadata :: AdapterMetadata
    -- ^ The metadata capability: the read-handle constructor and the packument assembly.
    , adapterArtifact :: AdapterArtifact
    -- ^ The artifact request formation, by filename and by authoritative URL.
    , adapterProjectName :: ProjectName
    {- ^ The ecosystem's own name parser. The publish guard, the sweep's candidate set, and
    anything else that turns a raw string into a 'PackageName' reads this one definition.
    -}
    , adapterPublish :: Maybe AdapterPublish
    {- ^ The publish capability. 'Nothing' for an ecosystem this build writes nothing for, whose
    publish route then answers the opt-in @405@ and whose declared write destination refuses the boot.
    -}
    , adapterMaintenance :: AdapterMaintenance
    {- ^ The store maintenance verbs, for a store whose only control plane is this protocol.
    Either verb may be absent, and a Dredger against such a store then refuses the mount.
    -}
    }

{- | The ecosystem's web-facing serve surface. The adapter derives both routing fields from one
declarative route table (npm's is "Ecluse.Core.Registry.Npm.Route"), so the routed surface and
the documented one cannot drift apart.
-}
data AdapterServe = AdapterServe
    { serveRouter :: MountRouter
    {- ^ The ecosystem's whole routing decision: which path a mount-relative request names and
    what serving it amounts to (an 'Ecluse.Core.Server.Context.RouteAction'). An unrecognised
    path yields the deny-by-default @404@.
    -}
    , serveRoutes :: NonEmpty RouteSpec
    {- ^ The same route table as data, one 'RouteSpec' per route 'serveRouter' serves. The
    OpenAPI spec ("Ecluse.Manifest") renders this instead of re-describing the grammar.
    -}
    , serveCredential :: CredentialMapping
    {- ^ The ecosystem's credential presentation: how the mount recovers a client's credential
    from its headers, and how Écluse carries one upstream. The neutral pipeline spells no scheme
    of its own and keeps the constant-time edge compare and the deny-by-default refusal.
    -}
    }
