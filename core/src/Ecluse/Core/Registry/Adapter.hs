-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The ecosystem adapter registry: resolve an 'Ecosystem' to its registered capability
record. It answers which ecosystems this binary supports, independent of what an operator
configures, which keeps an unsupported ecosystem and an unconfigured one distinct: the first
resolves to 'Nothing' here, and the second is simply never activated. A __configured__
ecosystem that resolves to 'Nothing' is the composition root's loud missing-adapter boot
error, never a half-wired mount. Only that root consumes an adapter: it resolves one per
activation and carries the capability records onto each pipeline's dependency record whole.
-}
module Ecluse.Core.Registry.Adapter (
    -- * The capability record
    RegistryAdapter (..),
    AdapterServe (..),
    AdapterMetadata (..),
    AdapterArtifact (..),
    AdapterPublish (..),
    AdapterMaintenance (..),
    ProjectName,

    -- * Registration
    adapterFor,
) where

import Ecluse.Core.Ecosystem (Ecosystem (Npm, PyPI, RubyGems))
import Ecluse.Core.Registry.Adapter.Types
import Ecluse.Core.Registry.Npm.Adapter (npmAdapter)

{- | Resolve an ecosystem to its registered 'RegistryAdapter', or 'Nothing' when this build
carries none. Every arm is explicit, so an added 'Ecosystem' surfaces here as a compiler error.
-}
adapterFor :: Ecosystem -> Maybe RegistryAdapter
adapterFor = \case
    Npm -> Just npmAdapter
    PyPI -> Nothing
    RubyGems -> Nothing
