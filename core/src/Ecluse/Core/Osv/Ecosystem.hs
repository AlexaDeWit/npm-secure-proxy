-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | What one OSV compile pass needs to know about the ecosystem it compiles.

osv.dev and Écluse do not always agree on the spelling, so a pass that carried one name would
either fetch a directory that does not exist or write an artifact the proxy's sync refuses. The
pass also needs the version grammar that orders the advisory bounds it ingests. This module
holds all three, and "Ecluse.Core.Osv.Compile" takes it rather than a bare name.
-}
module Ecluse.Core.Osv.Ecosystem (
    OsvEcosystem (..),
    osvEcosystemFor,
    osvEcosystemNamed,
) where

import Ecluse.Core.Ecosystem (Ecosystem (Npm, PyPI, RubyGems), ecosystemName, parseEcosystem)

-- | The two spellings and the version grammar one compile pass needs.
data OsvEcosystem = OsvEcosystem
    { osvExportDirectory :: Text
    {- ^ osv.dev's own spelling: the directory its export archive sits under, and the value an
    advisory's affected package carries, which is what the row filter matches.
    -}
    , osvWireName :: Text
    {- ^ Écluse's spelling ('ecosystemName'): it names the published artifact and stamps the
    @meta@ row the proxy's sync checks.
    -}
    , osvEcosystemTag :: Maybe Ecosystem
    {- ^ The ecosystem whose version grammar orders this pass's advisory bounds. 'Nothing' for a
    name this build does not serve, and then the pass tallies nothing.
    -}
    }
    deriving stock (Eq, Show)

{- | An ecosystem's pair of spellings. npm agrees with osv.dev, PyPI and RubyGems do not.

>>> osvEcosystemFor PyPI
OsvEcosystem {osvExportDirectory = "PyPI", osvWireName = "pypi", osvEcosystemTag = Just PyPI}
-}
osvEcosystemFor :: Ecosystem -> OsvEcosystem
osvEcosystemFor eco =
    OsvEcosystem
        { osvExportDirectory = exportDirectory
        , osvWireName = ecosystemName eco
        , osvEcosystemTag = Just eco
        }
  where
    exportDirectory = case eco of
        Npm -> "npm"
        PyPI -> "PyPI"
        RubyGems -> "RubyGems"

{- | The pair for a name a one-shot compile was given: a name this build serves resolves through
'osvEcosystemFor', and any other spells itself on both halves.

>>> osvEcosystemNamed "pypi"
OsvEcosystem {osvExportDirectory = "PyPI", osvWireName = "pypi", osvEcosystemTag = Just PyPI}
-}
osvEcosystemNamed :: Text -> OsvEcosystem
osvEcosystemNamed name = maybe unserved osvEcosystemFor (parseEcosystem name)
  where
    unserved = OsvEcosystem{osvExportDirectory = name, osvWireName = name, osvEcosystemTag = Nothing}
