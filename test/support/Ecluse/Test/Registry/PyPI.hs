-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Shared PyPI fixtures: the PEP 691 file entry every Simple-index example is built from.

The module name follows this support library's @Ecluse.X -> Ecluse.Test.X@ convention. The
entry carries the keys the projection reads plus one this build does not model, so an example
that asserts what survives a decode and one that asserts what a served entry relays read the
same document. 'withFileKeys' adds or overrides a key where an example is about that key.
-}
module Ecluse.Test.Registry.PyPI (
    simpleFile,
    withFileKeys,
) where

import Data.Aeson (Value (Object), object, (.=))
import Data.Aeson.Key (Key)
import Data.Aeson.KeyMap qualified as KeyMap

import Ecluse.Test.Package (validSha256)

{- | A complete PEP 691 file entry under the given name, on the ecosystem's declared files host
and carrying a well-formed sha256.
-}
simpleFile :: Text -> Value
simpleFile filename =
    object
        [ "filename" .= filename
        , "url" .= ("https://files.pythonhosted.org/packages/a0/" <> filename)
        , "hashes" .= object ["sha256" .= validSha256]
        , "requires-python" .= (">=3.10" :: Text)
        , "upload-time" .= ("2026-05-14T19:25:26Z" :: Text)
        , "provenance" .= ("https://pypi.org/integrity/x/provenance" :: Text)
        ]

-- | A file entry with the given keys added or overridden, so an example names only its own axis.
withFileKeys :: [(Key, Value)] -> Value -> Value
withFileKeys overrides = \case
    Object base -> Object (foldr (uncurry KeyMap.insert) base overrides)
    other -> other
