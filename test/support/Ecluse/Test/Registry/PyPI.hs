-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Shared PyPI filenames and PEP 691 entries
for projection, routing, and performance checks.
-}
module Ecluse.Test.Registry.PyPI (
    simpleFile,
    withFileKeys,
    separatorHeavySdist,
) where

import Data.Aeson (Value (Object), object, (.=))
import Data.Aeson.Key (Key)
import Data.Aeson.KeyMap qualified as KeyMap
import Data.Text qualified as T

import Ecluse.Test.Package (validSha256)

-- | A PEP 691 entry on the declared files host with a SHA-256 digest.
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

-- | A malformed sdist with distinct suffixes for allocation and scaling measurements.
separatorHeavySdist :: Text -> Int -> Text -> Text
separatorHeavySdist project count suffix = project <> "-1" <> T.replicate count "_a" <> "_" <> suffix <> ".tar.gz"
