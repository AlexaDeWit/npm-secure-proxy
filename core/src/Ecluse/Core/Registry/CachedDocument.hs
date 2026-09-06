-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The cached and served raw document as an __opaque carrier with a private constructor__.

The neutral pipeline and the metadata cache hold an upstream document without reading it: every
structural operation over it is an injected adapter capability, and the compiler enforces that
rather than discipline, because 'CachedDoc''s constructor is not exported. An ecosystem crosses
the boundary through an inject/project pair, 'npmCached' or 'pypiSimpleCached', and a document
projects only through the pair that injected it, so a foreign one reads as absent rather than
as an empty document. 'weighCachedDoc' sizes a held document without projecting it.
-}
module Ecluse.Core.Registry.CachedDocument (
    CachedDoc,
    weighCachedDoc,
    npmCached,
    FileVersionIndex,
    pypiSimpleCached,
) where

import Data.Aeson (Value, encode)
import Data.ByteString.Lazy qualified as BSL

{- | A raw document the cache holds and the pipeline threads. The derived 'Show' and 'Eq' are a
debug and test affordance, not a projection.
-}
data CachedDoc
    = CachedNpm Value
    | CachedPyPISimple Value FileVersionIndex
    deriving stock (Eq, Show)

{- | Which release each distribution file of a Simple index belongs to, computed once at fetch so
a replayed merge plan reaches a flat file array without re-parsing a file name.
-}
type FileVersionIndex = Map Text Text

{- | A held document's resident-size estimate: the byte length of its compact encoding, the
figure the metadata cache weighs an entry by.
-}
weighCachedDoc :: CachedDoc -> Int64
weighCachedDoc = \case
    CachedNpm v -> BSL.length (encode v)
    CachedPyPISimple v _ -> BSL.length (encode v)

-- | npm's boundary pair. A document another ecosystem injected projects as 'Nothing'.
npmCached :: (Value -> CachedDoc, CachedDoc -> Maybe Value)
npmCached = (CachedNpm, \case CachedNpm v -> Just v; _ -> Nothing)

{- | PyPI's boundary pair: the index 'Value' with the 'FileVersionIndex' its fetch computed. A
document another ecosystem injected projects as 'Nothing'.
-}
pypiSimpleCached :: ((Value, FileVersionIndex) -> CachedDoc, CachedDoc -> Maybe (Value, FileVersionIndex))
pypiSimpleCached = (uncurry CachedPyPISimple, \case CachedPyPISimple v files -> Just (v, files); _ -> Nothing)
