-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The cached and served raw document as an __opaque carrier with a private constructor__.

The serve path caches an upstream packument's raw document and rebuilds the served body
from it. The neutral pipeline and the metadata cache must /hold/ that document without
/reading/ it. Every structural operation over it is an injected adapter capability: the
fetch that produces it, the assembly that merges it, the serialisation that encodes it.
The compiler enforces that opacity, so the neutral code does not have to keep it by
discipline: the constructor of 'CachedDoc' is __not exported__. A module outside this one
can cache, thread, and hand back a 'CachedDoc', but it cannot inspect what the document
carries.

An ecosystem works in its own representation and crosses this boundary through an
inject/project pair: 'npmCached' for npm, whose representation is a JSON 'Data.Aeson.Value',
and 'pypiSimpleCached' for PyPI's Simple index, whose representation is that value paired with
the file-to-version index its fetch computed. Each injects on the way into the cache and
pipeline, and projects on the way out, at its own capabilities. A document projects only
through the pair that injected it, so a foreign document reads as absent rather than as an
empty one. The cache weighs a held document through 'weighCachedDoc' without projecting it.
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

{- | A raw document the metadata cache holds and the neutral serve pipeline threads: an npm
packument, or a PyPI Simple index with the index its fetch computed. The constructors are
private, so only this module's boundary pairs cross them and the neutral core cannot read the
document. The derived 'Show' and 'Eq' are a debug and test affordance, not a projection.
-}
data CachedDoc
    = CachedNpm Value
    | CachedPyPISimple Value FileVersionIndex
    deriving stock (Eq, Show)

{- | Which release each distribution file of a Simple index belongs to, keyed by file name.

PyPI indexes files rather than releases, so an assembly that replays a merge plan needs this to
reach a flat file array from a version key. It is computed once at fetch, so no served request
re-parses a distribution file name.
-}
type FileVersionIndex = Map Text Text

{- | A held document's resident-size estimate: the byte length of its compact encoding, the
figure the metadata cache weighs an entry by.
-}
weighCachedDoc :: CachedDoc -> Int64
weighCachedDoc = \case
    CachedNpm v -> BSL.length (encode v)
    CachedPyPISimple v _ -> BSL.length (encode v)

{- | npm's boundary pair: inject a packument 'Value' into a 'CachedDoc' and project one back.
A document another ecosystem injected projects as 'Nothing', which its assembly drops rather
than reading as an empty document.
-}
npmCached :: (Value -> CachedDoc, CachedDoc -> Maybe Value)
npmCached = (CachedNpm, \case CachedNpm v -> Just v; _ -> Nothing)

{- | PyPI's boundary pair for the Simple index: inject the index 'Value' with the
'FileVersionIndex' its fetch computed, and project the pair back. A document another ecosystem
injected projects as 'Nothing'.
-}
pypiSimpleCached :: ((Value, FileVersionIndex) -> CachedDoc, CachedDoc -> Maybe (Value, FileVersionIndex))
pypiSimpleCached = (uncurry CachedPyPISimple, \case CachedPyPISimple v files -> Just (v, files); _ -> Nothing)
