-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | A __selective__ decode of a PEP 691 Simple index: pull out __one release's files__ without
materialising the files of every other release.

A whole-index decode builds a 'Value' for every file entry. A project like @markupsafe@ ships
89 files for one release and hundreds across its history, so on the artifact gate's cold path
that decode dominates the cost. The gate consults a single release. This module walks the
index's own JSON token stream and materialises a 'Value' only for the files of that release,
__skipping every other file's tokens without allocating them__. The win is on the parse, not the
fetch.

The generic bounded token-walk engine this decode drives lives in "Ecluse.Core.Json.Selective".
This module adds PyPI's file selection on top.

== Deciding on a file's own name

An index carries no per-release grouping, so which release a file belongs to is spelled in its
own @filename@. The walk therefore probes each item for that one member and materialises the
whole item only when the name names the requested release. The probe reads a lazy token
structure, so a rejected file costs one string, not the object.

== Faithful to the whole-document decode

The skip is not a shortcut past validation. The walk consumes the __entire__ token stream, so
malformed JSON anywhere is 'SelectiveUndecodable' and a value nested past the budget anywhere is
'SelectiveTooDeeplyNested', exactly as a whole-document decode would refuse them. Every value it
does build goes through the same depth gate, so the entries it yields are the entries the
whole-document path would have yielded for that release.
-}
module Ecluse.Core.Registry.PyPI.SelectiveDecode (
    SelectedFiles (..),
    SelectiveError (..),
    selectFilesFromIndex,
) where

import Data.Aeson (Value (String))
import Data.Aeson.Decoding.ByteString (bsToTokens)
import Data.Aeson.Decoding.Tokens (TkRecord (..), Tokens (TkRecordOpen))
import Data.Aeson.Key qualified as Key

import Ecluse.Core.Json.Selective (
    SelectiveError (..),
    findInRecord,
    materialiseWithinBudget,
    selectFromArray,
    skipValue,
    trailingWhitespace,
    withArray,
    withRecord,
 )

{- | The raw 'Value' pieces a selective decode pulls out of a Simple index for one release. A
field is 'Nothing' when its key is absent, so the caller reproduces the whole-document outcome,
and an absent @name@ is the empty-name decode failure.
-}
data SelectedFiles = SelectedFiles
    { sfName :: Maybe Value
    -- ^ The top-level @name@ value, if the key was present (else 'Nothing').
    , sfFiles :: [Value]
    -- ^ The requested release's file entries, in index order.
    , sfFileCount :: Int
    -- ^ The number of entries in the @files@ array (@0@ when @files@ is absent).
    }
    deriving stock (Eq, Show)

{- | Selectively decode a Simple index's bytes for one release, skipping every other release's
file entries unallocated. @belongsTo@ says whether a file name names the requested release: the
caller supplies it, because reading a release out of a distribution name is PyPI's grammar and
not this walk's.

Each value is bounded at @maxDepth@ levels, the 'Ecluse.Core.Security.maxNestingDepth' budget,
so the bound matches a whole-document depth check. The body must be a well-formed JSON object
with nothing but whitespace after it. Anything else is 'SelectiveUndecodable'.
-}
selectFilesFromIndex :: Int -> (Text -> Bool) -> ByteString -> Either SelectiveError SelectedFiles
selectFilesFromIndex maxDepth belongsTo body
    -- The document object itself occupies one level, so a budget below 1 refuses it before the
    -- walk, matching a whole-document check, which requires a cap of at least 1 for the object.
    | maxDepth < 1 = Left SelectiveTooDeeplyNested
    | otherwise = case bsToTokens body of
        TkRecordOpen rec -> walkTop (maxDepth - 1) belongsTo rec
        -- The whole-document path renders a malformed body and a well-formed non-object alike
        -- as unobtainable metadata, so this walk does not distinguish them either.
        _ -> Left SelectiveUndecodable

-- The starting accumulator: nothing found, no files counted.
emptySelection :: SelectedFiles
emptySelection = SelectedFiles Nothing [] 0

{- The walk's threaded state. The flags mark a captured @name@ or @files@ so a later duplicate
never overwrites the first, as @aeson@ resolves it. The selection alone cannot carry that: a
captured key whose target was absent leaves nothing, and so does "not yet seen". -}
data WalkState = WalkState
    { wsSelection :: SelectedFiles
    , wsSeenName :: Bool
    , wsSeenFiles :: Bool
    }

initialWalk :: WalkState
initialWalk = WalkState emptySelection False False

{- Walk the top-level index record to its end, threading the walk state. Each top-level value
sits at @childBudget@, one level below the document object's own budget. -}
walkTop :: Int -> (Text -> Bool) -> TkRecord ByteString String -> Either SelectiveError SelectedFiles
walkTop childBudget belongsTo = fmap wsSelection . go initialWalk
  where
    go st = \case
        TkRecordEnd leftover
            | trailingWhitespace leftover -> Right st
            | otherwise -> Left SelectiveUndecodable
        TkRecordErr _ -> Left SelectiveUndecodable
        TkPair key valueToks -> case Key.toText key of
            "files" -> adoptFirst wsSeenFiles captureFiles st valueToks
            "name" -> adoptFirst wsSeenName captureName st valueToks
            _ -> skipValue childBudget valueToks >>= go st

    {- Adopt a captured top-level key at its first occurrence, or skip a later duplicate, since
    @aeson@ keeps the first. Either branch still walks the value to its end, depth-bounded and
    never materialised, so a malformed or over-deep sibling anywhere still breaches. -}
    adoptFirst captured capture st valueToks
        | captured st = skipValue childBudget valueToks >>= go st
        | otherwise = capture st valueToks >>= uncurry go

    -- Capture the first @files@ array: the requested release's entries and the raw entry count,
    -- then mark @files@ seen.
    captureFiles st valueToks =
        withArray childBudget valueToks $ \files -> do
            (picked, count, cont) <- selectFromArray (childBudget - 1) (const (belongsToRelease (childBudget - 1))) files
            pure (st{wsSelection = (wsSelection st){sfFiles = picked, sfFileCount = count}, wsSeenFiles = True}, cont)

    -- Capture the first top-level @name@ value, then mark @name@ seen.
    captureName st valueToks = do
        (nameValue, cont) <- materialiseWithinBudget childBudget valueToks
        pure (st{wsSelection = (wsSelection st){sfName = Just nameValue}, wsSeenName = True}, cont)

    {- Whether one file entry belongs to the requested release, read from its own @filename@
    alone. The entry's tokens are walked to find that one member, so a file of another release
    costs one materialised string rather than its whole object. An entry that is not a record,
    or that declares no readable name, belongs to no release and is skipped. -}
    belongsToRelease budget entryToks =
        case withRecord budget entryToks (findInRecord (budget - 1) "filename") of
            Left err -> Left err
            Right (found, _count, _cont) -> Right (maybe False (belongsTo . renderName) found)

-- A @filename@ value as text, or the empty name for a value that is not a string.
renderName :: Value -> Text
renderName = \case
    String name -> name
    _ -> ""
