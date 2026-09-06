-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | A memory-bounded __selective decode__ over a JSON document's token stream. This is the
reusable engine. It materialises only the values a caller picks out, skips every other value's
tokens unallocated, and depth-bounds every value it walks.

A whole-document decode (@aeson@'s @eitherDecodeStrict@) builds a 'Value' for /every/ member of a
large object. When a caller needs only a few members out of a multi-megabyte document, that decode
dominates the cost. This engine walks a document's JSON token stream: @aeson@'s
@Data.Aeson.Decoding@, no new dependency. It materialises a 'Value' only for the picked members
and skips the rest without allocating them. The win is on the /parse/, not the fetch. The engine
still reads the full bytes, but it parses them selectively, for @O(picked)@ work and residency
rather than @O(N)@.

== Faithful to the whole-document decode

Bounded selective decode is a memory-bounding defence on a size-unbounded, attacker-influenced
document. The walk is therefore faithful to the whole-document decode rather than a shortcut past
it.

  * It consumes the __entire__ token stream, so malformed JSON __anywhere__ surfaces as
    'SelectiveUndecodable', matching @eitherDecodeStrict@ failing the whole body.
  * It depth-bounds every value at the caller's budget, so a value nested past it __anywhere__ is
    a 'SelectiveTooDeeplyNested' breach. 'Ecluse.Core.Security.withinNestingBudget' is the same
    bound applied to a built 'Value'.
  * Within one object a key's __first__ occurrence wins. It walks a later duplicate for the
    malformed and over-deep checks but never re-materialises it, matching @aeson@'s duplicate-key
    resolution.

The engine names @aeson@'s token types and a depth budget only, with no registry or package
concept. Each JSON ecosystem layers its own selection walk on top: 'findInRecord' for a keyed
document, 'collectFromArray' for a file-list one. The npm packument selector is
"Ecluse.Core.Registry.Npm.SelectiveDecode".
-}
module Ecluse.Core.Json.Selective (
    -- * Refusal vocabulary
    SelectiveError (..),

    -- * Bounded selection
    findInRecord,
    collectFromArray,
    selectFromArray,
    materialiseWithinBudget,

    -- * Container guards
    withRecord,
    withArray,

    -- * Bounded skips
    skipValue,
    skipArray,
    skipRecord,

    -- * End of input
    trailingWhitespace,
) where

import Data.Aeson (Value)
import Data.Aeson.Decoding (toEitherValue)
import Data.Aeson.Decoding.Tokens (TkArray (..), TkRecord (..), Tokens (..))
import Data.Aeson.Key qualified as Key
import Data.ByteString qualified as BS

import Ecluse.Core.Security (withinNestingBudget)

{- | Why a selective decode could not yield a value. These are the two refusal causes a
whole-document decode would also raise, so a caller maps them onto its own error vocabulary.
-}
data SelectiveError
    = {- | The token stream was not well-formed JSON: malformed bytes anywhere, or trailing
      non-whitespace after the top-level value.
      -}
      SelectiveUndecodable
    | -- | Some value nested deeper than the depth budget allowed.
      SelectiveTooDeeplyNested
    deriving stock (Eq, Show)

{- | Find one key in a record. The first occurrence wins, matching @aeson@'s own object
decode, and only that value is materialised. Returns it, the raw count of entries scanned,
and the record's continuation. @childBudget@ is the depth budget the record's values sit at.
The scan runs to the record's end, so a malformed or over-deep sibling still refuses the decode.
-}
findInRecord :: Int -> Text -> TkRecord k String -> Either SelectiveError (Maybe Value, Int, k)
findInRecord childBudget target = go Nothing 0
  where
    go found !count = \case
        TkRecordEnd cont -> Right (found, count, cont)
        TkRecordErr _ -> Left SelectiveUndecodable
        TkPair key valueToks
            | Key.toText key == target
            , Nothing <- found -> do
                (value, cont) <- materialiseWithinBudget childBudget valueToks
                go (Just value) (count + 1) cont
            | otherwise -> skipValue childBudget valueToks >>= go found (count + 1)

{- | Collect the picked items out of an array, deciding by position so a rejected item's tokens
are skipped unallocated. The scan runs to the end, so a malformed unpicked item still refuses.
-}
collectFromArray :: Int -> (Int -> Bool) -> TkArray k String -> Either SelectiveError ([Value], Int, k)
collectFromArray budget pick = selectFromArray budget (\position _ -> Right (pick position))

{- | Collect the items a probe accepts, deciding from an item's own lazy tokens so reading one
discriminating member costs no materialised value. The scan still runs to the array's end.
-}
selectFromArray ::
    Int ->
    -- | The probe: an item's position and its own tokens, which continue into the rest of the array.
    (Int -> Tokens (TkArray k String) String -> Either SelectiveError Bool) ->
    TkArray k String ->
    Either SelectiveError ([Value], Int, k)
selectFromArray budget probe = go [] 0
  where
    go picked !count = \case
        TkArrayEnd cont -> Right (reverse picked, count, cont)
        TkArrayErr _ -> Left SelectiveUndecodable
        TkItem valueToks -> do
            wanted <- probe count valueToks
            if wanted
                then do
                    (value, cont) <- materialiseWithinBudget budget valueToks
                    go (value : picked) (count + 1) cont
                else skipValue budget valueToks >>= go picked (count + 1)

{- | Materialise one value from its tokens, bounded at @budget@. It is the same 'Value'
decode a whole-document path uses. Route every 'Value' a selective walk builds through
here, so each passes the same depth gate.
-}
materialiseWithinBudget :: Int -> Tokens k String -> Either SelectiveError (Value, k)
materialiseWithinBudget budget toks = case toEitherValue toks of
    Left _ -> Left SelectiveUndecodable
    Right (value, cont)
        | withinNestingBudget budget value -> Right (value, cont)
        | otherwise -> Left SelectiveTooDeeplyNested

{- | Run @k@ on a record token. Refuse a non-record value, and refuse the container outright when
the depth budget is already spent, because a record is itself one level.
-}
withRecord :: Int -> Tokens k String -> (TkRecord k String -> Either SelectiveError a) -> Either SelectiveError a
withRecord budget toks k
    | budget < 1 = Left SelectiveTooDeeplyNested
    | otherwise = case toks of
        TkRecordOpen rec -> k rec
        _ -> Left SelectiveUndecodable

{- | Run @k@ on an array token. Refuse a non-array value, and refuse the container outright when
the depth budget is already spent, because an array is itself one level.
-}
withArray :: Int -> Tokens k String -> (TkArray k String -> Either SelectiveError a) -> Either SelectiveError a
withArray budget toks k
    | budget < 1 = Left SelectiveTooDeeplyNested
    | otherwise = case toks of
        TkArrayOpen arr -> k arr
        _ -> Left SelectiveUndecodable

{- | Consume one value's tokens without allocating a 'Value', returning the continuation.
It bounds nesting exactly as 'Ecluse.Core.Security.withinNestingBudget' does over a built
'Value': a value occupies one level, and a container's children sit one level deeper.
-}
skipValue :: Int -> Tokens k String -> Either SelectiveError k
skipValue budget toks
    | budget < 1 = Left SelectiveTooDeeplyNested
    | otherwise = case toks of
        TkLit _ cont -> Right cont
        TkText _ cont -> Right cont
        TkNumber _ cont -> Right cont
        TkArrayOpen{} -> withArray budget toks (skipArray (budget - 1))
        TkRecordOpen rec -> skipRecord (budget - 1) rec
        TkErr _ -> Left SelectiveUndecodable

{- | Skip an array's items (each at @budget@), returning the continuation after its end. It is
'collectFromArray' picking none of them.
-}
skipArray :: Int -> TkArray k String -> Either SelectiveError k
skipArray budget arr = (\(_, _, cont) -> cont) <$> collectFromArray budget (const False) arr

-- | Skip a record's values (each at @budget@), returning the continuation after its end.
skipRecord :: Int -> TkRecord k String -> Either SelectiveError k
skipRecord budget = \case
    TkPair _ toks -> skipValue budget toks >>= skipRecord budget
    TkRecordEnd cont -> Right cont
    TkRecordErr _ -> Left SelectiveUndecodable

{- | Whether the bytes after the top-level value are JSON whitespace only. It is the end-of-input
check @eitherDecodeStrict@ applies, so a body with trailing non-whitespace fails identically.
-}
trailingWhitespace :: ByteString -> Bool
trailingWhitespace = BS.all isJsonSpace
  where
    isJsonSpace :: Word8 -> Bool
    isJsonSpace w = w == 0x20 || w == 0x0a || w == 0x0d || w == 0x09
