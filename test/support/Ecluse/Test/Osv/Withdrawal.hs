-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Withdrawal variants of committed advisory fixtures.
An independent overlap and an unrelated active control remain in every archive.
-}
module Ecluse.Test.Osv.Withdrawal (withdrawalBytes, withdrawalZip) where

import Data.Aeson (Value (Object), eitherDecodeStrict, encode)
import Data.Aeson.KeyMap qualified as KM
import Data.ByteString.Lazy qualified as LBS

import Ecluse.Test.Osv (osvZipOf)

-- | Set only the withdrawal field of the committed active record, including malformed test values.
withdrawalBytes :: Maybe Value -> IO ByteString
withdrawalBytes withdrawn = do
    bytes <- readFileBS "test/fixtures/osv/withdrawal/active.json"
    case eitherDecodeStrict bytes of
        Right (Object fields) -> pure (LBS.toStrict (encode (Object (maybe fields (\v -> KM.insert "withdrawn" v fields) withdrawn))))
        Right _ -> fail "withdrawal fixture is not an object"
        Left err -> fail err

-- | Assemble a transition archive whose active controls keep its compiled output nonempty.
withdrawalZip :: Maybe Value -> IO LByteString
withdrawalZip withdrawn = do
    target <- withdrawalBytes withdrawn
    independent <- readFileLBS "test/fixtures/osv/withdrawal/independent.json"
    control <- readFileLBS "test/fixtures/osv/v1/GHSA-corpus-0001.json"
    osvZipOf [("active.json", LBS.fromStrict target), ("independent.json", independent), ("control.json", control)]
