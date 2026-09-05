-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The PEP 691 JSON Simple index as it arrives on the wire, and its lenient decoder.

This module is the PyPI protocol __boundary__. PyPI is a file index rather than a document
store, so the shape it models is a flat @files@ array: one entry per distribution file, with
the release it belongs to spelled in the file name.
"Ecluse.Core.Registry.PyPI.Project" turns that into the agnostic domain model.

== What it models, and what it relays

It captures only the fields the rules and the serving path decide on: a file's name, location,
digests, interpreter constraint, size, upload instant, yank state, and provenance URL. The
@meta@ object and the PEP 700 @versions@ array are __not__ carried. The served body is rebuilt
from the raw document, so @meta._last-serial@ reaches a client without passing through a typed
model, and the surviving release set is computed from the files that survive rather than
relayed. Both are still walked, so a malformed entry in either is dropped and tracked.

The PEP 658 @core-metadata@ key is deliberately unmodelled: the wheel carries the same
metadata, so nothing above the projection reads it and no 'Ecluse.Core.Package.Artifact' field
holds it.

== Lenient on input, faithful on the decisive fields

A malformed @files@ or @versions@ entry drops as an 'InvalidEntry' rather than failing the
index, so one bad file cannot hide a whole project. @size@ is advisory and reads leniently, as
does @upload-time@: a version with no known upload instant simply fails the age quarantine. The
file name, location, and digests are required, because a file missing any of them can be
neither gated nor served.

@meta.api-version@ is the one field that can refuse the whole document. PEP 691 requires a
client to reject a major API version it does not speak, so an index declaring one does not
decode.
-}
module Ecluse.Core.Registry.PyPI.Wire (
    -- * The Simple index
    SimpleIndex (..),

    -- * One distribution file
    IndexFile (..),
    YankState (..),
) where

import Data.Aeson (
    FromJSON (parseJSON),
    Object,
    Value (Bool, Object, String),
    withObject,
    (.!=),
    (.:),
    (.:?),
 )
import Data.Aeson.KeyMap qualified as KeyMap
import Data.Aeson.Types (Parser, parseEither)
import Data.Text qualified as T
import Data.Time (UTCTime)

import Ecluse.Core.Json.Lenient (lenientOptional)
import Ecluse.Core.Package (
    InvalidEntry,
    InvalidEntryKind (InvalidIndexFile, InvalidVersionListing),
 )
import Ecluse.Core.Registry.WireSupport (partitionLenientList)

{- | One project's PEP 691 Simple index: the name it reports for itself and the distribution
files it offers. A dropped @files@ or @versions@ entry is recorded rather than served.
-}
data SimpleIndex = SimpleIndex
    { siName :: Text
    -- ^ The project name the index reports, verbatim. Empty when the key is absent.
    , siFiles :: [IndexFile]
    -- ^ The offered distribution files, in the order the index listed them.
    , siInvalidEntries :: [InvalidEntry]
    -- ^ The malformed @files@ and @versions@ entries the decode dropped.
    }
    deriving stock (Eq, Show)

instance FromJSON SimpleIndex where
    parseJSON = withObject "PyPI Simple index" $ \o -> do
        checkApiVersion o
        name <- o .:? "name" .!= ""
        (files, fileDrops) <- lenientFiles o
        versionDrops <- lenientVersionListing o
        pure
            SimpleIndex
                { siName = name
                , siFiles = files
                , -- Deterministic order (files, then the versions listing), each already in
                  -- input order, so the dropped-entry list is stable.
                  siInvalidEntries = fileDrops <> versionDrops
                }

{- | One distribution file: an sdist or a wheel, with the release it belongs to spelled in
'ifFilename' rather than carried beside it.
-}
data IndexFile = IndexFile
    { ifFilename :: Text
    -- ^ The distribution file name, which encodes the project, the release, and a wheel's tags.
    , ifUrl :: Text
    -- ^ The file's absolute upstream location, on the ecosystem's files host or the index's own.
    , ifHashes :: Map Text Text
    {- ^ Integrity digests keyed by algorithm name. @sha256@ is always present on public PyPI,
    and an algorithm this build does not know is dropped at projection.
    -}
    , ifRequiresPython :: Maybe Text
    -- ^ The PEP 440 interpreter specifier a client filters on, if the file declares one.
    , ifSize :: Maybe Int
    -- ^ The file's byte count, if reported. Advisory, so a hostile value reads as absent.
    , ifUploadTime :: Maybe UTCTime
    {- ^ When this file was published. It is per file, not per release, so a version's age
    signal is a fold over its files.
    -}
    , ifYanked :: YankState
    -- ^ Whether PEP 592 withdraws this file from resolution, and why.
    , ifProvenance :: Maybe Text
    -- ^ The URL of a PEP 740 attestation bundle, if the index names one.
    }
    deriving stock (Eq, Show)

instance FromJSON IndexFile where
    parseJSON = withObject "PyPI index file" $ \o ->
        IndexFile
            <$> o .: "filename"
            <*> o .: "url"
            <*> o .:? "hashes" .!= mempty
            <*> o .:? "requires-python"
            <*> lenientOptional o "size"
            <*> lenientOptional o "upload-time"
            <*> (yankState <$> o .:? "yanked")
            <*> o .:? "provenance"

{- | PEP 592's per-file yank marker. A yanked file stays installable by an exact pin and drops
out of every range, so it is withdrawn from resolution rather than deleted.
-}
data YankState
    = -- | The file resolves normally.
      FileOffered
    | -- | The file is withdrawn from resolution, with the reason the index gave.
      FileWithdrawn (Maybe Text)
    deriving stock (Eq, Show)

{- Read PEP 592's @yanked@ key, which is a boolean or the reason string. @false@, @null@,
absence, or any other shape reads as offered. -}
yankState :: Maybe Value -> YankState
yankState = \case
    Just (Bool True) -> FileWithdrawn Nothing
    Just (String reason) -> FileWithdrawn (Just reason)
    _ -> FileOffered

{- Refuse an index whose declared PEP 691 major API version this decoder does not speak, as
PEP 691 requires of a client. An index that declares none is read as this one. -}
checkApiVersion :: Object -> Parser ()
checkApiVersion o = do
    meta <- o .:? "meta" .!= mempty
    declared <- meta .:? "api-version"
    case T.breakOn "." <$> declared of
        Just (major, _) | major /= supportedApiMajor -> fail ("unsupported PEP 691 api-version: " <> toString major)
        _ -> pure ()

-- The PEP 691 major API version this decoder speaks.
supportedApiMajor :: Text
supportedApiMajor = "1"

{- Decode @files@ element-wise, recording an entry with no name, no location, or an
undecodable required field as an 'InvalidIndexFile': it cannot be gated, so it must not
be served. -}
lenientFiles :: Object -> Parser ([IndexFile], [InvalidEntry])
lenientFiles o = do
    raw <- o .:? "files" .!= []
    pure (first (map snd) (partitionLenientList InvalidIndexFile (parseEither parseJSON) (zipWith keyed [0 :: Int ..] raw)))
  where
    keyed position value = (fileKey position value, value)

{- Decode the PEP 700 @versions@ array element-wise for its drops alone. The files decide which
releases are served, so a listing entry that is not a version string loses only its own record. -}
lenientVersionListing :: Object -> Parser [InvalidEntry]
lenientVersionListing o = do
    raw <- o .:? "versions" .!= []
    pure (snd (partitionLenientList InvalidVersionListing decodeVersion (zip (map show [0 :: Int ..]) raw)))
  where
    decodeVersion :: Value -> Either String Text
    decodeVersion = parseEither parseJSON

-- The key a dropped file entry is recorded under: the name it declared, else its position.
fileKey :: Int -> Value -> Text
fileKey position = \case
    Object file | Just (String name) <- KeyMap.lookup "filename" file -> name
    _ -> show position
