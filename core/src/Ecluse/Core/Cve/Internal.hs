-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The advisory lookup's internals: the hardened SQLite open and the raw queries
"Ecluse.Core.Cve" curates into the public handle.

Importing this module opts out of the public surface's stability promises. It exists
so a test can pin the hardening properties directly against the connection the handle
actually uses. That connection refuses writes, and it distrusts schema-borne SQL.
-}
module Ecluse.Core.Cve.Internal (
    AdvisoryRange (..),
    CveDbRejected (..),
    openHardenedConnection,
    probeQuery,
    advisoriesQuery,
    coveredNamesQuery,
    toRange,
    provenanceQuery,
) where

import Database.SQLite.Simple (Connection, Only (..), SQLError, close, execute_, open, query, query_)
import UnliftIO.Exception (onException, try)

import Ecluse.Core.Ecosystem (Ecosystem, ecosystemName)
import Ecluse.Core.Osv.Schema (ColumnSpec (..), MetaKey (MetaEcosystem), TableSpec (..), osvSchemaEpoch, osvTableSpecs, renderMetaKey)
import Ecluse.Core.Osv.Types (UpperBound (FixedBefore, LastAffected, Unbounded))

{- | One advisory segment recorded against a package. 'arSeverity' is the CVSS base score
from 0 to 10 and 'arEpss' the EPSS probability from 0 to 1, each 'Nothing' when the artifact
carries no such score. The bounds are verbatim version text: 'arIntroduced' is inclusive and
'Nothing' means from the beginning, and 'arUpperBound' closes the segment.
-}
data AdvisoryRange = AdvisoryRange
    { arCveId :: Text
    , arSeverity :: Maybe Double
    , arIntroduced :: Maybe Text
    , arUpperBound :: UpperBound
    , arEpss :: Maybe Double
    }
    deriving stock (Eq, Show)

{- | Why the hardened open refused an artifact before building a handle over it. A
rejection is a value, not a fault, so the caller can keep the last known-good database.
-}
data CveDbRejected
    = {- | The artifact's @user_version@ stamp (carried) does not match this
      binary's 'osvSchemaEpoch'.
      -}
      CveDbWrongEpoch Int
    | {- | The artifact is not a usable SQLite database. Either it is not a
      database at all (absent or wrong header magic, which SQLite reports as
      @SQLITE_NOTADB@ on the first header read), or @PRAGMA quick_check@ found it
      structurally corrupt (a malformed, truncated, or crafted b-tree). The
      carried lines are the thrown error or the integrity report, which SQLite
      caps at 100 problems.
      -}
      CveDbIntegrityFailed [Text]
    | {- | A required relation (carried) does not conform to the epoch's schema
      contract: absent, not a real @STRICT@ table, or missing a required column
      with its declared type. A view here is attacker-authored SQL wearing the
      table's name. A lax (non-@STRICT@) table would leave the reader's decodes
      exposed to type-confused values.
      -}
      CveDbSchemaNonConformant Text
    | {- | The artifact's @meta@ table names a different ecosystem (carried) than
      the one this handle was asked to serve, or carries no ecosystem row at all
      so nothing can confirm the ecosystem ('Nothing'). Conformance catches an
      absent @meta@ table earlier, as 'CveDbSchemaNonConformant'.
      -}
      CveDbEcosystemMismatch (Maybe Text)
    deriving stock (Eq, Show)

{- | Open an artifact read-only-in-effect and accept or reject it. Every pragma runs
before the first query.

* @trusted_schema = OFF@ distrusts schema-defined functions, views feeding triggers, and
virtual tables in the file.
* @query_only = ON@ refuses every write, so no trigger can fire through the connection.
* @cell_size_check = ON@ turns a crafted oversized b-tree cell into a clean error, not an
out-of-bounds access.
* @mmap_size = 0@ keeps reads on the bounds-checked pager instead of mapping hostile file
pages into the address space.

Acceptance then runs cheapest and least trusting first: the 'osvSchemaEpoch' stamp, the
@PRAGMA quick_check@ integrity walk, the required tables against the epoch's schema
contract, and last the @meta@ ecosystem. sqlite-simple cannot pass @SQLITE_OPEN_READONLY@
at open, so @query_only@ carries the read-only guarantee for every statement.
-}
openHardenedConnection :: Ecosystem -> FilePath -> IO (Either CveDbRejected Connection)
openHardenedConnection eco dbFile = do
    conn <- open dbFile
    -- The 'onException' guard closes the connection when a statement throws instead, for
    -- example a non-SQLite file whose first file-touching pragma raises.
    let hardenAndAccept = do
            execute_ conn "PRAGMA trusted_schema = OFF"
            execute_ conn "PRAGMA query_only = ON"
            execute_ conn "PRAGMA cell_size_check = ON"
            execute_ conn "PRAGMA mmap_size = 0"
            acceptArtifact eco conn
    accepted <- hardenAndAccept `onException` close conn
    case accepted of
        Left rejection -> do
            close conn
            pure (Left rejection)
        Right () -> pure (Right conn)

acceptArtifact :: Ecosystem -> Connection -> IO (Either CveDbRejected ())
acceptArtifact eco conn = runExceptT $ do
    ExceptT (checkEpochStamp conn)
    ExceptT (checkIntegrity conn)
    traverse_ (ExceptT . checkTableConformance conn) osvTableSpecs
    ExceptT (checkMetaEcosystem eco conn)

checkEpochStamp :: Connection -> IO (Either CveDbRejected ())
checkEpochStamp conn = do
    -- @PRAGMA user_version@ is the first statement to read the file's header, so a non-SQLite
    -- artifact raises @SQLITE_NOTADB@ here rather than returning a stamp. Folding it into a
    -- rejection value lets the sync task remember the refusal, so no later poll re-downloads it.
    stamped <- try (query_ conn "PRAGMA user_version") :: IO (Either SQLError [Only Int])
    pure $ case stamped of
        Left err -> Left (CveDbIntegrityFailed ["not a valid SQLite database: " <> show err])
        Right rows -> case map fromOnly rows of
            [epoch]
                | epoch == osvSchemaEpoch -> Right ()
                | otherwise -> Left (CveDbWrongEpoch epoch)
            _ -> Left (CveDbWrongEpoch 0)

{- | Walk the database structure and refuse an artifact SQLite reports as corrupt.
@quick_check@ skips the index-vs-table cross-validation this code does not rely on.
A badly mangled b-tree aborts the walk with @SQLITE_CORRUPT@ instead of reporting
problem rows, and that throw folds into the same rejection.
-}
checkIntegrity :: Connection -> IO (Either CveDbRejected ())
checkIntegrity conn = do
    result <- try (query_ conn "PRAGMA quick_check") :: IO (Either SQLError [Only Text])
    pure $ case result of
        Left err -> Left (CveDbIntegrityFailed [show err])
        Right report -> case map fromOnly report of
            ["ok"] -> Right ()
            problems -> Left (CveDbIntegrityFailed problems)

{- | Does the artifact carry this relation as the schema contract demands: a real
@STRICT@ table with every required column under its declared type? A column beyond the
spec is tolerated, which keeps an additive schema change epoch-neutral. Nothing an
artifact carries may make this throw, which is why the pragma rows decode through 'Maybe'.
-}
checkTableConformance :: Connection -> TableSpec -> IO (Either CveDbRejected ())
checkTableConformance conn spec = do
    listed <- try (query conn "SELECT type, strict FROM pragma_table_list WHERE name = ?" (Only (tableName spec))) :: IO (Either SQLError [(Maybe Text, Maybe Int)])
    columns <- try (query conn "SELECT name, type, \"notnull\" FROM pragma_table_xinfo(?)" (Only (tableName spec))) :: IO (Either SQLError [(Maybe Text, Maybe Text, Maybe Int)])
    pure $ case (listed, columns) of
        (Right [(Just "table", Just 1)], Right cols)
            | all (hasConformingColumn cols) (tableColumns spec) -> Right ()
        _ -> Left (CveDbSchemaNonConformant (tableName spec))

-- Is the required column among the table's actual columns, under its declared
-- type and (where the decode relies on it) NOT NULL?
hasConformingColumn :: [(Maybe Text, Maybe Text, Maybe Int)] -> ColumnSpec -> Bool
hasConformingColumn cols spec = any conforms cols
  where
    conforms (name, declaredType, notnull) =
        name == Just (colName spec)
            && declaredType == Just (colDeclaredType spec)
            && (not (colNotNull spec) || notnull == Just 1)

checkMetaEcosystem :: Ecosystem -> Connection -> IO (Either CveDbRejected ())
checkMetaEcosystem eco conn = do
    -- Acceptance already confirmed @meta@ is a real @STRICT@ table of @NOT NULL TEXT@ whose
    -- values the integrity walk verified, so this row decode is total.
    named <- try (query conn "SELECT value FROM meta WHERE key = ?" (Only (renderMetaKey MetaEcosystem))) :: IO (Either SQLError [Only Text])
    pure $ case named of
        Left _ -> Left (CveDbEcosystemMismatch Nothing)
        Right rows ->
            let found = fromOnly <$> listToMaybe rows
             in if found == Just (ecosystemName eco)
                    then Right ()
                    else Left (CveDbEcosystemMismatch found)

{- | Does any advisory for this package name carry this exact version string as a fixed
bound? Deliberately string equality, under the artifact contract's canonical-semver expectation.
-}
probeQuery :: Connection -> Text -> Text -> IO Bool
probeQuery conn name version = do
    hits <- query conn "SELECT 1 FROM package_vulnerability_ranges WHERE package_name = ? AND fixed_version = ? LIMIT 1" (name, version) :: IO [Only Int]
    pure (not (null hits))

{- | Every package name this artifact records an advisory against, each once. The name index
covers the scan, and the result is what a store sweep intersects its listing with.
-}
coveredNamesQuery :: Connection -> IO [Text]
coveredNamesQuery conn =
    map fromOnly <$> query_ conn "SELECT DISTINCT package_name FROM package_vulnerability_ranges"

-- | Every advisory segment recorded against a package name.
advisoriesQuery :: Connection -> Text -> IO [AdvisoryRange]
advisoriesQuery conn name = do
    rows <- query conn "SELECT cve_id, introduced_version, fixed_version, last_affected_version, severity, epss_score FROM package_vulnerability_ranges WHERE package_name = ?" (Only name)
    pure (map toRange rows)

{- | One artifact row as an advisory segment, decoding the two nullable bound columns
into the segment's single upper bound.
-}
toRange :: (Text, Maybe Text, Maybe Text, Maybe Text, Maybe Double, Maybe Double) -> AdvisoryRange
toRange (cveId, intro, fixed, lastAffected, severity, epss) =
    AdvisoryRange
        { arCveId = cveId
        , arSeverity = severity
        , arIntroduced = intro
        , arUpperBound = upper
        , arEpss = epss
        }
  where
    -- The writer fills at most one bound column. A row carrying both resolves as the fix.
    upper = case (fixed, lastAffected) of
        (Just f, _) -> FixedBefore f
        (Nothing, Just la) -> LastAffected la
        (Nothing, Nothing) -> Unbounded

{- | The artifact's @meta@ provenance rows, key-sorted for a deterministic snapshot.
It runs only on an accepted connection, so the @(Text, Text)@ decode cannot throw.
-}
provenanceQuery :: Connection -> IO [(Text, Text)]
provenanceQuery conn = query_ conn "SELECT key, value FROM meta ORDER BY key"
