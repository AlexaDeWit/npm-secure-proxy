-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The advisory artifact contract shared by Pilot and its consumers.
The epoch covers incompatible table shapes and incompatible meanings of stored values.
Artifacts are rebuilt rather than migrated. Compatible additions preserve the epoch.
-}
module Ecluse.Core.Osv.Schema (
    -- * The artifact epoch
    osvSchemaEpoch,
    osvDbFileName,

    -- * The tables
    rangesTableDdl,
    metaTableDdl,
    ColumnSpec (..),
    TableSpec (..),
    osvTableSpecs,

    -- * The @meta@ table
    MetaKey (..),
    renderMetaKey,
) where

import Data.Universe.Class (Universe (..))
import Data.Universe.Generic (universeGeneric)

-- | Advance for incompatible shape or stored-value semantics, not compatible additions.
osvSchemaEpoch :: Int
osvSchemaEpoch = 3

{- | A stable per-ecosystem key until the artifact's read contract changes.

>>> osvDbFileName "npm"
"npm-osv-schema3.db"
-}
osvDbFileName :: Text -> FilePath
osvDbFileName ecosystem =
    toString ecosystem <> "-osv-schema" <> show osvSchemaEpoch <> ".db"

-- | The ranges table's canonical strict DDL. The writer owns indexes outside this read contract.
rangesTableDdl :: Text
rangesTableDdl =
    "CREATE TABLE package_vulnerability_ranges (\
    \  package_name TEXT NOT NULL,\
    \  cve_id TEXT NOT NULL,\
    \  introduced_version TEXT,\
    \  fixed_version TEXT,\
    \  last_affected_version TEXT,\
    \  severity REAL,\
    \  epss_score REAL\
    \) STRICT"

-- | The @meta@ provenance table's canonical DDL, @STRICT@ like 'rangesTableDdl'.
metaTableDdl :: Text
metaTableDdl =
    "CREATE TABLE meta (\
    \  key TEXT NOT NULL PRIMARY KEY,\
    \  value TEXT NOT NULL\
    \) STRICT"

-- | A required column's enforced storage type and nullability.
data ColumnSpec = ColumnSpec
    { colName :: Text
    , colDeclaredType :: Text
    , colNotNull :: Bool
    }
    deriving stock (Eq, Show)

-- | A table the reader requires, with the columns its queries decode.
data TableSpec = TableSpec
    { tableName :: Text
    , tableColumns :: [ColumnSpec]
    }
    deriving stock (Eq, Show)

-- | Required strict tables and columns. Additional columns preserve reader compatibility.
osvTableSpecs :: [TableSpec]
osvTableSpecs =
    [ TableSpec
        { tableName = "package_vulnerability_ranges"
        , tableColumns =
            [ ColumnSpec{colName = "package_name", colDeclaredType = "TEXT", colNotNull = True}
            , ColumnSpec{colName = "cve_id", colDeclaredType = "TEXT", colNotNull = True}
            , ColumnSpec{colName = "introduced_version", colDeclaredType = "TEXT", colNotNull = False}
            , ColumnSpec{colName = "fixed_version", colDeclaredType = "TEXT", colNotNull = False}
            , ColumnSpec{colName = "last_affected_version", colDeclaredType = "TEXT", colNotNull = False}
            , ColumnSpec{colName = "severity", colDeclaredType = "REAL", colNotNull = False}
            , ColumnSpec{colName = "epss_score", colDeclaredType = "REAL", colNotNull = False}
            ]
        }
    , TableSpec
        { tableName = "meta"
        , tableColumns =
            [ ColumnSpec{colName = "key", colDeclaredType = "TEXT", colNotNull = True}
            , ColumnSpec{colName = "value", colDeclaredType = "TEXT", colNotNull = True}
            ]
        }
    ]

{- | A key of the artifact's @meta@ table, which holds one @TEXT@ key\/value row per key
and carries the artifact's provenance.
-}
data MetaKey
    = -- | The Pilot application version that produced the artifact.
      MetaPilotVersion
    | -- | The ecosystem Pilot compiled the artifact for (e.g. @npm@).
      MetaEcosystem
    | -- | When the compilation finished, as an ISO-8601 UTC timestamp.
      MetaBuiltAt
    | -- | The advisory source's host:port identity. Older artifacts can carry a complete URL.
      MetaSourceUrl
    | -- | The EPSS source's host:port identity. Older artifacts can carry a complete URL.
      MetaEpssSourceUrl
    | -- | The number of advisory ranges the artifact holds.
      MetaRowCount
    deriving stock (Eq, Generic, Show)

-- Enumerate every MetaKey from the type itself, so a new key needs no hand-maintained
-- list. Derived from Generic, not a partial Enum/Bounded pair.
instance Universe MetaKey where universe = universeGeneric

-- | The key's stored form in the @meta@ table.
renderMetaKey :: MetaKey -> Text
renderMetaKey = \case
    MetaPilotVersion -> "pilot_version"
    MetaEcosystem -> "ecosystem"
    MetaBuiltAt -> "built_at"
    MetaSourceUrl -> "source_url"
    MetaEpssSourceUrl -> "epss_source_url"
    MetaRowCount -> "row_count"
