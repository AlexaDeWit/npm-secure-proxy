-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Cross-ecosystem scaffolding for assembling the document Écluse serves.

"Ecluse.Core.Registry.WireSupport" is the inbound half of the same boundary, projecting an
untrusted upstream document into the domain model. This is the outbound half. Each ecosystem
owns its own wire-shape assembly, because that shape is exactly what differs between them, and
calls these definitions for the parts that do not: the plan-to-source overlay, the
self-reported-name gate, the artifact-URL rebase, and the raw-document field read. The last
three are security-bearing, which is why each has one definition rather than one per ecosystem.
-}
module Ecluse.Core.Registry.ServedDocument (
    -- * Replaying a merge plan
    overlaySurvivors,

    -- * The interpolated-name gate
    safeDocumentName,

    -- * Rebasing an artifact location
    rebaseArtifactUrl,

    -- * Reading a raw document
    stringField,
) where

import Data.Aeson (Value (String))
import Data.Aeson.Key qualified as Key
import Data.Aeson.KeyMap (KeyMap)
import Data.Aeson.KeyMap qualified as KeyMap
import Data.Map.Strict qualified as Map

import Ecluse.Core.Package.Merge (MergePlan (mpSurvivors), SourceId)
import Ecluse.Core.Text (urlFilename)

{- | Resolve each surviving version to the entry its winning source holds, in key order. A
survivor whose source holds no entry drops out, and each source's lookup is built once.
-}
overlaySurvivors :: (src -> Text -> Maybe entry) -> Map SourceId src -> MergePlan -> [(Text, entry)]
overlaySurvivors lookupIn bySource plan =
    [ (version, entry)
    | (version, sid) <- Map.toList (mpSurvivors plan)
    , Just lookupVersion <- [Map.lookup sid indexed]
    , Just entry <- [lookupVersion version]
    ]
  where
    -- One partially applied lookup per source, so the index each closes over is built once.
    indexed = Map.map lookupIn bySource

{- | What the ecosystem's own name parser makes of the name a document claims for itself. The
projection already refuses such a name, so this is defence in depth on the interpolated URL.
-}
safeDocumentName :: (Text -> Maybe a) -> KeyMap Value -> Maybe a
safeDocumentName parse document = case KeyMap.lookup "name" document of
    Just (String name) -> parse name
    _ -> Nothing

{- | Point an upstream artifact location back through this mount, keeping its file name verbatim.
Idempotent while the renderer puts that file name in the terminal path segment.
-}
rebaseArtifactUrl :: (Text -> Maybe Text) -> Text -> Maybe Text
rebaseArtifactUrl renderMountUrl url = renderMountUrl =<< urlFilename url

-- | The 'Text' at @key@ in a raw document object, if present and a JSON string.
stringField :: Key.Key -> KeyMap Value -> Maybe Text
stringField key o = case KeyMap.lookup key o of
    Just (String s) -> Just s
    _ -> Nothing
