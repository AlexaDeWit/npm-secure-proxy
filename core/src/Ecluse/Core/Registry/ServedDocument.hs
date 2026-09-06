-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Cross-ecosystem scaffolding for assembling the document Écluse serves, shared by every
ecosystem's served-document assembly ("Ecluse.Core.Registry.Npm.Filter").

"Ecluse.Core.Registry.WireSupport" is the inbound half of the same boundary: it projects an
untrusted upstream document into the domain model. This module is the outbound half. Each
ecosystem still owns its own wire-shape assembly, because the shape of a served document is
exactly what differs between them, and calls these three definitions for the parts that do not:

* __The plan-to-source overlay__. 'overlaySurvivors' resolves each surviving version to the
  entry the source that won it holds, so an assembly replays a
  'Ecluse.Core.Package.Merge.MergePlan' without re-deriving which source that is.

* __The self-reported-name gate__. 'safeDocumentName' reads the name a document claims for
  itself and admits it only when the ecosystem's own grammar does. The name is
  upstream-controlled and it reaches an interpolated URL, so one definition gates it for every
  ecosystem.

* __The artifact-URL rebase__. 'rebaseArtifactUrl' points an upstream artifact location back
  through this mount, so a client that resolved metadata here downloads the bytes here too
  rather than going straight to upstream and past the gate.

The last two are security-bearing, which is why each has one definition rather than one per
ecosystem.
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

{- | Resolve each surviving version to the entry the source that won it holds for it, in
ascending version order. A survivor whose winning source holds no entry drops out, so the
assembly never fabricates one.

The caller supplies how to look one version up in one source document. That lookup is built
once per source and reused for every survivor it won, so a document with many versions is
indexed once rather than per survivor.
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

{- | What the ecosystem's own name parser makes of the name a document claims for itself, or
'Nothing' when the parser refuses it. The projection refuses such a name before the document is
ever served, so this is defence in depth: a document whose name does not clear the grammar has
no URL rebased under it at all.
-}
safeDocumentName :: (Text -> Maybe a) -> KeyMap Value -> Maybe a
safeDocumentName parse document = case KeyMap.lookup "name" document of
    Just (String name) -> parse name
    _ -> Nothing

{- | Point an upstream artifact location back through this mount: take the file name the URL
ends in and render the mount-local URL for it.

The file name goes through verbatim, so the bytes a client integrity-checks do not change.
'Nothing' when the URL names no file, or when the renderer declines it, which leaves the
location as it stands rather than pointing it somewhere wrong.

__Idempotent__: re-deriving the file name from an already-rebased URL yields the same URL, so
applying it more than once is safe.
-}
rebaseArtifactUrl :: (Text -> Maybe Text) -> Text -> Maybe Text
rebaseArtifactUrl renderMountUrl url = renderMountUrl =<< urlFilename url

-- | The 'Text' at @key@ in a raw document object, if present and a JSON string.
stringField :: Key.Key -> KeyMap Value -> Maybe Text
stringField key o = case KeyMap.lookup key o of
    Just (String s) -> Just s
    _ -> Nothing
