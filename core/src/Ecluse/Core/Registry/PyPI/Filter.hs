-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Assembling the PEP 691 Simple index Écluse serves, from a cross-upstream
'Ecluse.Core.Package.Merge.MergePlan' and the raw source documents.

Like npm's counterpart, the assembly works __structurally over the raw @aeson@ 'Value'__ rather
than re-serialising a typed model. The served index is an open document: a client reads keys
this build does not model, and rebuilding from "Ecluse.Core.Package" would silently drop them.
Reading the raw documents keeps every unmodelled key on every file entry that survives.

== What the plan decides, and what this module replays

The decisions are ecosystem-agnostic and belong to "Ecluse.Core.Package.Filter" and
"Ecluse.Core.Package.Merge": which releases survive, which source won each, and which files of
each survive the per-artifact partition. This module owns the __PEP 691 wire-shape assembly__:
selecting the surviving files out of the winning source's flat @files@ array, rebasing each
file's location onto this mount, and rebuilding the PEP 700 @versions@ array from the survivors.

PyPI indexes files rather than versions, so the plan's version keys reach the flat array through
the file-to-version index the cached document carries, computed once at fetch. The assembly
re-parses no distribution file name.

== What the served index carries, and what it drops

@meta@ comes from the precedence-winning document, so @meta._last-serial@ survives and a mirror
can still revalidate cheaply. @versions@ names the surviving releases alone. A file entry keeps
@upload-time@, @yanked@, @requires-python@, @size@, and @hashes@ verbatim, so a client's own
resolution and its integrity check see what the upstream published. The @core-metadata@ and
@data-dist-info-metadata@ keys are dropped from every entry: Écluse serves no PEP 658 sidecar,
and advertising one it does not serve would send a resolver to a @404@.

The file URL is rebased through the shared
'Ecluse.Core.Registry.ServedDocument.rebaseArtifactUrl', with PyPI supplying only the @url@ key
and the artifact route's own spelling, so a served location and the route that must claim it
cannot disagree.
-}
module Ecluse.Core.Registry.PyPI.Filter (
    -- * Assembling the served index
    assembleSimpleIndex,
) where

import Data.Aeson (Value (Array, Object, String))
import Data.Aeson.Key qualified as Key
import Data.Aeson.KeyMap (KeyMap)
import Data.Aeson.KeyMap qualified as KeyMap
import Data.Map.Strict qualified as Map
import Data.Set qualified as Set
import Data.Vector qualified as V

import Ecluse.Core.Package.Merge (MergePlan (mpArtifacts, mpSurvivors), SourceId)
import Ecluse.Core.Registry.PyPI.Project (isCanonicalName)
import Ecluse.Core.Registry.PyPI.Request (artifactPath)
import Ecluse.Core.Registry.ServedDocument (rebaseArtifactUrl, safeDocumentName)
import Ecluse.Core.Text (joinUrlPath)

{- | Assemble the served Simple index for @mountBase@ from a 'MergePlan' and the raw source
documents, each paired with the file-to-version index its fetch computed.

@name@ and @meta@ come from the base document, @versions@ from the plan's survivors, and
@files@ from the entries the plan's surviving artifacts name in the source that won each
release. A named file the winning source does not hold drops out, never a fabricated one. The
result is always an object, even for an empty plan or a non-object base document.
-}
assembleSimpleIndex :: Text -> Map SourceId (Value, Map Text Text) -> MergePlan -> Value -> Value
assembleSimpleIndex mountBase bySource plan base =
    Object
        ( baseObject
            & KeyMap.insert "versions" (Array (V.fromList (map String (Map.keys (mpSurvivors plan)))))
            & KeyMap.insert "files" (Array (V.fromList survivingFiles))
        )
  where
    baseObject :: KeyMap Value
    baseObject = case base of
        Object o -> o
        _ -> mempty

    {- One pass over each source's flat array, keeping an entry when the plan kept its file and
    named that source the winner of the release the file belongs to. The file-to-version index
    the fetch computed is what maps an entry back to a release, so no file name is re-parsed. -}
    survivingFiles :: [Value]
    survivingFiles =
        [ served entry
        | (sid, (source, fileIndex)) <- Map.toList bySource
        , entry <- entriesOf source
        , Just filename <- [entryFilename entry]
        , Set.member filename keptFiles
        , Just version <- [Map.lookup filename fileIndex]
        , Map.lookup version (mpSurvivors plan) == Just sid
        ]

    -- Every file the per-artifact partition kept, across every surviving release.
    keptFiles :: Set Text
    keptFiles = Set.fromList (concatMap toList (Map.elems (mpArtifacts plan)))

    {- One served entry: its location rebased onto this mount, and the sidecar keys dropped. A
    document whose own name does not clear the grammar has nothing interpolated under it, so its
    entries keep their upstream locations and the artifact-host gate refuses them at download. -}
    served :: Value -> Value
    served = case safeDocumentName isCanonicalName baseObject of
        Just project -> dropSidecarKeys . rebaseEntry (servedFileUrl mountBase project)
        Nothing -> dropSidecarKeys

{- The mount-local URL a served file resolves to. The path is the artifact route's own spelling,
formed by the same builder the upstream read uses, so a rebased URL and the route that must
claim it cannot drift. -}
servedFileUrl :: Text -> Text -> Text -> Text
servedFileUrl mountBase project filename = joinUrlPath mountBase (artifactPath project filename)

-- Rebase one file entry's @url@ onto this mount. An entry with no string @url@, or one naming
-- no file, is left as it stands.
rebaseEntry :: (Text -> Text) -> Value -> Value
rebaseEntry renderUrl = \case
    Object entry
        | Just url <- stringField "url" entry
        , Just rebased <- rebaseArtifactUrl renderUrl url ->
            Object (KeyMap.insert "url" (String rebased) entry)
    other -> other

{- Drop the PEP 658 sidecar keys from a served entry. Écluse serves no @.metadata@ companion, so
advertising one would send a resolver to a @404@ instead of the wheel it can read the same
metadata out of. -}
dropSidecarKeys :: Value -> Value
dropSidecarKeys = \case
    Object entry -> Object (foldr KeyMap.delete entry sidecarKeys)
    other -> other

-- The two spellings PEP 714 has an index emit for the same sidecar.
sidecarKeys :: [Key.Key]
sidecarKeys = ["core-metadata", "data-dist-info-metadata"]

-- A source document's raw @files@ array, empty when the document carries none.
entriesOf :: Value -> [Value]
entriesOf = \case
    Object o | Just (Array files) <- KeyMap.lookup "files" o -> toList files
    _ -> []

-- One file entry's declared name, when it declares a string one.
entryFilename :: Value -> Maybe Text
entryFilename = \case
    Object entry -> stringField "filename" entry
    _ -> Nothing

-- | The 'Text' at @key@ in an object, if present and a JSON string.
stringField :: Key.Key -> KeyMap Value -> Maybe Text
stringField key o = case KeyMap.lookup key o of
    Just (String s) -> Just s
    _ -> Nothing
