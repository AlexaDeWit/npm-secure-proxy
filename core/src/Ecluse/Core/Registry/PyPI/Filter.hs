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

    -- * The served-document boundary (PyPI's 'CachedDoc' capabilities)
    assembleSimpleDocument,
    serialiseSimpleDocument,
) where

import Data.Aeson (Value (Array, Object, String), encode)
import Data.Aeson.Key qualified as Key
import Data.Aeson.KeyMap (KeyMap)
import Data.Aeson.KeyMap qualified as KeyMap
import Data.Map.Strict qualified as Map
import Data.Set qualified as Set
import Data.Vector qualified as V

import Ecluse.Core.Package (PackageName)
import Ecluse.Core.Package.Merge (MergePlan (mpArtifacts, mpName, mpSurvivors), SourceId)
import Ecluse.Core.Registry.CachedDocument (CachedDoc, FileVersionIndex, pypiSimpleCached)
import Ecluse.Core.Registry.PyPI.Route (distributionPath)
import Ecluse.Core.Registry.ServedDocument (rebaseArtifactUrl)
import Ecluse.Core.Text (joinUrlPath)

{- | Assemble the served Simple index for @mountBase@ from a 'MergePlan' and the raw source
documents, each paired with the file-to-version index its fetch computed.

@name@ and @meta@ come from the base document, @versions@ from the plan's survivors, and
@files@ from the entries the plan's surviving artifacts name in the source that won each
release. A named file the winning source does not hold drops out, never a fabricated one. The
result is always an object, even for an empty plan or a non-object base document.

Locations are rebased under the plan's own project name, never a document's self-reported
spelling, so a served index carries no location this mount would not claim.
-}
assembleSimpleIndex :: Text -> Map SourceId (Value, FileVersionIndex) -> MergePlan -> Value -> Value
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

    keptFiles :: Set Text
    keptFiles = allKeptFiles plan

    -- One served entry: its location rebased onto this mount, and the sidecar keys dropped.
    served :: Value -> Value
    served = dropSidecarKeys . rebaseEntry (servedFileUrl mountBase (mpName plan))

{- The mount-local URL a served file resolves to, rendered from the distribution route that must
claim it. -}
servedFileUrl :: Text -> PackageName -> Text -> Maybe Text
servedFileUrl mountBase project filename = joinUrlPath mountBase <$> distributionPath project filename

-- Rebase one file entry's @url@ onto this mount. An entry with no string @url@, or one naming
-- no file, is left as it stands.
rebaseEntry :: (Text -> Maybe Text) -> Value -> Value
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

{- | PyPI's served-document __assemble__ capability
('Ecluse.Core.Registry.Adapter.Types.metadataAssemble'). The neutral pipeline threads the
documents opaquely, so projecting them into PyPI's own representation and injecting the result
back is PyPI's boundary. A source another ecosystem injected projects as 'Nothing' and
contributes nothing, the same rule the assembly applies to a survivor whose source holds no
entry for it.
-}
assembleSimpleDocument :: Text -> Map SourceId CachedDoc -> MergePlan -> Maybe CachedDoc -> CachedDoc
assembleSimpleDocument mountBase bySource plan base =
    fst pypiSimpleCached (assembleSimpleIndex mountBase sources plan baseValue, servedIndex)
  where
    sources = Map.mapMaybe (snd pypiSimpleCached) bySource
    baseValue = maybe (Object mempty) fst (snd pypiSimpleCached =<< base)

    {- The assembled document's own file-to-version index: the entries the assembly served, so a
    re-read of the served document resolves exactly the releases it lists. -}
    servedIndex :: FileVersionIndex
    servedIndex =
        Map.filterWithKey
            (\filename version -> Map.member version (mpSurvivors plan) && Set.member filename (allKeptFiles plan))
            (foldMap snd (Map.elems sources))

-- Every file the per-artifact partition kept, across every surviving release.
allKeptFiles :: MergePlan -> Set Text
allKeptFiles plan = Set.fromList (concatMap toList (Map.elems (mpArtifacts plan)))

{- | PyPI's served-document __serialise__ capability
('Ecluse.Core.Registry.Adapter.Types.metadataSerialise'): project the assembled 'CachedDoc' to
its 'Value' and encode it compactly to the wire bytes.
-}
serialiseSimpleDocument :: CachedDoc -> LByteString
serialiseSimpleDocument = encode . maybe (Object mempty) fst . snd pypiSimpleCached
