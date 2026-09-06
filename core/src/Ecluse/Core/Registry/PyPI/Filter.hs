-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Assembling the PEP 691 Simple index Écluse serves, from a cross-upstream 'MergePlan' and
the raw source documents.

The served index is an open document, so the assembly works structurally over the raw @aeson@
'Value' and every unmodelled key on a surviving entry reaches the client. The plan owns which
releases and files survive. This module owns the wire shape: selecting entries out of the
winning source's flat @files@ array through the file-to-version index the fetch computed,
rebasing each location onto this mount, dropping the two PEP 658 sidecar keys Écluse serves no
companion for, and rebuilding the PEP 700 @versions@ array.
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
import Ecluse.Core.Registry.ServedDocument (rebaseArtifactUrl, stringField)
import Ecluse.Core.Text (joinUrlPath)

{- | Assemble the served Simple index for @mountBase@, rebasing every location under the plan's own
project name so the index carries none this mount would not claim. Always an object.
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

    -- An entry survives when the plan kept its file and named its source the winner of the
    -- release it belongs to, which the fetch-time index resolves without re-parsing a name.
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

-- Écluse serves no @.metadata@ companion, and the wheel carries the same metadata.
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

{- | PyPI's served-document __assemble__ capability. A source another ecosystem injected projects as
'Nothing' and contributes nothing.
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
('Ecluse.Core.Registry.Adapter.Types.metadataSerialise'), to the compact wire bytes.
-}
serialiseSimpleDocument :: CachedDoc -> LByteString
serialiseSimpleDocument = encode . maybe (Object mempty) fst . snd pypiSimpleCached
