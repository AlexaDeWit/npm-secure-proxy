-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Assemble PEP 691 Simple indexes from a cross-upstream 'MergePlan' and raw documents.
Surviving entries retain unmodelled keys and must have a mount-local artifact URL.
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

    survivingFiles :: [Value]
    survivingFiles =
        [ dropSidecarKeys rebased
        | (sid, (source, fileIndex)) <- Map.toList bySource
        , entry <- entriesOf source
        , Just filename <- [entryFilename entry]
        , Set.member filename keptFiles
        , Just version <- [Map.lookup filename fileIndex]
        , Map.lookup version (mpSurvivors plan) == Just sid
        , Just rebased <- [rebaseEntry (servedFileUrl mountBase (mpName plan)) entry]
        ]

    keptFiles :: Set Text
    keptFiles = allKeptFiles plan

servedFileUrl :: Text -> PackageName -> Text -> Maybe Text
servedFileUrl mountBase project filename = joinUrlPath mountBase <$> distributionPath project filename

-- A kept filename can also name a refused sibling, so each raw entry must pass rebasing.
rebaseEntry :: (Text -> Maybe Text) -> Value -> Maybe Value
rebaseEntry renderUrl = \case
    Object entry
        | Just url <- stringField "url" entry
        , Just rebased <- rebaseArtifactUrl renderUrl url ->
            Just (Object (KeyMap.insert "url" (String rebased) entry))
    _ -> Nothing

-- Écluse serves no @.metadata@ companion, and the wheel carries the same metadata.
dropSidecarKeys :: Value -> Value
dropSidecarKeys = \case
    Object entry -> Object (foldr KeyMap.delete entry sidecarKeys)
    other -> other

-- The two spellings PEP 714 has an index emit for the same sidecar.
sidecarKeys :: [Key.Key]
sidecarKeys = ["core-metadata", "data-dist-info-metadata"]

entriesOf :: Value -> [Value]
entriesOf = \case
    Object o | Just (Array files) <- KeyMap.lookup "files" o -> toList files
    _ -> []

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

    servedIndex :: FileVersionIndex
    servedIndex =
        Map.filterWithKey
            (\filename version -> Map.member version (mpSurvivors plan) && Set.member filename (allKeptFiles plan))
            (foldMap snd (Map.elems sources))

allKeptFiles :: MergePlan -> Set Text
allKeptFiles plan = Set.fromList (concatMap toList (Map.elems (mpArtifacts plan)))

{- | PyPI's served-document __serialise__ capability
('Ecluse.Core.Registry.Adapter.Types.metadataSerialise'), to the compact wire bytes.
-}
serialiseSimpleDocument :: CachedDoc -> LByteString
serialiseSimpleDocument = encode . maybe (Object mempty) fst . snd pypiSimpleCached
