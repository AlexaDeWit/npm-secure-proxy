-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The two pure transforms an npm packument needs before Écluse serves it. The
first rewrites the embedded artifact URLs under the mount's prefix. The second
assembles the served document from a cross-upstream 'MergePlan' and the raw source
documents.

Both transforms operate __structurally over the raw @aeson@ 'Value'__, never by
re-serialising a typed model. This is load-bearing. The served packument is an __open__
document: its schema is @additionalProperties: true@. The proxy
must __relay unchanged__ any field Écluse does not model: author keys, registry
bookkeeping, per-version extras. Building the served body from the raw @Value@s keeps
every unmodelled key. Rebuilding it from "Ecluse.Core.Package" would silently drop them.

== The decision\/replay split

Four decisions are ecosystem-agnostic: /which/ versions survive, which source wins each
one, where @dist-tags.latest@ resolves, and each surviving version's publish instant.
"Ecluse.Core.Package.Filter" and "Ecluse.Core.Package.Merge" take them over the typed
'Ecluse.Core.Package.PackageInfo' and hand them here as a 'MergePlan'. This module owns
the __npm wire-shape assembly__: rebuilding @versions@\/@dist-tags@\/@time@ onto the
base document from the plan, and the tarball-URL rewrite over the raw upstream bytes.
The npm wire knowledge lives here. The decision logic does not, because every ecosystem
reuses it. See @docs\/architecture\/registry-model.md@ → "Decision surface vs served
surface".

== URL rewriting

'rewriteVersion' rewrites one version object's @dist.tarball@ to
@{mount-base}\/{pkg}\/-\/{file}@ through the shared
'Ecluse.Core.Registry.ServedDocument.rebaseArtifactUrl', which owns the file-name
derivation and its idempotence. npm supplies only the @\/-\/@ spelling. A client that
resolves metadata /through/ the proxy then downloads the bytes through it, rather than
going straight to upstream and bypassing the gate. See
@docs\/architecture\/web-layer.md@ → "Multi-ecosystem mounts", whose URL rewriting is
load-bearing. Keeping artifacts same-host also keeps npm's auth flowing, which a
separate artifact host would silently drop. The caller __supplies__ the
@{mount-base}\/{pkg}@ prefix. 'assembleMergedPackument' derives it from the mount base
and the document's own safety-gated @name@ as it places each surviving version.

== Assembling the served document

'assembleMergedPackument' replays a 'MergePlan' onto the raw source @Value@s in
__one pass__. Each surviving version's object comes from the raw document of the
source that won it. The served bytes are therefore the winning upstream's, unmodelled
keys and all. The assembly rewrites its @dist.tarball@ under the mount base as it
places the version.

It rebuilds @dist-tags@ and @time@ from the plan's reconciled decisions: the times as
normalised ISO-8601, keeping the base document's @created@\/@modified@ bookkeeping.
Every other top-level key comes from the base document. A version not in the plan's
survivors is never taken, so a client's resolver only ever sees admitted versions.
Presence in the packument /is/ availability.

The fused single pass is deliberate. Restricting, assembling, and rewriting as
separate whole-document edits would rebuild a many-version packument several times
per request. This transform sits on the serve path's hot loop. The rewrite gates the
interpolated name through the shared
'Ecluse.Core.Registry.ServedDocument.safeDocumentName', which reads the base document's own
@name@ under the npm grammar before anything interpolates it. A document with no usable name
has no URLs rewritten.
-}
module Ecluse.Core.Registry.Npm.Filter (
    -- * URL rewriting
    rewriteVersion,

    -- * Assembling the served document
    assembleMergedPackument,
    npmDocumentName,

    -- * The served-document boundary (npm's 'CachedDoc' capabilities)
    assembleMergedDocument,
    serialiseMergedDocument,
) where

import Data.Aeson (Value (Object, String), encode)
import Data.Aeson.Key qualified as Key
import Data.Aeson.KeyMap (KeyMap)
import Data.Aeson.KeyMap qualified as KeyMap
import Data.Map.Strict qualified as Map

import Ecluse.Core.Package.Merge (MergePlan (mpDistTags, mpTime), SourceId)
import Ecluse.Core.Registry.CachedDocument (CachedDoc, npmCached)
import Ecluse.Core.Registry.Npm.Project (projectName)
import Ecluse.Core.Registry.ServedDocument (overlaySurvivors, rebaseArtifactUrl, safeDocumentName)
import Ecluse.Core.Text (joinUrlPath, renderIso8601Utc)
import Ecluse.Core.Version (renderVersion)

{- | The packument's own @name@ when it is safe to interpolate into a rewritten
@dist.tarball@ path, read through the shared gate under npm's name grammar.
-}
npmDocumentName :: KeyMap Value -> Maybe Text
npmDocumentName = safeDocumentName (isRight . projectName)

{- | Rewrite one version object's @dist.tarball@ to @{prefix}\/-\/{file}@, so the client
fetches the artifact back through this mount. The @{file}@ is the tarball URL's filename,
kept verbatim so the bytes a client integrity-checks do not change.

Total, lossless, and idempotent: a version with no @dist@, no @tarball@ string, or no
filename segment is left unchanged, and every unmodelled key is relayed.

@prefix@ is the mount's @{base}\/{pkg}@. A @{pkg}@ read from a document's own @name@ is
upstream-controlled, so the caller must gate it through 'npmDocumentName' first.
-}
rewriteVersion :: Text -> Value -> Value
rewriteVersion prefix = \case
    Object vo -> Object (adjustObject "dist" (rewriteDist prefix) vo)
    other -> other

{- | Rewrite a @dist@ object's @tarball@ to @{prefix}\/-\/{file}@, where @file@ is
the existing URL's filename. A @dist@ with no string @tarball@, or a tarball with
no filename, is left unchanged.
-}
rewriteDist :: Text -> Value -> Value
rewriteDist prefix = \case
    Object dist
        | Just url <- stringField "tarball" dist
        , Just rebased <- rebaseArtifactUrl (\file -> prefix <> "/-/" <> file) url ->
            Object (KeyMap.insert "tarball" (String rebased) dist)
    other -> other

{- | Assemble the served packument for @mountBase@ from a 'MergePlan' and the raw source
documents. The plan owns @versions@, @dist-tags@, and @time@, and every other top-level key
comes from the base document.

The assembly reads the raw @Value@s rather than the typed projections, so unmodelled fields
survive. A survivor whose source object is missing drops out, never a fabricated one. The
result is always an object, even for an empty plan or a non-object base document.
-}
assembleMergedPackument :: Text -> Map SourceId Value -> MergePlan -> Value -> Value
assembleMergedPackument mountBase bySource plan base =
    Object rebuilt
  where
    rebuilt :: KeyMap Value
    rebuilt =
        baseObject
            & KeyMap.insert "versions" (Object survivingVersions)
            & KeyMap.insert "dist-tags" (Object distTags)
            & KeyMap.insert "time" (Object reconciledTime)

    baseObject :: KeyMap Value
    baseObject = case base of
        Object o -> o
        _ -> mempty

    -- The shared gate reads the document's own upstream-controlled @name@ before it reaches
    -- the URL, and a document with no usable name has no version rewritten.
    rewriteSurvivor :: Value -> Value
    rewriteSurvivor = maybe id (rewriteVersion . joinUrlPath mountBase) (npmDocumentName baseObject)

    -- Each survivor's object is the raw @Value@ of the source that won the key, unmodelled
    -- keys and all. A survivor whose source object is missing drops out, never fabricated.
    survivingVersions :: KeyMap Value
    survivingVersions =
        KeyMap.fromList
            [ (Key.fromText version, rewriteSurvivor object)
            | (version, object) <- overlaySurvivors versionObjectIn bySource plan
            ]

    -- The plan has already resolved @latest@ and dropped absent-target tags over the union.
    distTags :: KeyMap Value
    distTags =
        KeyMap.fromList
            [ (Key.fromText tag, String (renderVersion v))
            | (tag, v) <- Map.toList (mpDistTags plan)
            ]

    -- @time@ rebuilt from the plan's surviving-version times, with the base
    -- document's non-version bookkeeping keys (@created@\/@modified@) retained.
    reconciledTime :: KeyMap Value
    reconciledTime =
        bookkeepingTime
            <> KeyMap.fromList
                [ (Key.fromText version, String (renderIso8601Utc t))
                | (version, t) <- Map.toList (mpTime plan)
                ]

    -- Two direct lookups, not a traversal: the base @time@ map carries one entry per published
    -- version alongside the @created@\/@modified@ bookkeeping keys.
    bookkeepingTime :: KeyMap Value
    bookkeepingTime = case KeyMap.lookup "time" baseObject of
        Just (Object timeObject) ->
            KeyMap.fromList
                [ (k, value)
                | name <- timeBookkeepingKeys
                , let k = Key.fromText name
                , Just value <- [KeyMap.lookup k timeObject]
                ]
        _ -> mempty

{- | npm's served-document __assemble__ capability
('Ecluse.Core.Registry.Adapter.Types.metadataAssemble'). The neutral pipeline threads the
documents opaquely, so projecting them into npm's 'Value' and injecting the result back is
npm's boundary.
-}
assembleMergedDocument :: Text -> Map SourceId CachedDoc -> MergePlan -> Maybe CachedDoc -> CachedDoc
assembleMergedDocument mountBase bySource plan base =
    fst npmCached (assembleMergedPackument mountBase (Map.mapMaybe npmValue bySource) plan (fromMaybe (Object mempty) (npmValue =<< base)))

{- | npm's served-document __serialise__ capability
('Ecluse.Core.Registry.Adapter.Types.metadataSerialise'): project the assembled
'CachedDoc' to npm's 'Value' and encode it compactly to the wire bytes.
-}
serialiseMergedDocument :: CachedDoc -> LByteString
serialiseMergedDocument = encode . fromMaybe (Object mempty) . npmValue

{- A source document in npm's own representation. One another ecosystem injected projects as
'Nothing' and is dropped, the same rule the assembly applies to a survivor whose source holds no
entry: a foreign document contributes nothing rather than an empty one. -}
npmValue :: CachedDoc -> Maybe Value
npmValue = snd npmCached

{- One source document's version lookup: its raw @versions@ object, resolved once per source
by 'overlaySurvivors' and then read per survivor. -}
versionObjectIn :: Value -> Text -> Maybe Value
versionObjectIn source =
    \version -> versions >>= KeyMap.lookup (Key.fromText version)
  where
    versions = case source of
        Object o | Just (Object vs) <- KeyMap.lookup "versions" o -> Just vs
        _ -> Nothing

-- The non-version keys an npm @time@ object carries, which the assembly relays
-- unchanged.
timeBookkeepingKeys :: [Text]
timeBookkeepingKeys = ["created", "modified"]

{- | Apply a function to the value at @key@, only when the object already carries that key.
A missing key stays absent, never fabricated, so passthrough stays lossless.
-}
adjustObject :: Key.Key -> (Value -> Value) -> KeyMap Value -> KeyMap Value
adjustObject key f o = case KeyMap.lookup key o of
    Just v -> KeyMap.insert key (f v) o
    Nothing -> o

-- | The 'Text' at @key@ in an object, if present and a JSON string.
stringField :: Key.Key -> KeyMap Value -> Maybe Text
stringField key o = case KeyMap.lookup key o of
    Just (String s) -> Just s
    _ -> Nothing
