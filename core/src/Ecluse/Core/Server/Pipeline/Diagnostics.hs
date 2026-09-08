-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Operator diagnostics for metadata failures, dropped entries, and integrity divergence.
Access-refusal logs contain no upstream body, headers, or credential.
-}
module Ecluse.Core.Server.Pipeline.Diagnostics (
    logMetadataFailure,
    logInvalidEntries,
    warnDivergences,
) where

import Data.Aeson (Value)
import Data.Aeson.Text (encodeToLazyText)
import Data.Text qualified as T
import Data.Text.Lazy qualified as TL
import Katip (KatipContext, Severity (WarningS), katipAddContext, logFM, ls, sl)

import Ecluse.Core.Package (
    HashAlg,
    InvalidEntry (invalidKey, invalidKind, invalidReason, invalidValue),
    PackageName,
    dropCountsByKind,
    renderHashAlg,
    renderInvalidEntryKind,
    renderPackageName,
 )
import Ecluse.Core.Package.Merge (
    Divergence (divLosing, divVersion, divWinning),
    IntegrityFingerprint,
    MergePlan (mpDivergences),
    integrityHashes,
 )
import Ecluse.Core.Registry (FetchFault (FetchBoundExceeded, FetchTransport, FetchUrlUnformable))
import Ecluse.Core.Registry.Metadata (
    MetadataError (MetadataAuthorisationFailure, MetadataBoundExceeded, MetadataFetch, MetadataNameMismatch, MetadataUndecodable),
 )
import Ecluse.Core.Security (
    LimitError (BodyTooLarge, TooDeeplyNested, TooManyArtifacts, TooManyVersions),
    authorityLabel,
 )
import Ecluse.Core.Server.Context (Handler)
import Ecluse.Core.Server.Pipeline.Internal (
    logDecodeFailure,
    logNameMismatch,
    logUpstreamUnformable,
    logUpstreamUnreachable,
 )
import Ecluse.Core.Telemetry.Record (MetricsPort (..))

-- | Log a per-origin metadata-fetch failure, dispatched by its cause. The serve path calls it once per real fetch, inside the single-flight leader and in the request's context.
logMetadataFailure :: PackageName -> Text -> MetadataError -> Handler ()
logMetadataFailure name baseUrl = \case
    MetadataAuthorisationFailure _ -> logFM WarningS "the upstream refused metadata access"
    MetadataBoundExceeded err -> logBreach name err
    MetadataUndecodable -> logDecodeFailure name
    MetadataNameMismatch reported -> logNameMismatch name baseUrl reported
    MetadataFetch (FetchBoundExceeded err) -> logBreach name err
    MetadataFetch (FetchUrlUnformable urlErr) -> logUpstreamUnformable name baseUrl urlErr
    MetadataFetch (FetchTransport fault) -> logUpstreamUnreachable name baseUrl fault

logBreach :: (KatipContext m) => PackageName -> LimitError -> m ()
logBreach name err =
    katipAddContext payload $
        logFM WarningS (ls message)
  where
    payload =
        sl "module" pipelineModule
            <> sl "package" (renderPackageName name)
            <> sl "bound" boundName
            <> sl "observed" observed
            <> sl "cap" cap

    message :: Text
    message = "refused an upstream metadata document: it exceeded the " <> boundName <> " response bound (observed " <> observed <> ", cap " <> cap <> ")"

    -- Pulled from the typed error, so the ceiling, the observed value, and the cap
    -- always agree with what was enforced.
    boundName :: Text
    observed :: Text
    cap :: Text
    (boundName, observed, cap) = case err of
        BodyTooLarge c -> ("body-size", "over " <> show c <> " bytes", show c <> " bytes")
        TooManyVersions seen c -> ("version-count", show seen, show c)
        TooManyArtifacts seen c -> ("artifact-count", show seen, show c)
        TooDeeplyNested c -> ("nesting-depth", "over " <> show c <> " levels", show c <> " levels")

-- | Log a cross-upstream integrity divergence (threat #11) at 'WarningS' and meter it: a public copy contradicts the trusted one on a shared integrity algorithm for a shared version.
warnDivergences :: (KatipContext m) => MetricsPort -> PackageName -> MergePlan -> m ()
warnDivergences metrics name plan =
    case toList (mpDivergences plan) of
        [] -> pass
        divs -> do
            liftIO (for_ divs (const (mpMergeDivergence metrics)))
            katipAddContext (payload divs) $ logFM WarningS (ls (message divs))
  where
    payload divs =
        sl "module" pipelineModule
            <> sl "package" (renderPackageName name)
            <> sl "versions" (T.intercalate "," (map divVersion divs))
    message divs =
        "cross-upstream integrity divergence: the trusted copy of "
            <> renderPackageName name
            <> " is served, but a public copy contradicts it on a shared integrity algorithm for "
            <> show (length divs)
            <> " version(s): "
            <> T.intercalate "; " (map renderDivergence divs)

renderDivergence :: Divergence -> Text
renderDivergence d =
    divVersion d
        <> " (trusted "
        <> renderFingerprint (divWinning d)
        <> " vs public "
        <> renderFingerprint (divLosing d)
        <> ")"

renderFingerprint :: IntegrityFingerprint -> Text
renderFingerprint fp = "{" <> T.intercalate ", " (map renderHash (integrityHashes fp)) <> "}"

renderHash :: (Text, Maybe HashAlg, Text) -> Text
renderHash (file, alg, body) = file <> " " <> maybe "none" renderHashAlg alg <> ":" <> body

-- | Log at 'WarningS' the malformed packument entries the projection dropped rather than failing the whole document.
logInvalidEntries :: (KatipContext m) => PackageName -> Text -> [InvalidEntry] -> m ()
logInvalidEntries name baseUrl entries =
    katipAddContext payload $
        logFM WarningS (ls message)
  where
    payload =
        sl "module" pipelineModule
            <> sl "package" (renderPackageName name)
            <> sl "upstream" (authorityLabel baseUrl)
            <> sl "droppedByKind" (dropCountsByKind entries)
            <> sl "droppedEntries" (map renderDroppedEntry (take maxRenderedDrops entries))

    entriesLen :: Int
    entriesLen = length entries

    message :: Text
    message =
        "dropped " <> show entriesLen <> " malformed entr" <> plural <> " from an upstream packument (the rest is served)"
    plural = if entriesLen == 1 then "y" else "ies"

-- One dropped entry for the operator, carrying the raw value the upstream sent
-- (truncated) so the offending bytes stay visible.
renderDroppedEntry :: InvalidEntry -> Text
renderDroppedEntry e =
    renderInvalidEntryKind (invalidKind e)
        <> " "
        <> invalidKey e
        <> " = "
        <> truncatedValue (invalidValue e)
        <> " ("
        <> invalidReason e
        <> ")"

-- The raw value as compact JSON, truncated to 'maxRenderedValueChars': only that many
-- characters are ever forced, so a huge value never balloons the log line.
truncatedValue :: Value -> Text
truncatedValue v =
    let rendered = TL.toStrict (TL.take (fromIntegral maxRenderedValueChars + 1) (encodeToLazyText v))
     in if T.compareLength rendered maxRenderedValueChars == GT
            then T.take maxRenderedValueChars rendered <> "…"
            else rendered

-- How many dropped entries the log renders in full, and how many characters of each raw value, so
-- a flood of drops or one huge value cannot bloat a log line. The per-kind counts stay complete.
maxRenderedDrops :: Int
maxRenderedDrops = 20

maxRenderedValueChars :: Int
maxRenderedValueChars = 200

-- The operator-facing @module@ log filter key. It is held stable as this value rather than the
-- source module path, so an operator's saved filter keeps matching.
pipelineModule :: Text
pipelineModule = "Ecluse.Server.Pipeline"
