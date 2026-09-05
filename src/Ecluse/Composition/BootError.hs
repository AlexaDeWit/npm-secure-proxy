-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The boot-error vocabulary of the composition root: every reason Écluse refuses to start, and
its operator-facing rendering.

Each case is a __fail-loud__ boot failure, and the root aggregates them, so a single run reports
every problem an operator must fix (see @docs\/architecture\/configuration.md@ → "Validation").
This module is the shared spine of the composition-root modules that produce them, so it holds
no policy of its own beyond the rendering and the fold that turns a thrown fault into one.
-}
module Ecluse.Composition.BootError (
    BootError (..),
    StoreMaintenanceReason (..),
    refuseOnThrow,
    renderBootError,
    renderBootErrors,
) where

import Data.Text qualified as T
import UnliftIO (tryAny)

import Ecluse.Config (
    PolicyError,
    StoreTag,
    renderPolicyError,
    storeTagName,
 )
import Ecluse.Config.Resolve (mountKeyRef)
import Ecluse.Core.Credential (Secret)
import Ecluse.Core.Ecosystem (Ecosystem, ecosystemName)
import Ecluse.Core.Text (displayExceptionT)

{- | A reason the composition root refuses to start. The root aggregates them, so a
single run reports every problem an operator must fix.
-}
data BootError
    = -- | A rule policy did not resolve (surfaced by 'Ecluse.Config.loadConfig').
      PolicyBootError PolicyError
    | {- | A configured mount's ecosystem has no adapter wired, so Écluse cannot serve it.
      A loud miss, never a silent drop.
      -}
      MissingAdapter Ecosystem
    | {- | A mount has no initialised mirror-write provider. Every active mount derives its
      credential from its mirror target, so this is a safety net, not a reachable state.
      -}
      UnresolvedCredential Ecosystem
    | {- | The queue URL's shape names a backend this binary compiled no implementation for.
      An honest refusal, never a silent fall-through to a different backend.
      -}
      QueueProviderUnavailable Text
    | {- | An SQS endpoint override (@AWS_ENDPOINT_URL_SQS@) is set but @AWS_REGION@ is not.
      An emulator or VPC endpoint carries no region in its host, so the ambient one must scope it.
      -}
      QueueRegionMissing
    | {- | @ECLUSE_QUEUE__URL@ is set but its shape names no backend this binary knows. Guessing
      one would send mirror jobs somewhere the operator did not point at. Carries the value.
      -}
      QueueUrlUnrecognised Text
    | {- | The configured SQS endpoint override (@AWS_ENDPOINT_URL_SQS@) is not a parseable
      endpoint URL. It can carry a credential, so the value stays redacted behind the secret.
      -}
      QueueEndpointMalformed Secret
    | {- | The S3 advisory client's endpoint override (@AWS_ENDPOINT_URL@) is not a parseable
      endpoint URL. Refused rather than dropped, so a typo never silently dials real AWS.
      -}
      AwsEndpointMalformed Secret
    | {- | The eager boot-time CodeArtifact mint threw. Carries the rendered exception, which
      tells a transient AWS error from a permanent one to fix.
      -}
      CodeArtifactMintFailed Text
    | {- | A publication target is set and the mount declares no first-party namespaces, so the
      anti-shadowing guard has nothing to enforce and any name could be shadowed.
      -}
      FirstPartyMissing Ecosystem
    | {- | A static publish credential is set without a verifiable inbound edge
      (@ECLUSE_SERVER__AUTH_TOKEN@). An unauthenticated request could otherwise publish as Écluse.
      -}
      PublishStaticCredentialNeedsEdge Ecosystem StoreTag
    | {- | A mount's publication target, at the carried registry, shares a host with the named
      mount's public upstream. The publisher's relayed credential would reach a public registry.
      -}
      PublicationTargetOnPublicUpstream Ecosystem Ecosystem Text
    | {- | A mount's publication target is also the named mount's endpoint under the named key, at
      the carried registry. A publish would be relayed into a role declared for something else.
      -}
      PublicationTargetOnMountEndpoint Ecosystem Ecosystem Text Text
    | {- | A mount's mirror target, at the carried registry, shares a host with the named mount's
      public upstream. Écluse's own mirror-write credential would reach a public registry.
      -}
      MirrorTargetOnPublicUpstream Ecosystem Ecosystem Text
    | {- | A mount's mirror target is also the named mount's endpoint under the named key, at the
      carried registry. A sweep of that store would delete data the other role owns.
      -}
      MirrorTargetOnMountEndpoint Ecosystem Ecosystem Text Text
    | {- | Two endpoints, each carried as its mount and its tagged key path, name the carried
      registry under different tags, so the two declarations disagree about what serves that store.
      -}
      StoreTagConflict Ecosystem Text Ecosystem Text Text
    | {- | An explicit memory override breaks the combined memory-plan invariant even after every
      tenant shed to its minimum. A computed plan degrades and boots, an operator claim does not.
      -}
      MemoryPlanOverrideUnsafe [Text]
    | {- | A split-deployment role (carried as its invocation) was selected over the bounded
      in-memory queue, whose jobs never leave the process that enqueued them.
      -}
      SplitRoleNeedsDurableQueue Text
    | {- | The dedicated mirror worker was launched with no mount declaring a mirror target, so
      it has no queue to drain and nothing to publish.
      -}
      MirrorRoleWithoutMirroring
    | {- | Building the configured mirror-queue backend threw. Carries the rendered exception,
      which tells a transient fault from a permanent one to fix.
      -}
      MirrorQueueUnavailable Text
    | {- | Preparing the configured advisory sync threw. Carries the rendered exception, which
      tells a transient fault from a permanent one to fix.
      -}
      AdvisorySyncUnavailable Text
    | {- | A vetted mirror store has no store maintenance backend the Dredger can sweep it
      with, carrying why.
      -}
      StoreMaintenanceUnavailable Ecosystem StoreMaintenanceReason
    | {- | An advisory store is configured and no mount is, so @ecluse pilot@ has no ecosystem
      to compile an artifact for and would publish nothing.
      -}
      PilotWithoutEcosystem
    deriving stock (Eq, Show)

-- | Why a mount's mirror target reached no store maintenance handle.
data StoreMaintenanceReason
    = -- | The mount's store tag names no control plane this build implements.
      NoControlPlane StoreTag
    | -- | The mount's store carries no operator consent to delete from it.
      DeletionNotPermitted StoreTag
    | {- | The store's only control plane is the ecosystem protocol, which spells no package
      listing or version delete.
      -}
      NoProtocolMaintenance
    | -- | Building the cleared backend's client against the live environment threw.
      ClientBuildFailed Text
    deriving stock (Eq, Show)

{- | Fold a thrown fault into the boot error the caller names, so a phase that dials a live
environment refuses through the aggregate rather than escaping the boot as an exception.
-}
refuseOnThrow :: (Text -> BootError) -> IO a -> IO (Either [BootError] a)
refuseOnThrow refusal action = first (pure . refusal . displayExceptionT) <$> tryAny action

{- | Render an aggregated refusal as the one block a failed launch reports, so every problem an
operator must fix appears in a single run.
-}
renderBootErrors :: [BootError] -> Text
renderBootErrors = T.unlines . map renderBootError

-- | Render a 'BootError' as a human-facing line for the aggregated failure block.
renderBootError :: BootError -> Text
renderBootError = \case
    PolicyBootError err -> renderPolicyError err
    MissingAdapter eco ->
        "mount " <> ecosystemName eco <> " has no adapter wired in this build"
    UnresolvedCredential eco ->
        "mount "
            <> ecosystemName eco
            <> " has no initialised mirror-write credential in this build"
    QueueProviderUnavailable provider ->
        "mirror queue provider "
            <> provider
            <> " (named by the ECLUSE_QUEUE__URL shape) is not available in this build"
    QueueRegionMissing ->
        "the SQS endpoint override (AWS_ENDPOINT_URL_SQS) is set but AWS_REGION is not: an emulator or VPC endpoint does not carry its region, so AWS_REGION must scope it"
    QueueUrlUnrecognised url ->
        "ECLUSE_QUEUE__URL names no queue backend this build knows: "
            <> url
            <> " (expected an SQS queue URL, https://sqs.{region}.amazonaws.com/{account}/{queue}, or a Pub/Sub topic resource, projects/{project}/topics/{topic}; unset it to run the bounded in-memory queue)"
    -- Both endpoint values can carry a credential, so each reason names its variable,
    -- never the URL.
    QueueEndpointMalformed{} ->
        "the SQS endpoint override (AWS_ENDPOINT_URL_SQS) is not a valid endpoint URL"
    AwsEndpointMalformed{} ->
        "the AWS endpoint override (AWS_ENDPOINT_URL) is not a valid endpoint URL"
    CodeArtifactMintFailed detail ->
        "mirror-target credential provider codeartifact failed to mint an initial token at boot: "
            <> detail
            <> " (a transient AWS error may clear on retry. A permanent one, such as a bad domain or region or a missing permission, must be fixed)"
    FirstPartyMissing eco ->
        mountKeyRef eco "publicationTarget" <> " is set but " <> mountKeyRef eco "firstParty" <> " is not: a publication target needs the namespaces this deployment owns, written in the ecosystem's own shape (npm scopes such as @acme, PyPI distribution names and acme-* prefixes), for the anti-shadowing guard."
    PublishStaticCredentialNeedsEdge eco tag ->
        mountKeyRef eco ("publicationTarget." <> storeTagName tag <> ".token")
            <> " is set but ECLUSE_SERVER__AUTH_TOKEN is not: a static publish credential needs a verifiable inbound edge."
    PublicationTargetOnPublicUpstream eco other url ->
        mountKeyRef eco "publicationTarget"
            <> " ("
            <> url
            <> ") shares a host with "
            <> mountKeyRef other "publicUpstream"
            <> ": a publish carries the publisher's own credential, which must never reach a public upstream, so point it at a registry that shares a host with no public upstream"
    PublicationTargetOnMountEndpoint eco other key url ->
        mountKeyRef eco "publicationTarget"
            <> " is also "
            <> mountKeyRef other key
            <> " ("
            <> url
            <> "): point it at a registry that holds no other role, so a publish is never relayed into one"
    MirrorTargetOnPublicUpstream eco other url ->
        mountKeyRef eco "mirrorTarget"
            <> " ("
            <> url
            <> ") shares a host with "
            <> mountKeyRef other "publicUpstream"
            <> ": the mirror write carries this proxy's own credential, which must never reach a public upstream, so point it at a registry that shares a host with no public upstream"
    MirrorTargetOnMountEndpoint eco other key url ->
        mountKeyRef eco "mirrorTarget"
            <> " is also "
            <> mountKeyRef other key
            <> " ("
            <> url
            <> "): the Dredger permanently deletes from the mirror target, so point it at a registry that holds no other role, or run no Dredger against this configuration"
    StoreTagConflict eco key other otherKey url ->
        mountKeyRef eco key
            <> " and "
            <> mountKeyRef other otherKey
            <> " name the same registry ("
            <> url
            <> ") under two tags: one store has one backend, so declare both endpoints under the same tag"
    MemoryPlanOverrideUnsafe details ->
        "memory plan refused: " <> T.intercalate "; " details
    SplitRoleNeedsDurableQueue invocation ->
        invocation
            <> " splits the mirror worker from the proxy, but ECLUSE_QUEUE__URL is unset, so mirroring runs on the bounded in-memory queue whose jobs never leave the process that enqueued them: point ECLUSE_QUEUE__URL at a durable queue, or run the single-process ecluse proxy"
    MirrorRoleWithoutMirroring ->
        "ecluse mirror runs the mirror worker alone, but no mount declares a mirror target, so it has nothing to mirror: set ECLUSE_MOUNTS__<ECOSYSTEM>__MIRROR_TARGET__<TAG>__URL, or run a role that needs no mirror queue"
    MirrorQueueUnavailable detail ->
        "the mirror queue backend named by ECLUSE_QUEUE__URL could not be built at boot: "
            <> detail
            <> " (a transient AWS or network error may clear on retry. A permanent one, such as unresolvable AWS credentials or a queue URL naming no reachable queue, must be fixed)"
    AdvisorySyncUnavailable detail ->
        "the advisory sync named by ECLUSE_ADVISORIES__URL could not be prepared at boot: "
            <> detail
            <> " (a transient AWS or network error may clear on retry. A permanent one, such as unresolvable AWS credentials or an ECLUSE_ADVISORIES__DATA_DIR this process cannot create, must be fixed)"
    StoreMaintenanceUnavailable eco reason ->
        mountKeyRef eco "mirrorTarget"
            <> " has no usable store maintenance backend: "
            <> renderStoreMaintenanceReason eco reason
            <> " (the Dredger deletes from every mount's mirror target, so it refuses rather than starting against a store it cannot sweep)"
    PilotWithoutEcosystem ->
        "ECLUSE_ADVISORIES__URL is set but no mount is declared, so ecluse pilot has no ecosystem to compile an advisory artifact for: declare the mounts this deployment serves under ECLUSE_MOUNTS__<ECOSYSTEM>__, or run a role this configuration has work for"

renderStoreMaintenanceReason :: Ecosystem -> StoreMaintenanceReason -> Text
renderStoreMaintenanceReason eco = \case
    NoControlPlane tag ->
        "its target is a " <> storeTagName tag <> " store, which carries no store maintenance backend this build can sweep"
    DeletionNotPermitted tag ->
        "its target is a "
            <> storeTagName tag
            <> " store and "
            <> mountKeyRef eco ("mirrorTarget." <> storeTagName tag <> ".permitDeletion")
            <> " is not set: that key is your consent for the Dredger to delete from this store"
    NoProtocolMaintenance ->
        "its store has no control plane, and the "
            <> ecosystemName eco
            <> " protocol carries no package listing or version delete for one"
    ClientBuildFailed detail -> "building its client failed: " <> detail
