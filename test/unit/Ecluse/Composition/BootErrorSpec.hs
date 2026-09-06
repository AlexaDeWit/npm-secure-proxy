-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Composition.BootErrorSpec (spec) where

import Data.Text qualified as T
import Test.Hspec

import Ecluse.Composition.BootError (
    BootError (..),
    StoreMaintenanceReason (ClientBuildFailed, NoControlPlane),
    renderBootError,
    renderBootErrors,
 )
import Ecluse.Config (
    PolicyError (UnknownRuleType),
    StoreTag (TagRegistry, TagVerdaccio),
 )
import Ecluse.Core.Credential (mkSecret)
import Ecluse.Core.Ecosystem (Ecosystem (..))

spec :: Spec
spec = do
    renderBootErrorSpec
    renderBootErrorsSpec

renderBootErrorsSpec :: Spec
renderBootErrorsSpec =
    describe "renderBootErrors" $
        it "reports every aggregated refusal, one line each, in the order it received them" $
            -- One failed launch shows every problem an operator must fix, so no refusal may be
            -- dropped and none may be reordered ahead of another.
            renderBootErrors [MissingAdapter PyPI, MirrorRoleWithoutMirroring]
                `shouldBe` renderBootError (MissingAdapter PyPI)
                    <> "\n"
                    <> renderBootError MirrorRoleWithoutMirroring
                    <> "\n"

renderBootErrorSpec :: Spec
renderBootErrorSpec = describe "renderBootError" $
    it "renders each boot-error kind as a distinct operator-facing line" $ do
        renderBootError (PolicyBootError (UnknownRuleType "x" "Y")) `shouldSatisfy` infixed "unknown type"
        renderBootError (MissingAdapter PyPI) `shouldSatisfy` infixed "no adapter"
        renderBootError (UnresolvedCredential Npm)
            `shouldSatisfy` infixed "mirror-write credential"
        renderBootError (QueueProviderUnavailable "pubsub") `shouldSatisfy` infixed "not available"
        renderBootError QueueRegionMissing `shouldSatisfy` infixed "AWS_REGION"
        renderBootError QueueRegionMissing `shouldSatisfy` infixed "AWS_ENDPOINT_URL_SQS"
        -- The unrecognised-shape render names the value and the accepted forms.
        renderBootError (QueueUrlUnrecognised "https://queue.example.test/q")
            `shouldSatisfy` infixed "https://queue.example.test/q"
        renderBootError (QueueUrlUnrecognised "x") `shouldSatisfy` infixed "projects/{project}/topics/{topic}"
        -- Each endpoint-override render names its variable, never the value it refused.
        renderBootError (QueueEndpointMalformed (mkSecret "http://u:tok@h"))
            `shouldSatisfy` infixed "AWS_ENDPOINT_URL_SQS"
        renderBootError (QueueEndpointMalformed (mkSecret "http://u:tok@h"))
            `shouldNotSatisfy` infixed "tok"
        renderBootError (AwsEndpointMalformed (mkSecret "http://u:tok@h"))
            `shouldSatisfy` infixed "AWS_ENDPOINT_URL"
        renderBootError (AwsEndpointMalformed (mkSecret "http://u:tok@h"))
            `shouldNotSatisfy` infixed "tok"
        renderBootError (AwsEndpointMalformed (mkSecret "http://u:tok@h"))
            `shouldNotSatisfy` infixed "AWS_ENDPOINT_URL_SQS"
        -- The mint-failure render tells a transient failure from a permanent one.
        renderBootError (CodeArtifactMintFailed "AccessDenied") `shouldSatisfy` infixed "transient"
        renderBootError (FirstPartyMissing Npm) `shouldSatisfy` infixed "ECLUSE_MOUNTS__NPM__FIRST_PARTY"
        renderBootError (PublishStaticCredentialNeedsEdge Npm TagVerdaccio) `shouldSatisfy` infixed "ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__VERDACCIO__TOKEN"
        -- Each collision render names the offending key, the mount it collided with, and why.
        renderBootError (PublicationTargetOnPublicUpstream Npm PyPI "https://store.example.test")
            `shouldSatisfy` infixed "ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET (https://store.example.test) shares a host with ECLUSE_MOUNTS__PYPI__PUBLIC_UPSTREAM"
        renderBootError (PublicationTargetOnPublicUpstream Npm PyPI "https://store.example.test")
            `shouldSatisfy` infixed "publisher's own credential"
        -- Both host-rule refusals name the change that satisfies the rule, as the store-rule
        -- refusals do, so a warned operator never learns more than a refused one.
        renderBootError (PublicationTargetOnPublicUpstream Npm PyPI "https://store.example.test")
            `shouldSatisfy` infixed "point it at a registry that shares a host with no public upstream"
        renderBootError (PublicationTargetOnMountEndpoint Npm PyPI "privateUpstream" "https://store.example.test")
            `shouldSatisfy` infixed "ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET is also ECLUSE_MOUNTS__PYPI__PRIVATE_UPSTREAM (https://store.example.test)"
        renderBootError (PublicationTargetOnMountEndpoint Npm PyPI "privateUpstream" "https://store.example.test")
            `shouldSatisfy` infixed "point it at a registry that holds no other role"
        renderBootError (MirrorTargetOnPublicUpstream Npm Npm "https://store.example.test")
            `shouldSatisfy` infixed "ECLUSE_MOUNTS__NPM__MIRROR_TARGET (https://store.example.test) shares a host with ECLUSE_MOUNTS__NPM__PUBLIC_UPSTREAM"
        renderBootError (MirrorTargetOnPublicUpstream Npm Npm "https://store.example.test")
            `shouldSatisfy` infixed "point it at a registry that shares a host with no public upstream"
        -- The mirror-store refusal adds the shared registry, which the operator needs to see
        -- because two keys can name one store under different spellings.
        renderBootError (MirrorTargetOnMountEndpoint Npm PyPI "privateUpstream" "https://store.example.test")
            `shouldSatisfy` infixed "ECLUSE_MOUNTS__NPM__MIRROR_TARGET is also ECLUSE_MOUNTS__PYPI__PRIVATE_UPSTREAM (https://store.example.test)"
        renderBootError (MirrorTargetOnMountEndpoint Npm PyPI "privateUpstream" "https://store.example.test")
            `shouldSatisfy` infixed "the Dredger permanently deletes from the mirror target"
        -- A split-role refusal names the invocation the operator typed and the key that fixes it.
        renderBootError (SplitRoleNeedsDurableQueue "ecluse proxy --no-worker")
            `shouldSatisfy` infixed "ecluse proxy --no-worker"
        renderBootError (SplitRoleNeedsDurableQueue "ecluse mirror") `shouldSatisfy` infixed "ECLUSE_QUEUE__URL"
        renderBootError MirrorRoleWithoutMirroring `shouldSatisfy` infixed "ECLUSE_MOUNTS__<ECOSYSTEM>__MIRROR_TARGET__<TAG>__URL"
        -- The queue backend refuses at the boot's own gate, so its render tells a transient
        -- fault from a permanent one exactly as the credential mint's does.
        renderBootError (MirrorQueueUnavailable "CredentialChainExhausted")
            `shouldSatisfy` infixed "ECLUSE_QUEUE__URL"
        renderBootError (MirrorQueueUnavailable "CredentialChainExhausted")
            `shouldSatisfy` infixed "transient"
        -- The advisory sync reaches the same credential discovery, so it refuses at that gate too.
        renderBootError (AdvisorySyncUnavailable "CredentialChainExhausted")
            `shouldSatisfy` infixed "ECLUSE_ADVISORIES__URL"
        renderBootError (AdvisorySyncUnavailable "CredentialChainExhausted")
            `shouldSatisfy` infixed "ECLUSE_ADVISORIES__DATA_DIR"
        renderBootError (AdvisorySyncUnavailable "CredentialChainExhausted")
            `shouldSatisfy` infixed "transient"
        -- The maintenance refusal names the key, the reason, and why the Dredger will not
        -- start without a backend for it.
        renderBootError (StoreMaintenanceUnavailable Npm (NoControlPlane TagRegistry))
            `shouldSatisfy` infixed "ECLUSE_MOUNTS__NPM__MIRROR_TARGET has no usable store maintenance backend: its target is a registry store, which carries no store maintenance backend this build can sweep"
        renderBootError (StoreMaintenanceUnavailable Npm (NoControlPlane TagRegistry))
            `shouldSatisfy` infixed "deletes from every mount's mirror target"
        renderBootError (StoreMaintenanceUnavailable Npm (ClientBuildFailed "CredentialChainExhausted"))
            `shouldSatisfy` infixed "building its client failed: CredentialChainExhausted"
        -- The tag conflict names both endpoints down to the tag, so an operator sees which
        -- declaration to change.
        renderBootError (StoreTagConflict Npm "mirrorTarget.codeArtifact" Npm "privateUpstream.verdaccio" "https://one.example.test")
            `shouldSatisfy` infixed "ECLUSE_MOUNTS__NPM__MIRROR_TARGET__CODE_ARTIFACT and ECLUSE_MOUNTS__NPM__PRIVATE_UPSTREAM__VERDACCIO"
        renderBootError (StoreTagConflict Npm "mirrorTarget.codeArtifact" Npm "privateUpstream.verdaccio" "https://one.example.test")
            `shouldSatisfy` infixed "one store has one backend, so declare both endpoints under the same tag"
        -- The sweep-pace refusal names the key, the value it read, and the floor it fell under,
        -- so an operator can fix it without reading the source for the floor.
        renderBootError (DredgerChunkPauseBeneathFloor 1 2)
            `shouldSatisfy` infixed "ECLUSE_DREDGER__CHUNK_PAUSE (dredger.chunkPause) is 1s, beneath the floor of 2s"
        renderBootError (DredgerChunkPauseBeneathFloor 1 2)
            `shouldSatisfy` infixed "may be raised and never lowered"
        -- The idle-Pilot refusal names both keys: the one that is set and the ones that are not.
        renderBootError PilotWithoutEcosystem
            `shouldSatisfy` infixed "ECLUSE_ADVISORIES__URL is set but no mount is declared"
        renderBootError PilotWithoutEcosystem
            `shouldSatisfy` infixed "ECLUSE_MOUNTS__<ECOSYSTEM>__"
  where
    infixed :: Text -> Text -> Bool
    infixed needle hay = needle `T.isInfixOf` hay
