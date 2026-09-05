-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.CompositionSpec (spec) where

import Data.Text qualified as T
import Test.Hspec

import Ecluse (mountBindingFor)
import Ecluse.Composition (
    BootWiring (bwBindings),
    PublishBudget (..),
    WiringPorts (WiringPorts, wpClock, wpReporters, wpResolveAdapter, wpRuleDeps),
    firstPartyName,
    planMounts,
    resolveBootWiring,
 )
import Ecluse.Composition.BootError (BootError (..), renderBootError)
import Ecluse.Composition.Support (
    expectConfig,
    expectEnv,
    expectProviders,
    expectValidated,
    fixedNow,
    overrideEnv,
    scopedName,
    staticEnvVars,
    testLimits,
    withoutMirrorTargetUrl,
 )
import Ecluse.Composition.Types (RegistryRole (MirrorWriter))
import Ecluse.Composition.Validate (vetBoot)
import Ecluse.Composition.Vet (runVet)
import Ecluse.Config (
    ConfigError (..),
    FirstParty (FirstPartyNpmScopes, FirstPartyPyPI),
    PolicyError (UnknownRuleType),
    StoreTag (TagRegistry),
    loadConfig,
    renderConfigError,
 )
import Ecluse.Core.Credential (unSecret)
import Ecluse.Core.Ecosystem (Ecosystem (..))
import Ecluse.Core.Package (HashAlg (SHA1, SHA512), PackageName, mkPackageName, mkScope)
import Ecluse.Core.Package.Integrity (
    mkMinIntegrity,
    mkMinTrustedIntegrity,
 )
import Ecluse.Core.Package.Merge (DivergencePolicy (FailClosed))
import Ecluse.Core.Registry.PyPI.FirstParty (PyPIFirstParty (PyPIOwnedName))
import Ecluse.Core.Security (Limits (maxBodyBytes, maxNestingDepth, maxVersionCount), defaultLimits)
import Ecluse.Core.Security.Egress (registryUrlText)
import Ecluse.Core.Server.Admission.Bytes (newByteAdmission)
import Ecluse.Core.Server.Context (
    MountBinding (bindingPackumentDeps, bindingPrefix, bindingPublishDeps),
    PackumentDeps (..),
    PublishDeps (..),
    pdMirror,
    pdPrivateBaseUrl,
    pdPublicBaseUrl,
    pdTarballHostGate,
 )
import Ecluse.Core.Server.Response (appendHelp)
import Ecluse.Core.Server.Upstream (
    MirrorServePlan (MirrorOnAdmit, NoMirrorWrite),
    mountUpstreams,
    upstreamTarballHostGate,
 )
import Ecluse.Test.Credential (noCredentialReporters)
import Ecluse.Test.Package (defaultMinIntegrity, defaultMinTrustedIntegrity, thingName)
import Ecluse.Test.Rules (inertRuleDeps)

{- | Tests the composition root's boot-time wiring. Every boot problem is a fail-fast,
aggregated boot error, and the injected clock and adapter resolver keep this spec free of IO.
-}
spec :: Spec
spec = do
    planMountsSpec
    bootErrorSpec
    publishWiringSpec
    firstPartySpec

expectDoc :: ByteString -> IO ByteString
expectDoc = pure

{- | A complete document mount keyed by the given ecosystem. Its non-CodeArtifact mirror target
and static write token resolve, so the no-adapter case fails on the adapter alone.
-}
mountDoc :: Text -> ByteString
mountDoc eco =
    encodeUtf8
        ( "{\"mounts\":{\""
            <> eco
            <> "\":{\"privateUpstream\":{\"registry\":{\"url\":\"https://priv\"}},\
               \\"publicUpstream\":{\"registry\":{\"url\":\"https://pub\"}},\
               \\"mirrorTarget\":{\"registry\":{\"url\":\"https://mir\",\"token\":\"t\"}}}}}"
        )

{- The ports a unit test injects into the environment-dependent tier: the real adapter resolver,
a fixed clock, inert rule deps, and reporters that record nothing. -}
testWiringPorts :: WiringPorts
testWiringPorts =
    WiringPorts
        { wpReporters = const noCredentialReporters
        , wpResolveAdapter = mountBindingFor
        , wpClock = pure fixedNow
        , wpRuleDeps = const inertRuleDeps
        }

-- Build the served bindings from an env + optional document through the boot's own pure pass
-- and then its environment-dependent tier, exactly as the composition root does.
planFrom :: [(String, String)] -> Maybe ByteString -> IO (Either [BootError] [MountBinding])
planFrom = planFromWith testLimits

-- As 'planFrom', but with the caller's resolved 'Limits' (the record the memory
-- budget would hand the composition root).
planFromWith :: Limits -> [(String, String)] -> Maybe ByteString -> IO (Either [BootError] [MountBinding])
planFromWith limits envVars mDocBytes = do
    case loadConfig envVars mDocBytes of
        Left cfgErrs -> pure (Left (concatMap toBoot errs))
          where
            errs = cfgErrs
            toBoot (PolicyErrors es) = map PolicyBootError es
            toBoot (ParseError err) = [PolicyBootError (UnknownRuleType "parse" err)]
            toBoot missing@(MountMissingPrivateUpstream _) = [PolicyBootError (UnknownRuleType "mount" (renderConfigError missing))]
            toBoot missing@(CodeArtifactHostMismatch _ _) = [PolicyBootError (UnknownRuleType "mount" (renderConfigError missing))]
            toBoot missing@(CodeArtifactFormatUnsupported _) = [PolicyBootError (UnknownRuleType "mount" (renderConfigError missing))]
            toBoot missing@(CodeArtifactRepositoryMissing _ _) = [PolicyBootError (UnknownRuleType "mount" (renderConfigError missing))]
            toBoot missing@PublicUrlRequired = [PolicyBootError (UnknownRuleType "server" (renderConfigError missing))]
        Right cfg -> case snd (runVet MirrorWriter (vetBoot cfg)) of
            -- The pass refuses before anything is built, which is what the composition root sees.
            Left vetErrs -> pure (Left vetErrs)
            Right plan -> do
                -- The root always pairs a publishing mount with a body budget. A
                -- generous test budget keeps these specs about the wiring.
                bodyBudget <- newByteAdmission (128 * 1024 * 1024)
                let publishBudget = PublishBudget{pbBodyBudget = bodyBudget, pbMaxRequestBytes = 26214400}
                fmap bwBindings <$> resolveBootWiring testWiringPorts limits (Just publishBudget) plan

planMountsSpec :: Spec
planMountsSpec = describe "resolveBootWiring (config-driven serving)" $ do
    it "produces one npm binding with packument-serve deps wired (served, not a 501 stub)" $ do
        _ <- expectEnv staticEnvVars
        planFrom staticEnvVars Nothing >>= \case
            Left errs -> expectationFailure ("unexpected boot errors: " <> show errs)
            Right [binding] -> do
                bindingPrefix binding `shouldBe` ("npm" :| [])
                do
                    let deps = bindingPackumentDeps binding
                    fmap registryUrlText (pdPrivateBaseUrl deps) `shouldBe` Just "https://private.example.test"
                    registryUrlText (pdPublicBaseUrl deps) `shouldBe` "https://public.example.test"
                    -- server.publicUrl is required once a mount is active, so the
                    -- mount base is always the absolute URL a real client needs.
                    pdMountBaseUrl deps `shouldBe` "https://registry.example.test/npm"
                    -- The mirror serve plan is wired from the mount's config: an
                    -- admitted public artifact enqueues toward the declared target.
                    mirrorTargetText (pdMirror deps) `shouldBe` Just "https://mirror.example.test"
                    -- The binding derives the tarball-host gate from the upstreams the deps carry,
                    -- never from a second reading of the configuration. npm declares no ecosystem
                    -- artifact hosts.
                    pdTarballHostGate deps
                        `shouldBe` upstreamTarballHostGate (mountUpstreams [] (pdPrivateBaseUrl deps) (pdPublicBaseUrl deps) (pdMirror deps))
            Right other -> expectationFailure ("expected exactly one binding, got " <> show (length other))

    it "rewrites the tarball base to an absolute URL under ECLUSE_SERVER__PUBLIC_URL" $ do
        -- With ECLUSE_SERVER__PUBLIC_URL set, dist.tarball rewrites to an absolute URL a real
        -- npm client can fetch, instead of the npm-incompatible relative path.
        _ <- expectEnv (overrideEnv "ECLUSE_SERVER__PUBLIC_URL" "https://proxy.example.test" staticEnvVars)
        planFrom (overrideEnv "ECLUSE_SERVER__PUBLIC_URL" "https://proxy.example.test" staticEnvVars) Nothing >>= \case
            Right [binding] -> do
                let deps = bindingPackumentDeps binding
                pdMountBaseUrl deps `shouldBe` "https://proxy.example.test/npm"
            other -> expectationFailure ("expected one binding, got " <> show (fmap length other))

    it "drops a trailing slash on ECLUSE_SERVER__PUBLIC_URL so the base joins with one separator" $ do
        _ <- expectEnv (overrideEnv "ECLUSE_SERVER__PUBLIC_URL" "https://proxy.example.test/" staticEnvVars)
        planFrom (overrideEnv "ECLUSE_SERVER__PUBLIC_URL" "https://proxy.example.test/" staticEnvVars) Nothing >>= \case
            Right [binding] -> do
                let deps = bindingPackumentDeps binding
                pdMountBaseUrl deps `shouldBe` "https://proxy.example.test/npm"
            other -> expectationFailure ("expected one binding, got " <> show (fmap length other))

    it "carries the resolved rule policy onto the binding's packument deps" $ do
        _ <- expectEnv staticEnvVars
        planFrom staticEnvVars Nothing >>= \case
            Right [binding] -> do
                -- 'PreparedRule' has no 'Show' (it carries an evaluator), so assert on
                -- the count rather than the rules themselves.
                let deps = bindingPackumentDeps binding
                null (pdRules deps) `shouldBe` False
            other -> expectationFailure ("expected one binding, got " <> show (fmap length other))

    it "threads the inbound edge token, clock, and help message onto the deps" $ do
        config <- expectConfig (("ECLUSE_SERVER__AUTH_TOKEN", "edge-secret") : ("ECLUSE_SERVER__HELP_MESSAGE", "ask #platform") : staticEnvVars) Nothing
        providers <- expectProviders config
        plan <- expectValidated config
        planMounts mountBindingFor (pure fixedNow) (const inertRuleDeps) providers testLimits Nothing plan >>= \case
            Right [binding] -> do
                let deps = bindingPackumentDeps binding
                fmap unSecret (pdInboundToken deps) `shouldBe` Just "edge-secret"
                fmap (\help -> appendHelp (Just help) "denied") (pdHelp deps)
                    `shouldBe` Just "denied ask #platform"
                served <- pdNow deps
                served `shouldBe` fixedNow
            other -> expectationFailure ("expected one binding, got " <> show (fmap length other))

    it "defaults additionalBlockedRanges to empty onto every mount's deps" $ do
        _ <- expectEnv staticEnvVars
        planFrom staticEnvVars Nothing >>= \case
            Right [binding] -> do
                let deps = bindingPackumentDeps binding
                pdAdditionalBlockedRanges deps `shouldBe` []
            other -> expectationFailure ("expected one binding, got " <> show (fmap length other))

    it "threads the operator's global additionalBlockedRanges onto every mount's deps" $ do
        -- Global (not per-mount): which internal ranges exist on an operator's own
        -- network is a deployment-wide fact, so one list applies to every mount alike.
        let testEnvVars = ("ECLUSE_EGRESS__ADDITIONAL_BLOCKED_RANGES", "203.0.113.0/24") : staticEnvVars
        _ <- expectEnv testEnvVars
        planFrom testEnvVars Nothing >>= \case
            Right [binding] -> do
                let deps = bindingPackumentDeps binding
                pdAdditionalBlockedRanges deps `shouldBe` ["203.0.113.0/24"]
            other -> expectationFailure ("expected one binding, got " <> show (fmap length other))

    it "defaults the response-bound budget to the secure defaults" $ do
        -- With no ECLUSE_MAX_* set, the deps carry Ecluse.Core.Security.defaultLimits -- the
        -- secure-default body/version/nesting ceilings (security.md invariant 4).
        _ <- expectEnv staticEnvVars
        planFrom staticEnvVars Nothing >>= \case
            Right [binding] -> do
                let deps = bindingPackumentDeps binding
                pdLimits deps `shouldBe` defaultLimits
            other -> expectationFailure ("expected one binding, got " <> show (fmap length other))

    it "threads the resolved limits onto every mount's deps" $ do
        -- The memory budget resolves the byte cap before the root runs, and the bindings carry the
        -- resolved 'Limits' record verbatim.
        let custom = defaultLimits{maxBodyBytes = 2048, maxVersionCount = 10, maxNestingDepth = 16}
        planFromWith custom staticEnvVars Nothing >>= \case
            Right [binding] -> do
                let deps = bindingPackumentDeps binding
                maxBodyBytes (pdLimits deps) `shouldBe` 2048
                maxVersionCount (pdLimits deps) `shouldBe` 10
                maxNestingDepth (pdLimits deps) `shouldBe` 16
            other -> expectationFailure ("expected one binding, got " <> show (fmap length other))

    it "defaults the public-integrity floor to SHA-256 onto the deps" $ do
        -- With ECLUSE_INTEGRITY__MIN_PUBLIC unset, every mount's deps carry the default
        -- SHA-256 floor the public admission gate enforces.
        _ <- expectEnv staticEnvVars
        planFrom staticEnvVars Nothing >>= \case
            Right [binding] -> do
                let deps = bindingPackumentDeps binding
                pdMinIntegrity deps `shouldBe` defaultMinIntegrity
            other -> expectationFailure ("expected one binding, got " <> show (fmap length other))

    it "threads a raised public-integrity floor onto the deps" $ do
        sha512Floor <- either (fail . toString) pure (mkMinIntegrity SHA512)
        _ <- expectEnv (("ECLUSE_INTEGRITY__MIN_PUBLIC", "sha512") : staticEnvVars)
        planFrom (("ECLUSE_INTEGRITY__MIN_PUBLIC", "sha512") : staticEnvVars) Nothing >>= \case
            Right [binding] -> do
                let deps = bindingPackumentDeps binding
                pdMinIntegrity deps `shouldBe` sha512Floor
            other -> expectationFailure ("expected one binding, got " <> show (fmap length other))

    it "defaults the trusted-integrity floor to SHA-256 onto the deps" $ do
        _ <- expectEnv staticEnvVars
        planFrom staticEnvVars Nothing >>= \case
            Right [binding] -> do
                let deps = bindingPackumentDeps binding
                pdMinTrustedIntegrity deps `shouldBe` defaultMinTrustedIntegrity
            other -> expectationFailure ("expected one binding, got " <> show (fmap length other))

    it "threads a loosened trusted-integrity floor (sha1) onto the deps" $ do
        -- The trusted floor is loosenable below SHA-256, unlike the public floor's hard SHA-256
        -- minimum, so a SHA-1 value must reach the deps the trusted gate consults.
        sha1Floor <- either (fail . toString) pure (mkMinTrustedIntegrity SHA1)
        _ <- expectEnv (("ECLUSE_INTEGRITY__MIN_TRUSTED", "sha1") : staticEnvVars)
        planFrom (("ECLUSE_INTEGRITY__MIN_TRUSTED", "sha1") : staticEnvVars) Nothing >>= \case
            Right [binding] -> do
                let deps = bindingPackumentDeps binding
                pdMinTrustedIntegrity deps `shouldBe` sha1Floor
            other -> expectationFailure ("expected one binding, got " <> show (fmap length other))

    it "refines the trusted floor and divergence policy per mount over the global defaults" $ do
        -- The two knobs describe trust in a particular registry, so a legacy mount's
        -- loosening must not leak onto other mounts. The mount key overrides, and the
        -- global default stands elsewhere.
        sha1Floor <- either (fail . toString) pure (mkMinTrustedIntegrity SHA1)
        let env =
                ("ECLUSE_MOUNTS__NPM__INTEGRITY__MIN_TRUSTED", "sha1")
                    : ("ECLUSE_MOUNTS__NPM__INTEGRITY__DIVERGENCE_POLICY", "fail-closed")
                    : staticEnvVars
        planFrom env Nothing >>= \case
            Right [binding] -> do
                let deps = bindingPackumentDeps binding
                pdMinTrustedIntegrity deps `shouldBe` sha1Floor
                pdDivergencePolicy deps `shouldBe` FailClosed
            other -> expectationFailure ("expected one binding, got " <> show (fmap length other))

bootErrorSpec :: Spec
bootErrorSpec = describe "resolveBootWiring (fail fast at boot)" $ do
    it "fails on an unresolved rule policy (a typo'd rule type)" $ do
        _ <- expectEnv staticEnvVars
        _ <- expectDoc "{\"rules\":{\"oops\":{\"type\":\"Nope\"}}}"
        planFrom staticEnvVars (Just "{\"rules\":{\"oops\":{\"type\":\"Nope\"}}}") >>= \case
            Left errs -> errs `shouldBe` [PolicyBootError (UnknownRuleType "oops" "Nope")]
            Right _ -> expectationFailure "expected a policy boot error"

    it "fails on a configured mount whose ecosystem has no adapter" $ do
        -- Touching any pypi key activates the mount, so the env fixture must carry
        -- the private upstream the activation contract requires.
        let unservedEnv =
                ("ECLUSE_MOUNTS__RUBYGEMS__PRIVATE_UPSTREAM__REGISTRY__URL", "https://priv.example.test")
                    : ("ECLUSE_MOUNTS__RUBYGEMS__MIRROR_TARGET__REGISTRY__URL", "https://mir.example.test")
                    : ("ECLUSE_MOUNTS__RUBYGEMS__MIRROR_TARGET__REGISTRY__TOKEN", "t")
                    : staticEnvVars
        _ <- expectEnv unservedEnv
        _ <- expectDoc (mountDoc "rubygems")
        planFrom unservedEnv (Just (mountDoc "rubygems")) >>= \case
            Left errs -> errs `shouldBe` [MissingAdapter RubyGems]
            Right _ -> expectationFailure "expected boot failure"

    it "refuses a leftover write token on a mount that declares no mirror-target url" $ do
        -- The write token lives under the target's tag, so a token left behind still
        -- declares the target and the absent url refuses, naming the key path.
        let env = withoutMirrorTargetUrl staticEnvVars
        planFrom env Nothing >>= \case
            Left errs ->
                map renderBootError errs
                    `shouldSatisfy` any (T.isInfixOf "mirrorTarget.registry.url is required")
            Right _ -> expectationFailure "expected a mirror-target boot error"

    it "binds a serve-only mount (no mirror target): NoMirrorWrite deps over the private merge" $ do
        let env = filter ((/= "ECLUSE_MOUNTS__NPM__MIRROR_TARGET__REGISTRY__TOKEN") . fst) (withoutMirrorTargetUrl staticEnvVars)
        planFrom env Nothing >>= \case
            Right [binding] -> do
                let deps = bindingPackumentDeps binding
                mirrorTargetText (pdMirror deps) `shouldBe` Nothing
                fmap registryUrlText (pdPrivateBaseUrl deps) `shouldBe` Just "https://private.example.test"
            other -> expectationFailure ("expected one serve-only binding, got " <> show (fmap length other))

    it "binds a pure public gate from enabled alone (no endpoint keys declared)" $ do
        -- The two-variable start: enabled activates the mount, the template public
        -- upstream serves, nothing is private and nothing mirrors.
        planFrom [("ECLUSE_MOUNTS__NPM__ENABLED", "true"), ("ECLUSE_SERVER__PUBLIC_URL", "https://registry.example.test")] Nothing >>= \case
            Right [binding] -> do
                let deps = bindingPackumentDeps binding
                pdPrivateBaseUrl deps `shouldBe` Nothing
                mirrorTargetText (pdMirror deps) `shouldBe` Nothing
                registryUrlText (pdPublicBaseUrl deps) `shouldBe` "https://registry.npmjs.org"
            other -> expectationFailure ("expected one binding, got " <> show (fmap length other))

    it "fails when a publication target is set without first-party namespaces" $ do
        -- ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__REGISTRY__URL set but ECLUSE_MOUNTS__NPM__FIRST_PARTY absent
        -- leaves the anti-shadowing guard nothing to enforce, so the boot refuses rather than defaulting.
        _ <- expectEnv (("ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__REGISTRY__URL", "https://publish.example.test") : staticEnvVars)
        planFrom (("ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__REGISTRY__URL", "https://publish.example.test") : staticEnvVars) Nothing >>= \case
            Left errs -> errs `shouldBe` [FirstPartyMissing Npm]
            Right _ -> expectationFailure "expected a publication-allow-missing boot error"

    it "fails when a static publish credential is set without a verifiable inbound edge" $ do
        -- ECLUSE_SERVER__AUTH_TOKEN unset is the default open edge. With
        -- ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__REGISTRY__TOKEN set, any unauthenticated client could
        -- publish within scope under Ecluse's own write credential, so the boot refuses.
        let testEnvVars =
                [ ("ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__REGISTRY__URL", "https://publish.example.test")
                , ("ECLUSE_MOUNTS__NPM__FIRST_PARTY", "@acme")
                , ("ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__REGISTRY__TOKEN", "publish-write-token")
                ]
                    <> staticEnvVars
        _ <- expectEnv testEnvVars
        planFrom testEnvVars Nothing >>= \case
            Left errs -> errs `shouldBe` [PublishStaticCredentialNeedsEdge Npm TagRegistry]
            Right _ -> expectationFailure "expected a publish-static-credential-needs-edge boot error"

    it "accumulates both publish boot errors when the namespaces are missing and the static credential has no edge" $ do
        -- Both couplings trip at once and surface together in a stable order: the namespaces
        -- first, then the edge requirement. The operator then fixes both before the next boot.
        let testEnvVars =
                [ ("ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__REGISTRY__URL", "https://publish.example.test")
                , ("ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__REGISTRY__TOKEN", "publish-write-token")
                ]
                    <> staticEnvVars
        _ <- expectEnv testEnvVars
        planFrom testEnvVars Nothing >>= \case
            Left errs -> errs `shouldMatchList` [FirstPartyMissing Npm, PublishStaticCredentialNeedsEdge Npm TagRegistry]
            Right _ -> expectationFailure "expected both publish boot errors, accumulated"

publishWiringSpec :: Spec
publishWiringSpec = describe "resolveBootWiring (first-party publish deps)" $ do
    it "wires the publication target and the first-party predicate onto the mount when configured" $ do
        let testEnv =
                [ ("ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__REGISTRY__URL", "https://publish.example.test")
                , ("ECLUSE_MOUNTS__NPM__FIRST_PARTY", "@acme, @beta")
                ]
                    <> staticEnvVars
        _ <- expectEnv testEnv
        planFrom testEnv Nothing >>= \case
            Right [binding] -> case bindingPublishDeps binding of
                Just deps -> do
                    registryUrlText (pubTargetUrl deps) `shouldBe` "https://publish.example.test"
                    -- The declaration reaches the mount as npm's own predicate: both
                    -- configured scopes admit, and anything outside them is refused.
                    map (pubAllowed deps) [scopedName "acme", scopedName "beta"] `shouldBe` [True, True]
                    map (pubAllowed deps) [scopedName "evil", thingName] `shouldBe` [False, False]
                Nothing -> expectationFailure "expected the mount to carry publish deps"
            _ -> expectationFailure "expected a single wired binding"

    it "boots a static publish credential when a verifiable inbound edge is configured" $ do
        -- The positive control for the fail-loud boot test above: the same static publish
        -- credential boots once ECLUSE_SERVER__AUTH_TOKEN gates the edge.
        let testEnv =
                [ ("ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__REGISTRY__URL", "https://publish.example.test")
                , ("ECLUSE_MOUNTS__NPM__FIRST_PARTY", "@acme")
                , ("ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__REGISTRY__TOKEN", "publish-write-token")
                , ("ECLUSE_SERVER__AUTH_TOKEN", "edge-token")
                ]
                    <> staticEnvVars
        _ <- expectEnv testEnv
        planFrom testEnv Nothing >>= \case
            Right [binding] -> case bindingPublishDeps binding of
                Just deps -> registryUrlText (pubTargetUrl deps) `shouldBe` "https://publish.example.test"
                Nothing -> expectationFailure "expected the mount to carry publish deps"
            _ -> expectationFailure "expected a single wired binding"

    it "refuses the boot, and wires no publish deps, when the publication target is a public upstream" $ do
        -- The witness that reaches the relay comes only from the collision check, so a
        -- refused target cannot be wired at all.
        let testEnv =
                [ ("ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__REGISTRY__URL", "https://public.example.test/npm/")
                , ("ECLUSE_MOUNTS__NPM__FIRST_PARTY", "@acme")
                ]
                    <> staticEnvVars
        _ <- expectEnv testEnv
        planFrom testEnv Nothing >>= \case
            Left errs -> errs `shouldBe` [PublicationTargetOnPublicUpstream Npm Npm "https://public.example.test/npm/"]
            Right _ -> expectationFailure "expected a publication-target collision boot error"

    it "leaves the publish path off (no publish deps) when no publication target is configured" $ do
        -- The opt-out: with no ECLUSE_MOUNTS__NPM__PUBLICATION_TARGET__REGISTRY__URL the mount carries no
        -- publish deps, so a PUT /{pkg} is 405. There is no implicit write path.
        _ <- expectEnv staticEnvVars
        planFrom staticEnvVars Nothing >>= \case
            Right [binding] -> case bindingPublishDeps binding of
                Nothing -> pure ()
                Just _ -> expectationFailure "expected no publish deps when no publication target is configured"
            _ -> expectationFailure "expected a single wired binding"

{- The mirror serve plan's declared target as characters. The wired value carries the
https-only egress witness, and these assertions read the configured URL back out of it. -}
mirrorTargetText :: MirrorServePlan -> Maybe Text
mirrorTargetText = \case
    MirrorOnAdmit url -> Just (registryUrlText url)
    NoMirrorWrite -> Nothing

{- | The one first-party predicate every consumer of the privilege reads. Each ecosystem's arm is pinned
here, because a disagreement between consumers is the dependency confusion it closes.
-}
firstPartySpec :: Spec
firstPartySpec = describe "firstPartyName (the derived first-party predicate)" $ do
    it "matches an npm scope exactly, refusing a lookalike and an unscoped name" $
        map
            (firstPartyName (FirstPartyNpmScopes (mkScope "acme" :| [mkScope "beta"])))
            [scopedName "acme", scopedName "beta", scopedName "acme-evil", thingName]
            `shouldBe` [True, True, False, False]

    it "dispatches the PyPI arm to PyPI's own predicate" $
        -- The arm's matching rules are pinned in "Ecluse.Core.Registry.PyPI.FirstPartySpec". This row
        -- proves the root hands the declaration to it rather than deciding anything itself.
        map (firstPartyName (pypiFirstParty ("Acme_Tools" :| [])) . pypiName) ["acme-tools", "beta"]
            `shouldBe` [True, False]

    it "wires the same predicate onto the mount's serve deps, deny by default" $ do
        let testEnv = [("ECLUSE_MOUNTS__NPM__FIRST_PARTY", "@acme")] <> staticEnvVars
        _ <- expectEnv testEnv
        planFrom testEnv Nothing >>= \case
            Right [binding] -> do
                let deps = bindingPackumentDeps binding
                map (pdFirstParty deps) [scopedName "acme", scopedName "evil", thingName]
                    `shouldBe` [True, False, False]
            _ -> expectationFailure "expected a single wired binding"

    it "owns no name on a mount that declares none" $ do
        _ <- expectEnv staticEnvVars
        planFrom staticEnvVars Nothing >>= \case
            Right [binding] ->
                map (pdFirstParty (bindingPackumentDeps binding)) [scopedName "acme", thingName]
                    `shouldBe` [False, False]
            _ -> expectationFailure "expected a single wired binding"

-- A PyPI name, in the ecosystem whose canonical form is PEP 503's.
pypiName :: Text -> PackageName
pypiName = mkPackageName PyPI Nothing

-- A PyPI declaration of exact names.
pypiFirstParty :: NonEmpty Text -> FirstParty
pypiFirstParty = FirstPartyPyPI . fmap (PyPIOwnedName . pypiName)
