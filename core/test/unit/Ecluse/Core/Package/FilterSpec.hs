-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Core.Package.FilterSpec (spec) where

import Data.Aeson (Value (String))
import Data.Map.Strict qualified as Map
import Data.Set qualified as Set
import Data.Text qualified as T
import Data.Time (UTCTime (..), addUTCTime, fromGregorian, nominalDay)
import Hedgehog (Gen, annotateShow, assert, forAll, (===))
import Hedgehog qualified as H
import Hedgehog.Gen qualified as Gen
import Hedgehog.Range qualified as Range
import Test.Hspec
import Test.Hspec.Hedgehog (hedgehog)

import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.Package (
    Artifact (artFilename, artUrl),
    CodeExecSignal (NoCodeOnInstall, RunsCodeOnInstall),
    InvalidEntry (invalidKey, invalidKind, invalidReason, invalidValue),
    InvalidEntryKind (InvalidIndexFile, InvalidVersionManifest),
    PackageDetails (..),
    PackageInfo (..),
    PackageName,
 )
import Ecluse.Core.Package.Filter (FilterPlan (..), enforceArtifactLocations, enforceArtifactLocationsOf)
import Ecluse.Core.Rules.Types (
    EvalContext (EvalContext),
    PrecededRule,
    Rule (AllowIfOlderThan, DenyInstallTimeExecution),
 )
import Ecluse.Core.Security (AllowedHostPorts, ecosystemArtifactAuthorities)
import Ecluse.Core.Version (compareVersions, isStable, mkVersion, parseVersionKey, renderVersion)
import Ecluse.Test.Package (sampleArtifact, sampleDetails, thingName)
import Ecluse.Test.Rules (atDefaultPrecedence, filterPlan, inertRuleDeps, isApproved)

spec :: Spec
spec = do
    survivorSpec
    latestSpec
    decisionsSpec
    propertiesSpec
    enforceArtifactLocationsSpec
    enforceArtifactLocationsOfSpec

-- | A fixed "now" so the age-based admit/deny axis is deterministic.
now :: UTCTime
now = UTCTime (fromGregorian 2026 6 20) 0

ctx :: EvalContext
ctx = EvalContext now Nothing

{- | The policy under test: a 7-day publish-age quarantine plus an install-script deny. A version
is approved iff it is at least 7 days old and declares no install script.
-}
policy :: [PrecededRule]
policy =
    [ atDefaultPrecedence (AllowIfOlderThan (7 * nominalDay))
    , atDefaultPrecedence DenyInstallTimeExecution
    ]

name :: PackageName
name = thingName

-- | An instant @ageDays@ before 'now', for a version's publish time.
publishedDaysAgo :: Integer -> UTCTime
publishedDaysAgo ageDays = addUTCTime (negate (fromInteger ageDays * nominalDay)) now

{- | A per-version snapshot carrying only what the filter reads: the version, the publish time,
and the install-code signal. Every other field is inert.
-}
detailsAt :: Text -> Integer -> Bool -> PackageDetails
detailsAt rawVer ageDays hasInstall =
    (sampleDetails name (mkVersion Npm rawVer))
        { pkgPublishedAt = Just (publishedDaysAgo ageDays)
        , pkgInstallCode = if hasInstall then RunsCodeOnInstall "postinstall" else NoCodeOnInstall
        , pkgLicenses = ["MIT"]
        }

{- | Build a 'PackageInfo' from @(rawVersion, ageDays, hasInstall)@ triples, with
@dist-tags.latest@ pointed at the given version (or none).
-}
infoOf :: Maybe Text -> [(Text, Integer, Bool)] -> PackageInfo
infoOf latest vs =
    PackageInfo
        { infoName = name
        , infoVersions = Map.fromList [(v, detailsAt v age install) | (v, age, install) <- vs]
        , infoDistTags = maybe Map.empty (Map.singleton "latest" . mkVersion Npm) latest
        , infoInvalidEntries = []
        }

survivorSpec :: Spec
survivorSpec = describe "fpSurvivors" $ do
    it "keeps only the approved versions, dropping a too-young one" $ do
        -- 1.0.0 is 30 days old and approved. 2.0.0 is 1 day old, denied by the age gate.
        plan <- filterPlan inertRuleDeps ctx policy (infoOf (Just "2.0.0") [("1.0.0", 30, False), ("2.0.0", 1, False)])
        fpSurvivors plan `shouldBe` Set.singleton "1.0.0"

    it "drops a version that declares an install script even when old enough" $ do
        -- Both old enough, but 2.0.0 runs an install script → denied by the deny rule.
        plan <- filterPlan inertRuleDeps ctx policy (infoOf (Just "1.0.0") [("1.0.0", 30, False), ("2.0.0", 30, True)])
        fpSurvivors plan `shouldBe` Set.singleton "1.0.0"

    it "is empty when nothing is approved" $ do
        plan <- filterPlan inertRuleDeps ctx policy (infoOf (Just "2.0.0") [("1.0.0", 1, False), ("2.0.0", 1, False)])
        fpSurvivors plan `shouldBe` Set.empty

latestSpec :: Spec
latestSpec = describe "fpLatest" $ do
    it "keeps a surviving upstream latest rather than promoting a higher survivor" $ do
        -- Upstream latest is 1.0.0 and both survive. Keep-unless-denied: 1.0.0
        -- stays, never promoted to the higher 2.0.0.
        plan <- filterPlan inertRuleDeps ctx policy (infoOf (Just "1.0.0") [("1.0.0", 30, False), ("2.0.0", 30, False)])
        latestRaw plan `shouldBe` Just "1.0.0"

    it "repoints latest down to a surviving version when the chosen latest is denied" $ do
        -- Upstream latest aims at the denied 2.0.0. The plan repoints it to the
        -- surviving 1.0.0.
        plan <- filterPlan inertRuleDeps ctx policy (infoOf (Just "2.0.0") [("1.0.0", 30, False), ("2.0.0", 1, False)])
        latestRaw plan `shouldBe` Just "1.0.0"

    it "prefers the highest stable survivor when repointing over a prerelease" $ do
        -- Upstream latest (3.0.0) is denied. The survivors are a stable 1.0.0 and a
        -- prerelease 2.0.0-rc.1, and the stable-preferring repoint chooses 1.0.0.
        plan <-
            filterPlan
                inertRuleDeps
                ctx
                policy
                (infoOf (Just "3.0.0") [("1.0.0", 30, False), ("2.0.0-rc.1", 30, False), ("3.0.0", 1, False)])
        latestRaw plan `shouldBe` Just "1.0.0"

    it "is Nothing when nothing survives" $ do
        plan <- filterPlan inertRuleDeps ctx policy (infoOf (Just "1.0.0") [("1.0.0", 1, False)])
        fpLatest plan `shouldBe` Nothing

decisionsSpec :: Spec
decisionsSpec = describe "fpDecisions" $ do
    it "carries one decision per version (survivors and denials alike)" $ do
        plan <- filterPlan inertRuleDeps ctx policy (infoOf (Just "2.0.0") [("1.0.0", 30, False), ("2.0.0", 1, False)])
        length (fpDecisions plan) `shouldBe` 2

    it "is all-non-approved when nothing survives" $ do
        plan <- filterPlan inertRuleDeps ctx policy (infoOf (Just "1.0.0") [("1.0.0", 1, False), ("2.0.0", 1, True)])
        length (fpDecisions plan) `shouldBe` 2
        any isApproved (fpDecisions plan) `shouldBe` False

propertiesSpec :: Spec
propertiesSpec = describe "properties" $ do
    it "survivors are exactly the approved version keys" $
        hedgehog $ do
            spec' <- forAll genSpec
            plan <- liftIO (filterPlan inertRuleDeps ctx policy (toInfo spec'))
            fpSurvivors plan === approvedKeys spec'

    it "decisions number one per version, all non-approved when no survivor" $
        hedgehog $ do
            spec' <- forAll genSpec
            plan <- liftIO (filterPlan inertRuleDeps ctx policy (toInfo spec'))
            length (fpDecisions plan) === length (specVersions spec')
            when (Set.null (fpSurvivors plan)) $
                assert (not (any isApproved (fpDecisions plan)))

    it "latest, when present, is always a surviving version" $
        hedgehog $ do
            spec' <- forAll genSpec
            plan <- liftIO (filterPlan inertRuleDeps ctx policy (toInfo spec'))
            case fpLatest plan of
                Nothing -> assert (Set.null (fpSurvivors plan))
                Just v -> assert (renderVersion v `Set.member` fpSurvivors plan)

    it "a surviving upstream latest is kept, never promoted to a higher survivor" $
        hedgehog $ do
            spec' <- forAll genSpec
            plan <- liftIO (filterPlan inertRuleDeps ctx policy (toInfo spec'))
            -- When the upstream-chosen latest itself survives, keep-unless-denied
            -- holds it in place regardless of any higher survivor.
            case specLatest spec' of
                Just chosen
                    | chosen `Set.member` fpSurvivors plan ->
                        latestRaw plan === Just chosen
                _ -> H.success

    it "a repointed latest is the highest stable survivor when any survivor is stable" $
        hedgehog $ do
            spec' <- forAll genSpec
            plan <- liftIO (filterPlan inertRuleDeps ctx policy (toInfo spec'))
            let survivors = fpSurvivors plan
                -- A repoint happens only when the chosen latest did not survive.
                chosenSurvived = maybe False (`Set.member` survivors) (specLatest spec')
                stableSurvivors = filter isStableRaw (Set.toList survivors)
            when (not chosenSurvived && not (null stableSurvivors)) $
                case latestRaw plan of
                    Just l -> do
                        annotateShow (l, stableSurvivors)
                        assert (isStableRaw l)
                        assert (all (\s -> compareVersions (mkVersion Npm s) (mkVersion Npm l) /= Just GT) stableSurvivors)
                    Nothing -> annotateShow survivors >> H.failure

{- | A generated logical packument: a chosen @latest@ target plus versions, each with an age and
an install-script flag. 'policy' decides which of them survive.
-}
data GenSpec = GenSpec
    { specLatest :: Maybe Text
    , specVersions :: [(Text, Integer, Bool)]
    }
    deriving stock (Show)

toInfo :: GenSpec -> PackageInfo
toInfo (GenSpec latest vs) = infoOf latest vs

-- | The keys 'policy' would approve: at least 7 days old and no install script.
approvedKeys :: GenSpec -> Set Text
approvedKeys =
    Set.fromList . map fst3 . filter (\(_, age, install) -> age >= 7 && not install) . specVersions
  where
    fst3 (a, _, _) = a

genSpec :: Gen GenSpec
genSpec = do
    n <- Gen.int (Range.linear 0 6)
    let versionStrings = take n versionPool
    triples <-
        forM versionStrings $ \v -> do
            age <- Gen.integral (Range.linear 0 60)
            install <- Gen.bool
            pure (v, age, install)
    latest <- case versionStrings of
        [] -> pure Nothing
        _ -> Just <$> Gen.element versionStrings
    pure (GenSpec latest triples)

-- A pool mixing stable and prerelease semver so repointing exercises both bands.
versionPool :: [Text]
versionPool = ["1.0.0", "1.1.0", "2.0.0-rc.1", "2.0.0", "3.0.0-beta", "10.0.0"]

-- | The resolved @latest@ as its raw version string, if present.
latestRaw :: FilterPlan -> Maybe Text
latestRaw = fmap renderVersion . fpLatest

-- | Whether a raw npm version string parses to a stable (non-prerelease) release.
isStableRaw :: Text -> Bool
isStableRaw raw = either (const False) isStable (parseVersionKey Npm raw)

{- | The served-location fold over a whole document: the scheme normalisation, the authority
check against the serving origin, and the per-artifact partition that drops a version only
when no file of it survives.
-}
enforceArtifactLocationsSpec :: Spec
enforceArtifactLocationsSpec = describe "enforceArtifactLocations (served artifact locations)" $ do
    let httpsUpstream = "https://registry.npmjs.org"
        urlOf info = (\(art :| _) -> artUrl art) . pkgArtifacts <$> Map.lookup "1.0.0" (infoVersions info)
        enforce = enforceArtifactLocations noArtifactHosts

    it "upgrades a same-host http artifact URL to https (https upstream)" $
        urlOf (enforce httpsUpstream (infoWithArtifact "http://registry.npmjs.org/thing/-/thing-1.0.0.tgz"))
            `shouldBe` Just "https://registry.npmjs.org/thing/-/thing-1.0.0.tgz"

    it "keeps an https artifact URL on the serving authority" $
        urlOf (enforce httpsUpstream (infoWithArtifact "https://registry.npmjs.org/thing/-/thing-1.0.0.tgz"))
            `shouldBe` Just "https://registry.npmjs.org/thing/-/thing-1.0.0.tgz"

    it "drops an https artifact URL on a foreign authority for an ecosystem declaring no artifact hosts" $ do
        let enforced = enforce httpsUpstream (infoWithArtifact "https://cdn.example.net/thing-1.0.0.tgz")
        Map.lookup "1.0.0" (infoVersions enforced) `shouldBe` Nothing
        map invalidKind (infoInvalidEntries enforced) `shouldBe` [InvalidVersionManifest]

    it "keeps an https artifact URL on a declared artifact host" $
        urlOf (enforceArtifactLocations (ecosystemArtifactAuthorities ["https://cdn.example.net"]) httpsUpstream (infoWithArtifact "https://cdn.example.net/thing-1.0.0.tgz"))
            `shouldBe` Just "https://cdn.example.net/thing-1.0.0.tgz"

    it "drops the refused file and keeps the version when another file survives" $ do
        let enforced = enforce httpsUpstream (infoWithArtifacts ("https://registry.npmjs.org/ok.whl" :| ["https://cdn.example.net/bad.whl"]))
        map artFilename . toList . pkgArtifacts <$> Map.lookup "1.0.0" (infoVersions enforced)
            `shouldBe` Just ["ok.whl"]
        map invalidKind (infoInvalidEntries enforced) `shouldBe` [InvalidIndexFile]
        map invalidKey (infoInvalidEntries enforced) `shouldBe` ["bad.whl"]

    it "drops a foreign-host http artifact URL and records it (https upstream)" $ do
        let enforced = enforce httpsUpstream (infoWithArtifact "http://evil.example.test/thing-1.0.0.tgz")
        Map.lookup "1.0.0" (infoVersions enforced) `shouldBe` Nothing
        map invalidKind (infoInvalidEntries enforced) `shouldBe` [InvalidVersionManifest]

    it "records the dropped artifact's authority, never its URL (the value reaches a log line)" $ do
        -- An upstream-supplied artifact location can carry a credential in its userinfo or a
        -- signed query string. The drop-tracking WARNING line renders the recorded value,
        -- so the filter keeps only the authority.
        let enforced = enforce httpsUpstream (infoWithArtifact credentialedTarball)
        map invalidValue (infoInvalidEntries enforced) `shouldBe` [String "evil.test:443"]
        droppedText enforced `shouldSatisfy` (not . T.isInfixOf "hunter2")
        droppedText enforced `shouldSatisfy` (not . T.isInfixOf "sig=abc")

    it "keeps the credential out of the drop reason as well as the value" $
        -- The WARNING line renders the reason beside the value, and the refusal reason is
        -- the other place the offending URL could reach it.
        map invalidReason (infoInvalidEntries (enforce httpsUpstream (infoWithArtifact credentialedTarball)))
            `shouldBe` ["dist.tarball is http on a host other than the upstream registry: evil.test:443"]

    for_ credentialedSpellings $ \(label, url) ->
        it ("reduces a " <> label <> " artifact URL, which carries no scheme to key on") $ do
            -- 'mkInvalidEntry' recognises a URL by its scheme separator, so the filter, whose
            -- input is known to be a URL, reduces these spellings itself.
            let enforced = enforce httpsUpstream (infoWithArtifact url)
            droppedText enforced `shouldSatisfy` (not . T.isInfixOf "hunter2")
            droppedText enforced `shouldSatisfy` (not . T.isInfixOf "sig=abc")

    it "keeps a same-authority artifact URL for a non-https (loopback) upstream" $
        urlOf (enforce "http://127.0.0.1:8080" (infoWithArtifact "http://127.0.0.1:8080/thing/-/thing-1.0.0.tgz"))
            `shouldBe` Just "http://127.0.0.1:8080/thing/-/thing-1.0.0.tgz"

    it "still checks the authority for a non-https upstream, which the download gate also does" $
        Map.lookup "1.0.0" (infoVersions (enforce "http://127.0.0.1:8080" (infoWithArtifact "http://evil.example.test/thing-1.0.0.tgz")))
            `shouldBe` Nothing

{- | The single-version form the selective-decode path uses: the same two predicates over one
version's artifacts, with 'Nothing' when none survives.
-}
enforceArtifactLocationsOfSpec :: Spec
enforceArtifactLocationsOfSpec = describe "enforceArtifactLocationsOf (single-version form)" $ do
    let httpsUpstream = "https://registry.npmjs.org"
        urlOf = fmap ((\(art :| _) -> artUrl art) . pkgArtifacts)
        enforce = enforceArtifactLocationsOf noArtifactHosts

    it "upgrades a same-host http artifact URL to https" $
        urlOf (enforce httpsUpstream (detailsWithArtifact "http://registry.npmjs.org/thing/-/thing-1.0.0.tgz"))
            `shouldBe` Just "https://registry.npmjs.org/thing/-/thing-1.0.0.tgz"

    it "drops the version when its artifact URL is http on a foreign host" $
        enforce httpsUpstream (detailsWithArtifact "http://evil.example.test/thing-1.0.0.tgz")
            `shouldBe` Nothing

    it "drops the version when its artifact authority is neither the origin nor a declared host" $
        enforce httpsUpstream (detailsWithArtifact "https://cdn.example.net/thing-1.0.0.tgz")
            `shouldBe` Nothing

    it "keeps a same-authority artifact URL for a non-https (loopback) upstream" $
        urlOf (enforce "http://127.0.0.1:8080" (detailsWithArtifact "http://127.0.0.1:8080/thing-1.0.0.tgz"))
            `shouldBe` Just "http://127.0.0.1:8080/thing-1.0.0.tgz"

-- | An ecosystem that declares no artifact host of its own, which is npm's posture.
noArtifactHosts :: AllowedHostPorts
noArtifactHosts = ecosystemArtifactAuthorities []

-- | A dropped artifact URL carrying a credential in its userinfo and a signature in its query.
credentialedTarball :: Text
credentialedTarball = "http://deploy:hunter2@evil.test/x?sig=abc"

{- | The same credential in the two spellings that carry no scheme separator, so the generic
drop-record redaction has nothing to key on.
-}
credentialedSpellings :: [(String, Text)]
credentialedSpellings =
    [ ("scheme-less", "deploy:hunter2@evil.test/x?sig=abc")
    , ("protocol-relative", "//deploy:hunter2@evil.test/x?sig=abc")
    ]

-- | Every dropped entry of a filtered document as one rendered blob, the way a log line reads it.
droppedText :: PackageInfo -> Text
droppedText = show . infoInvalidEntries

-- | A one-version 'PackageInfo' whose sole artifact carries the given URL.
infoWithArtifact :: Text -> PackageInfo
infoWithArtifact url =
    PackageInfo
        { infoName = name
        , infoVersions = Map.singleton "1.0.0" (detailsWithArtifact url)
        , infoDistTags = Map.empty
        , infoInvalidEntries = []
        }

-- | A 'PackageDetails' whose sole artifact carries the given URL (age\/install-signal inert).
detailsWithArtifact :: Text -> PackageDetails
detailsWithArtifact url =
    (detailsAt "1.0.0" 30 False){pkgArtifacts = sampleArtifact{artUrl = url} :| []}

{- | A one-version 'PackageInfo' whose version owns one artifact per URL, each named by that
URL's own file name, so a per-artifact drop is identifiable.
-}
infoWithArtifacts :: NonEmpty Text -> PackageInfo
infoWithArtifacts urls =
    PackageInfo
        { infoName = name
        , infoVersions = Map.singleton "1.0.0" details
        , infoDistTags = Map.empty
        , infoInvalidEntries = []
        }
  where
    details = (detailsAt "1.0.0" 30 False){pkgArtifacts = fmap artifactAt urls}
    artifactAt url = sampleArtifact{artUrl = url, artFilename = T.takeWhileEnd (/= '/') url}
