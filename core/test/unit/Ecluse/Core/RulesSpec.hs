-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Policy decisions over package evidence and injected capabilities.
Advisory regressions preserve ecosystem identity and display spelling.
-}
module Ecluse.Core.RulesSpec (spec) where

import Data.Text qualified as T
import Data.Time (UTCTime (..), addUTCTime, fromGregorian, nominalDay)
import Hedgehog (Gen, forAll, (===))
import Hedgehog qualified as H
import Hedgehog.Gen qualified as Gen
import Hedgehog.Range qualified as Range
import Test.Hspec
import Test.Hspec.Hedgehog (hedgehog)

import UnliftIO.Exception (throwIO)

import Ecluse.Core.Breaker (noBreakerReporter)
import Ecluse.Core.Cve (AdvisoryRange (..))
import Ecluse.Core.Ecosystem (Ecosystem (..))
import Ecluse.Core.Osv.Types (UpperBound (FixedBefore, Unbounded))
import Ecluse.Core.Package
import Ecluse.Test.Cve (fakeCveLookup)
import Ecluse.Test.Package (sampleDetails, v1_0_0)
import Ecluse.Test.Rules (
    admittedBy,
    atDefaultPrecedence,
    blockedBy,
    inertRuleDeps,
    isUndecidable,
    noFaultReporter,
    withInstallScripts,
 )
import Ecluse.Test.Support (TestContractEscape (TestContractEscape))

import Ecluse.Core.Rules
import Ecluse.Core.Rules.Types

-- | A fixed "now" so age-based tests are deterministic.
now :: UTCTime
now = UTCTime (fromGregorian 2026 6 20) 0

ctx :: EvalContext
ctx = EvalContext now Nothing

{- | A package version under an optional npm scope, published @ageDays@ days before 'now'.
The rules under test read only the scope, the publish age, and the install-code signal.
-}
pkg :: Maybe Text -> Integer -> PackageDetails
pkg mScope ageDays =
    (sampleDetails (mkPackageName Npm (mkScope <$> mScope) "thing") v1_0_0)
        { pkgPublishedAt = Just (addUTCTime (negate (fromInteger ageDays * nominalDay)) now)
        , pkgLicenses = ["MIT"]
        }

isAllow :: RuleVerdict -> Bool
isAllow (Allow _) = True
isAllow _ = False

isNoDecision :: RuleVerdict -> Bool
isNoDecision (NoDecision _) = True
isNoDecision _ = False

isDeny :: RuleVerdict -> Bool
isDeny (Deny _) = True
isDeny _ = False

isBlockedByDefault :: Decision -> Bool
isBlockedByDefault (BlockedByDefault _) = True
isBlockedByDefault _ = False

-- | Put a rule at an explicit precedence (the operator-override form).
at :: Int -> Rule -> PrecededRule
at = PrecededRule

{- | Decide a policy through the one engine ('prepare' then 'evalRules') under the
given capabilities.
-}
decideWith :: RuleDeps -> [PrecededRule] -> PackageDetails -> IO Decision
decideWith deps prs pd = prepare deps prs >>= \prepared -> evalRules ctx prepared pd

-- | 'decideWith' for the pure built-ins, which consult no capability.
decide :: [PrecededRule] -> PackageDetails -> IO Decision
decide = decideWith inertRuleDeps

-- | Rule capabilities whose advisory database is the given fake's rows.
depsWith :: [(Text, AdvisoryRange)] -> RuleDeps
depsWith rows =
    RuleDeps
        { rdWithCveLookup = \use -> use (Just (fakeCveLookup rows))
        , rdCurrentAdvisoryEtag = pure Nothing
        , rdBreakerReporter = noBreakerReporter
        , rdFaultReporter = noFaultReporter
        }

{- | One advisory naming @thing\@1.0.0@ (the version 'pkg' builds) as its exact
fixed bound, with no other advisory leaving the package affected.
-}
fixRows :: [(Text, AdvisoryRange)]
fixRows = [("thing", AdvisoryRange "GHSA-fixed-0001" Nothing (Just "0") (FixedBefore "1.0.0") Nothing)]

{- | One advisory covering @[0, 2.0.0)@, so it affects the version 'pkg' builds, carrying the
CVSS and EPSS scores under test.
-}
affecting :: Maybe Double -> Maybe Double -> [(Text, AdvisoryRange)]
affecting severity epss = [("thing", AdvisoryRange "GHSA-affect-0001" severity (Just "0") (FixedBefore "2.0.0") epss)]

denyCveAt :: Double -> Rule
denyCveAt threshold = DenyIfCve (DenyIfCveParams threshold FailDeny)

denyEpssAt :: Double -> Rule
denyEpssAt threshold = DenyIfEpss (DenyIfEpssParams threshold FailDeny)

genScope :: Gen Text
genScope = Gen.text (Range.linear 1 12) Gen.alpha

genAgeDays :: Gen Integer
genAgeDays = Gen.integral (Range.linear 0 3650)

genPrecedence :: Gen Int
genPrecedence = Gen.int (Range.linear 0 1000)

{- | A rule that fires on the package the order-independence property builds: scoped
@scopeTxt@, old, and running install scripts. None yields no decision, so every rule competes.
-}
genFiringRule :: Text -> Gen Rule
genFiringRule scopeTxt =
    Gen.element
        [ AllowScope (mkScope scopeTxt)
        , AllowIfOlderThan (7 * nominalDay)
        , DenyInstallTimeExecution
        ]

-- Compare decisions independently of the order in which abstention reasons arrived.
canonical :: Decision -> Decision
canonical (BlockedByDefault reasons) = BlockedByDefault (sort reasons)
canonical d = d

spec :: Spec
spec = do
    describe "advisory package identity" $ do
        for_ [denyCveAt 0, denyEpssAt 0] $ \rule ->
            it (toString (ruleName rule <> " queries the canonical PyPI name")) $ do
                let pd = (pkg Nothing 0){pkgName = mkPackageName PyPI Nothing "Flask_Thing"}
                    rows = [("flask-thing", snd row) | row <- affecting (Just 9.8) (Just 0.9)]
                evalRule (depsWith rows) ctx rule pd >>= (`shouldSatisfy` isDeny)

        it "matches a PyPI fix and keeps its display spelling in the decision message" $ do
            let pd = (pkg Nothing 0){pkgName = mkPackageName PyPI Nothing "Flask_Thing"}
                rows = [("flask-thing", snd row) | row <- fixRows]
            decision <- decideWith (depsWith rows) [atDefaultPrecedence AllowIfRemediatesCve] pd
            admittedBy decision `shouldBe` Just "AllowIfRemediatesCve"
            renderDecision pd decision `shouldSatisfy` T.isInfixOf "Flask_Thing@1.0.0"

        it "does not fast-track a PyPI fix while a canonical-name advisory still affects it" $ do
            let pd = (pkg Nothing 0){pkgName = mkPackageName PyPI Nothing "Flask_Thing"}
                rows = [("flask-thing", snd row) | row <- fixRows <> affecting Nothing Nothing]
            evalRule (depsWith rows) ctx AllowIfRemediatesCve pd >>= (`shouldSatisfy` isNoDecision)

        for_ [mkPackageName Npm Nothing "Flask_Thing", mkPackageName Npm (Just (mkScope "Acme")) "Flask_Thing"] $ \name ->
            it (toString ("preserves npm identity " <> renderPackageName name)) $ do
                let pd = (pkg Nothing 0){pkgName = name}
                    exactRows = [(renderPackageName name, snd row) | row <- affecting Nothing Nothing]
                    otherRows = [("flask-thing", snd row) | row <- affecting Nothing Nothing]
                    exactFixes = [(renderPackageName name, snd row) | row <- fixRows]
                evalRule (depsWith exactRows) ctx (denyCveAt 0) pd >>= (`shouldSatisfy` isDeny)
                evalRule (depsWith otherRows) ctx (denyCveAt 0) pd >>= (`shouldSatisfy` isNoDecision)
                evalRule (depsWith exactFixes) ctx AllowIfRemediatesCve pd >>= (`shouldSatisfy` isAllow)

    describe "evalRule" $ do
        it "AllowScope allows a matching scope" $
            evalRule inertRuleDeps ctx (AllowScope (mkScope "myorg")) (pkg (Just "myorg") 0)
                >>= (`shouldSatisfy` isAllow)
        it "AllowScope yields no decision on a non-matching scope" $
            evalRule inertRuleDeps ctx (AllowScope (mkScope "myorg")) (pkg (Just "other") 0)
                >>= (`shouldSatisfy` isNoDecision)
        it "AllowScope yields no decision on an unscoped package" $
            evalRule inertRuleDeps ctx (AllowScope (mkScope "myorg")) (pkg Nothing 0)
                >>= (`shouldSatisfy` isNoDecision)
        it "AllowIfOlderThan allows a version older than the threshold" $
            evalRule inertRuleDeps ctx (AllowIfOlderThan (7 * nominalDay)) (pkg Nothing 30)
                >>= (`shouldSatisfy` isAllow)
        it "AllowIfOlderThan yields no decision on a too-young version" $
            evalRule inertRuleDeps ctx (AllowIfOlderThan (7 * nominalDay)) (pkg Nothing 1)
                >>= (`shouldSatisfy` isNoDecision)
        it "DenyInstallTimeExecution denies a package that runs install scripts" $
            evalRule inertRuleDeps ctx DenyInstallTimeExecution (withInstallScripts (pkg Nothing 99))
                >>= (`shouldSatisfy` isDeny)
        it "DenyInstallTimeExecution yields no decision when there are no install scripts" $
            evalRule inertRuleDeps ctx DenyInstallTimeExecution (pkg Nothing 99)
                >>= (`shouldSatisfy` isNoDecision)
        it "DenyByIdentity matches a package name exactly" $
            evalRule inertRuleDeps ctx (DenyByIdentity "thing") (pkg Nothing 0)
                >>= (`shouldSatisfy` isDeny)
        it "DenyByIdentity matches a package@version exactly" $
            evalRule inertRuleDeps ctx (DenyByIdentity "thing@1.0.0") (pkg Nothing 0)
                >>= (`shouldSatisfy` isDeny)
        it "DenyByIdentity matches a scoped package name exactly" $
            evalRule inertRuleDeps ctx (DenyByIdentity "@myorg/thing") (pkg (Just "myorg") 0)
                >>= (`shouldSatisfy` isDeny)
        it "DenyByIdentity yields no decision on a non-match" $
            evalRule inertRuleDeps ctx (DenyByIdentity "other") (pkg Nothing 0)
                >>= (`shouldSatisfy` isNoDecision)
        it "AllowByIdentity matches a package name exactly" $
            evalRule inertRuleDeps ctx (AllowByIdentity "thing") (pkg Nothing 0)
                >>= (`shouldSatisfy` isAllow)
        it "AllowByIdentity matches a package@version exactly" $
            evalRule inertRuleDeps ctx (AllowByIdentity "thing@1.0.0") (pkg Nothing 0)
                >>= (`shouldSatisfy` isAllow)
        it "AllowByIdentity yields no decision on a non-match" $
            evalRule inertRuleDeps ctx (AllowByIdentity "other") (pkg Nothing 0)
                >>= (`shouldSatisfy` isNoDecision)

    describe "evalRule (AllowIfRemediatesCve)" $ do
        it "allows a version an advisory names as its exact fix, crediting the advisory" $
            evalRule (depsWith fixRows) ctx AllowIfRemediatesCve (pkg Nothing 0)
                >>= (`shouldBe` Allow "remediates GHSA-fixed-0001")
        it "names every advisory the version fixes in the reason" $ do
            let rows =
                    [ ("thing", AdvisoryRange "GHSA-fixed-0001" Nothing (Just "0") (FixedBefore "1.0.0") Nothing)
                    , ("thing", AdvisoryRange "GHSA-fixed-0002" Nothing (Just "0.2.0") (FixedBefore "1.0.0") Nothing)
                    ]
            evalRule (depsWith rows) ctx AllowIfRemediatesCve (pkg Nothing 0)
                >>= (`shouldBe` Allow "remediates GHSA-fixed-0001, GHSA-fixed-0002")
        it "matches the OSV wire form of a scoped name" $ do
            let rows = [("@myorg/thing", AdvisoryRange "GHSA-fixed-0003" Nothing (Just "0") (FixedBefore "1.0.0") Nothing)]
            evalRule (depsWith rows) ctx AllowIfRemediatesCve (pkg (Just "myorg") 0)
                >>= (`shouldBe` Allow "remediates GHSA-fixed-0003")
        it "abstains when no advisory names the version as a fix (exact match only)" $ do
            -- 1.0.0 sits past this advisory's 0.9.0 fix, but the fast lane is a
            -- deliberate exact-fix probe: being merely unaffected earns nothing.
            let rows = [("thing", AdvisoryRange "GHSA-fixed-0001" Nothing (Just "0") (FixedBefore "0.9.0") Nothing)]
            evalRule (depsWith rows) ctx AllowIfRemediatesCve (pkg Nothing 0)
                >>= (`shouldBe` NoDecision "no advisory names this version as its fix")
        it "abstains when the version still sits inside another advisory's affected range" $ do
            let rows =
                    fixRows
                        <> [("thing", AdvisoryRange "GHSA-open-0002" Nothing (Just "0.5.0") Unbounded Nothing)]
            evalRule (depsWith rows) ctx AllowIfRemediatesCve (pkg Nothing 0)
                >>= (`shouldBe` NoDecision "fixes GHSA-fixed-0001 but is still affected by GHSA-open-0002")
        it "abstains when no advisory database is loaded" $
            evalRule inertRuleDeps ctx AllowIfRemediatesCve (pkg Nothing 0)
                >>= (`shouldBe` NoDecision "no advisory database is loaded")

    describe "evalRule (DenyIfCve)" $ do
        it "denies an affected version whose advisory meets the threshold, naming it" $
            evalRule (depsWith (affecting (Just 9.8) Nothing)) ctx (denyCveAt 8.0) (pkg Nothing 0)
                >>= (`shouldBe` Deny "affected by GHSA-affect-0001 (CVSS >= 8.0)")
        it "abstains when the affecting advisory is below the threshold" $
            evalRule (depsWith (affecting (Just 5.0) Nothing)) ctx (denyCveAt 8.0) (pkg Nothing 0)
                >>= (`shouldSatisfy` isNoDecision)
        it "denies an unscored advisory (fail-closed: npm malware carries no score)" $
            evalRule (depsWith (affecting Nothing Nothing)) ctx (denyCveAt 8.0) (pkg Nothing 0)
                >>= (`shouldSatisfy` isDeny)
        it "abstains when the version sits outside the affected range" $ do
            -- 1.0.0 is past this advisory's exclusive 1.0.0 fix, so unaffected.
            let rows = [("thing", AdvisoryRange "GHSA-affect-0002" (Just 9.9) (Just "0") (FixedBefore "1.0.0") Nothing)]
            evalRule (depsWith rows) ctx (denyCveAt 8.0) (pkg Nothing 0)
                >>= (`shouldSatisfy` isNoDecision)
        it "fails closed (Undecidable) when no advisory database is loaded" $
            decideWith inertRuleDeps [atDefaultPrecedence (denyCveAt 8.0)] (pkg Nothing 0)
                >>= (`shouldSatisfy` isUndecidable)
        it "fails open (skips) when configured onUnavailable=skip and no database is loaded" $
            decideWith inertRuleDeps [atDefaultPrecedence (DenyIfCve (DenyIfCveParams 8.0 FailNoDecision))] (pkg Nothing 0)
                >>= (`shouldSatisfy` isBlockedByDefault)

    describe "evalRule (DenyIfEpss)" $ do
        it "denies an affected version whose advisory meets the threshold, naming it" $
            evalRule (depsWith (affecting Nothing (Just 0.75))) ctx (denyEpssAt 0.5) (pkg Nothing 0)
                >>= (`shouldBe` Deny "affected by GHSA-affect-0001 (EPSS >= 0.5)")
        it "denies at the threshold exactly, which is where an at-or-above gate closes" $
            evalRule (depsWith (affecting Nothing (Just 0.5))) ctx (denyEpssAt 0.5) (pkg Nothing 0)
                >>= (`shouldSatisfy` isDeny)
        it "abstains when the affecting advisory scores below the threshold" $
            evalRule (depsWith (affecting Nothing (Just 0.1))) ctx (denyEpssAt 0.5) (pkg Nothing 0)
                >>= (`shouldSatisfy` isNoDecision)
        it "denies an advisory with no EPSS score (fail-closed: the comparison is unprovable)" $
            -- The npm malware feed carries no CVE alias for the feed to key on, so its
            -- advisories reach the rule unscored and must not slip the gate.
            evalRule (depsWith (affecting (Just 9.8) Nothing)) ctx (denyEpssAt 0.5) (pkg Nothing 0)
                >>= (`shouldSatisfy` isDeny)
        it "abstains when the version sits outside the affected range" $ do
            let rows = [("thing", AdvisoryRange "GHSA-affect-0002" Nothing (Just "0") (FixedBefore "1.0.0") (Just 0.99))]
            evalRule (depsWith rows) ctx (denyEpssAt 0.5) (pkg Nothing 0)
                >>= (`shouldSatisfy` isNoDecision)
        it "fails closed (Undecidable) when no advisory database is loaded" $
            decideWith inertRuleDeps [atDefaultPrecedence (denyEpssAt 0.5)] (pkg Nothing 0)
                >>= (`shouldSatisfy` isUndecidable)
        it "fails open (skips) when configured onUnavailable=skip and no database is loaded" $
            decideWith inertRuleDeps [atDefaultPrecedence (DenyIfEpss (DenyIfEpssParams 0.5 FailNoDecision))] (pkg Nothing 0)
                >>= (`shouldSatisfy` isBlockedByDefault)

    describe "deny precedence (DenyIfEpss)" $ do
        it "overrides the quarantine allow at default precedences, whatever the order" $ do
            let rs = [atDefaultPrecedence (AllowIfOlderThan (7 * nominalDay)), atDefaultPrecedence (denyEpssAt 0.5)]
                deps = depsWith (affecting Nothing (Just 0.75))
            decideWith deps rs (pkg Nothing 99) >>= \d -> blockedBy d `shouldBe` Just "DenyIfEpss"
            decideWith deps (reverse rs) (pkg Nothing 99) >>= \d -> blockedBy d `shouldBe` Just "DenyIfEpss"
        it "yields to an operator's identity pin, the documented escape hatch" $
            -- AllowByIdentity (250) outranks the advisory deny band (225), as it does for
            -- DenyIfCve: an operator who pins a version has decided it must ship.
            decideWith
                (depsWith (affecting Nothing (Just 0.99)))
                (map atDefaultPrecedence [AllowByIdentity "thing@1.0.0", denyEpssAt 0.5])
                (pkg Nothing 0)
                >>= \d -> admittedBy d `shouldBe` Just "AllowByIdentity"
        it "is outranked by an install-script deny, which keeps the last word" $
            decideWith
                (depsWith (affecting Nothing (Just 0.99)))
                (map atDefaultPrecedence [DenyInstallTimeExecution, denyEpssAt 0.5])
                (withInstallScripts (pkg Nothing 0))
                >>= \d -> blockedBy d `shouldBe` Just "DenyInstallTimeExecution"
        it "ties with DenyIfCve at their shared default, and the boot order breaks it by name" $
            -- Both fire on the same advisory. The earlier name takes the credit, so a
            -- decision never depends on the configured order.
            decideWith
                (depsWith (affecting (Just 9.8) (Just 0.99)))
                (map atDefaultPrecedence [denyEpssAt 0.5, denyCveAt 8.0])
                (pkg Nothing 0)
                >>= \d -> blockedBy d `shouldBe` Just "DenyIfCve"

    describe "cveIdsInReason -- recovering advisory ids for the denial audit line" $ do
        -- The deny reason 'denyVerdict' builds, asserted verbatim above. The audit layer reads
        -- the ids back from it, so a reword of either fails one of these.
        let denyReason = "affected by GHSA-affect-0001 (CVSS >= 8.0)"
        it "recovers the id a DenyIfCve denial named" $
            cveIdsInReason denyReason `shouldBe` ["GHSA-affect-0001"]
        it "recovers the id a DenyIfEpss denial named" $
            cveIdsInReason "affected by GHSA-affect-0001 (EPSS >= 0.5)" `shouldBe` ["GHSA-affect-0001"]
        it "recovers several ids" $
            cveIdsInReason "affected by CVE-2026-0001, GHSA-aaaa-bbbb-cccc (CVSS >= 7.0)"
                `shouldBe` ["CVE-2026-0001", "GHSA-aaaa-bbbb-cccc"]
        it "recovers them from the wrapped decision message the audit line carries" $
            -- The audit layer sees the rendered decision's wrapping, not the raw reason.
            cveIdsInReason ("thing@1.0.0 was denied by DenyIfCve: " <> denyReason)
                `shouldBe` ["GHSA-affect-0001"]
        it "yields nothing for a non-CVE denial" $ do
            cveIdsInReason "runs code on install: postinstall" `shouldBe` []
            cveIdsInReason "thing@1.0.0 was denied by DenyInstallTimeExecution: runs code on install"
                `shouldBe` []

    describe "PrecededRule" $ do
        it "exposes the precedence and rule it was built with" $ do
            -- The fields a config loader reads to patch a rule's precedence.
            let pr = PrecededRule 250 DenyInstallTimeExecution
            rulePrecedence pr `shouldBe` 250
            prRule pr `shouldBe` DenyInstallTimeExecution
        it "shows both fields" $
            show (PrecededRule 250 DenyInstallTimeExecution)
                `shouldBe` ("PrecededRule {rulePrecedence = 250, prRule = DenyInstallTimeExecution}" :: String)

    describe "defaultPrecedence" $ do
        it "ranks every deny default strictly above every allow default" $ do
            -- The out-of-the-box invariant: a matching deny overrides any allow.
            let allows = [AllowScope (mkScope "x"), AllowIfOlderThan 0, AllowByIdentity "x", AllowIfRemediatesCve]
            defaultPrecedence DenyInstallTimeExecution
                `shouldSatisfy` (\d -> all ((d >) . defaultPrecedence) allows)
        it "orders the allow band by explicitness: quarantine < fast lane < scope < identity" $
            ( defaultAllowIfOlderThanPrecedence
            , defaultAllowIfRemediatesCvePrecedence
            , defaultAllowScopePrecedence
            , defaultAllowByIdentityPrecedence
            )
                `shouldSatisfy` (\(q, f, s, i) -> q < f && f < s && s < i)
        it "atDefaultPrecedence pairs a rule with its type default" $
            atDefaultPrecedence DenyInstallTimeExecution
                `shouldBe` PrecededRule defaultDenyInstallTimeExecutionPrecedence DenyInstallTimeExecution

    describe "prepare" $ do
        it "attaches the fail-open resilience (and its breaker) to AllowIfRemediatesCve" $
            -- The one thing a reviewer must check on the remediation lane: an
            -- uncomputable lookup abstains (FailNoDecision) and never admits or 503s.
            prepare inertRuleDeps [atDefaultPrecedence AllowIfRemediatesCve] >>= \case
                [r] -> fmap resAlignment (prepResilience r) `shouldBe` Just FailNoDecision
                other -> expectationFailure ("expected one prepared rule, got " <> show (length other))
        it "prepares every pure built-in to run directly, with no resilience" $ do
            rules <-
                prepare
                    inertRuleDeps
                    ( map
                        atDefaultPrecedence
                        [ AllowScope (mkScope "myorg")
                        , AllowIfOlderThan (7 * nominalDay)
                        , AllowByIdentity "thing"
                        , DenyInstallTimeExecution
                        , DenyByIdentity "thing"
                        ]
                    )
            map (isJust . prepResilience) rules `shouldBe` replicate 5 False

    describe "bootOrder" $ do
        it "orders highest precedence first, then rule name ascending" $ do
            -- A shuffled configured set arranges into one total order: precedence
            -- descending, then name as the deterministic tiebreak.
            rules <-
                prepare
                    inertRuleDeps
                    [ at 100 (AllowIfOlderThan (7 * nominalDay))
                    , at 300 DenyInstallTimeExecution
                    , at 200 (AllowScope (mkScope "myorg"))
                    ]
            map prepName (bootOrder rules)
                `shouldBe` ["DenyInstallTimeExecution", "AllowScope", "AllowIfOlderThan"]
        it "breaks an equal-precedence tie by name ascending" $ do
            rules <-
                prepare
                    inertRuleDeps
                    [ at 200 (AllowScope (mkScope "myorg"))
                    , at 200 (AllowIfOlderThan (7 * nominalDay))
                    ]
            map prepName (bootOrder rules)
                `shouldBe` ["AllowIfOlderThan", "AllowScope"]

    describe "renderBootOrder" $ do
        it "emits one line per rule, in boot order, with each precedence" $ do
            rules <-
                prepare
                    inertRuleDeps
                    [ at 100 (AllowIfOlderThan (7 * nominalDay))
                    , at 300 DenyInstallTimeExecution
                    ]
            renderBootOrder rules
                `shouldBe` [ "rule 1: DenyInstallTimeExecution (precedence 300)"
                           , "rule 2: AllowIfOlderThan (precedence 100)"
                           ]
        it "is empty for an empty rule set" $
            prepare inertRuleDeps [] >>= \rules -> renderBootOrder rules `shouldBe` []

    describe "evalRules" $ do
        it "denies by default with no rules" $
            decide [] (pkg (Just "myorg") 99) >>= (`shouldBe` BlockedByDefault [])
        it "admits via the single matching allow rule" $
            decide [atDefaultPrecedence (AllowScope (mkScope "myorg"))] (pkg (Just "myorg") 0)
                >>= \d -> admittedBy d `shouldBe` Just "AllowScope"
        it "the higher-precedence allow wins among allows" $
            -- The version is too young for the age rule, but the scope rule matches.
            -- At default precedences the scope allow outranks it anyway.
            decide
                (map atDefaultPrecedence [AllowIfOlderThan (7 * nominalDay), AllowScope (mkScope "myorg")])
                (pkg (Just "myorg") 0)
                >>= \d -> admittedBy d `shouldBe` Just "AllowScope"
        it "a matching deny rule overrides an allow at default precedence, whatever the order" $ do
            let rs = map atDefaultPrecedence [AllowScope (mkScope "myorg"), DenyInstallTimeExecution]
                p = withInstallScripts (pkg (Just "myorg") 99)
            decide rs p >>= \d -> blockedBy d `shouldBe` Just "DenyInstallTimeExecution"
            decide (reverse rs) p >>= \d -> blockedBy d `shouldBe` Just "DenyInstallTimeExecution"
        it "resolves an equal-precedence allow-vs-deny tie by name, not by deny-priority" $ do
            -- Equal explicit precedence uses the rule name as its tiebreak.
            let rs = [at 300 (AllowScope (mkScope "myorg")), at 300 DenyInstallTimeExecution]
                p = withInstallScripts (pkg (Just "myorg") 99)
            decide rs p >>= \d -> admittedBy d `shouldBe` Just "AllowScope"
            decide (reverse rs) p >>= \d -> admittedBy d `shouldBe` Just "AllowScope"
        it "breaks an equal-precedence allow-vs-allow tie by name, regardless of order" $ do
            -- The boot order breaks an equal-precedence tie by the smallest ruleName, not by list
            -- position. "AllowIfOlderThan" sorts before "AllowScope", so it takes the credit.
            let allows =
                    [ at 150 (AllowScope (mkScope "myorg"))
                    , at 150 (AllowIfOlderThan (7 * nominalDay))
                    ]
                p = pkg (Just "myorg") 30
            decide allows p >>= \d -> admittedBy d `shouldBe` Just "AllowIfOlderThan"
            decide (reverse allows) p >>= \d -> admittedBy d `shouldBe` Just "AllowIfOlderThan"
        it "an operator-elevated allow outranks a higher-default deny" $
            -- The operator lifts the scope allow above the deny's default precedence,
            -- so the engine admits a trusted internal scope despite its install scripts.
            decide
                [ at (defaultDenyInstallTimeExecutionPrecedence + 1) (AllowScope (mkScope "myorg"))
                , atDefaultPrecedence DenyInstallTimeExecution
                ]
                (withInstallScripts (pkg (Just "myorg") 99))
                >>= \d -> admittedBy d `shouldBe` Just "AllowScope"
        it "DenyByIdentity outranks an AllowScope for the same name" $ do
            -- Precedence test: DenyByIdentity (400) outranks AllowScope (200)
            let rs = map atDefaultPrecedence [AllowScope (mkScope "myorg"), DenyByIdentity "@myorg/thing"]
                p = pkg (Just "myorg") 0
            decide rs p >>= \d -> blockedBy d `shouldBe` Just "DenyByIdentity"
            decide (reverse rs) p >>= \d -> blockedBy d `shouldBe` Just "DenyByIdentity"
        it "the remediation fast lane admits a young fix ahead of the quarantine" $
            -- The whole point of the rule: the engine admits a security patch too young
            -- for min-age because an advisory names it as the exact fix.
            decideWith
                (depsWith fixRows)
                (map atDefaultPrecedence [AllowIfOlderThan (7 * nominalDay), AllowIfRemediatesCve])
                (pkg Nothing 0)
                >>= \d -> admittedBy d `shouldBe` Just "AllowIfRemediatesCve"
        it "a failing advisory lookup abstains: the quarantine still governs, and nothing turns Undecidable" $ do
            -- The deliberate failure asymmetry: an unconfirmable remediation costs the fix its fast
            -- lane, never availability and never an admission.
            let broken =
                    RuleDeps
                        { rdWithCveLookup = \_ -> throwIO (TestContractEscape "advisory database exploded")
                        , rdCurrentAdvisoryEtag = pure Nothing
                        , rdBreakerReporter = noBreakerReporter
                        , rdFaultReporter = noFaultReporter
                        }
                policy = map atDefaultPrecedence [AllowIfOlderThan (7 * nominalDay), AllowIfRemediatesCve]
            -- An old enough version still rides the ordinary allow.
            decideWith broken policy (pkg Nothing 30)
                >>= \d -> admittedBy d `shouldBe` Just "AllowIfOlderThan"
            -- A young version is denied by default, not fail-closed 'Undecidable'.
            decideWith broken policy (pkg Nothing 1) >>= \case
                BlockedByDefault _ -> pass
                other -> expectationFailure ("expected BlockedByDefault, got " <> show other)
        it "denies by default when every rule is non-decisive, collecting each reason in boot order" $
            -- The audit trail carries each non-decisive rule's reason in boot order, highest
            -- precedence first: AllowScope (200) then AllowIfOlderThan (100).
            decide
                (map atDefaultPrecedence [AllowIfOlderThan (7 * nominalDay), AllowScope (mkScope "myorg")])
                (pkg (Just "other") 1)
                >>= \case
                    BlockedByDefault reasons ->
                        reasons
                            `shouldBe` [ "scope is not the allow-listed @myorg"
                                       , "published only 1 day ago, minimum age is 7 days"
                                       ]
                    other -> expectationFailure ("expected BlockedByDefault, got " <> show other)

    describe "renderDuration" $ do
        it "renders a whole unit as that unit alone" $ do
            renderDuration 604800 `shouldBe` "7 days"
            renderDuration 86400 `shouldBe` "1 day"
            renderDuration 60 `shouldBe` "1 minute"
        it "renders the two most-significant non-zero units" $ do
            renderDuration 90 `shouldBe` "1 minute 30 seconds"
            renderDuration 3661 `shouldBe` "1 hour 1 minute"
            renderDuration 86700 `shouldBe` "1 day 5 minutes"
        it "distinguishes a value just short of a threshold from the threshold" $ do
            renderDuration 89 `shouldBe` "1 minute 29 seconds"
            renderDuration 90 `shouldBe` "1 minute 30 seconds"
        it "pluralises only non-unit counts" $ do
            renderDuration 1 `shouldBe` "1 second"
            renderDuration 2 `shouldBe` "2 seconds"
        it "renders a zero or sub-second duration as zero seconds" $ do
            renderDuration 0 `shouldBe` "0 seconds"
            renderDuration 0.4 `shouldBe` "0 seconds"
        it "clamps a negative duration to zero" $
            renderDuration (negate 5) `shouldBe` "0 seconds"

    describe "properties" $ do
        it "an empty rule set always denies by default" $
            hedgehog $ do
                mScope <- forAll (Gen.maybe genScope)
                ageDays <- forAll genAgeDays
                d <- liftIO (decide [] (pkg mScope ageDays))
                d === BlockedByDefault []

        it "every rule non-decisive yields deny-by-default" $
            hedgehog $ do
                -- A non-matching scope, a too-young age, and no install scripts leave every rule
                -- non-decisive, whatever the precedences.
                scopeTxt <- forAll genScope
                otherTxt <- forAll (Gen.filter (/= scopeTxt) genScope)
                precs <- forAll (Gen.list (Range.singleton 3) genPrecedence)
                let rules =
                        zipWith
                            PrecededRule
                            precs
                            [AllowScope (mkScope scopeTxt), AllowIfOlderThan (7 * nominalDay), DenyInstallTimeExecution]
                liftIO (decide rules (pkg (Just otherTxt) 1)) >>= \case
                    BlockedByDefault _ -> H.success
                    other -> H.annotateShow other >> H.failure

        it "the highest-precedence deny wins over any lower allow" $
            hedgehog $ do
                scopeTxt <- forAll genScope
                ageDays <- forAll genAgeDays
                allowPrec <- forAll genPrecedence
                denyPrec <- forAll (Gen.int (Range.linear (allowPrec + 1) (allowPrec + 1000)))
                let rules = [at allowPrec (AllowScope (mkScope scopeTxt)), at denyPrec DenyInstallTimeExecution]
                    p = withInstallScripts (pkg (Just scopeTxt) ageDays)
                d <- liftIO (decide rules p)
                blockedBy d === Just "DenyInstallTimeExecution"

        it "an operator-elevated allow outranks a lower-precedence deny" $
            hedgehog $ do
                scopeTxt <- forAll genScope
                ageDays <- forAll genAgeDays
                denyPrec <- forAll genPrecedence
                allowPrec <- forAll (Gen.int (Range.linear (denyPrec + 1) (denyPrec + 1000)))
                let rules = [at allowPrec (AllowScope (mkScope scopeTxt)), at denyPrec DenyInstallTimeExecution]
                    p = withInstallScripts (pkg (Just scopeTxt) ageDays)
                d <- liftIO (decide rules p)
                admittedBy d === Just "AllowScope"

        it "the decision is invariant under shuffling the rule list" $
            hedgehog $ do
                -- Colliding precedences exercise deterministic rule-name tiebreaks.
                scopeTxt <- forAll genScope
                ageDays <- forAll genAgeDays
                n <- forAll (Gen.int (Range.linear 0 6))
                rules <- forAll (Gen.list (Range.singleton n) (genFiringRule scopeTxt))
                precs <- forAll (Gen.list (Range.singleton n) genPrecedence)
                let preceded = zipWith PrecededRule precs rules
                    p = withInstallScripts (pkg (Just scopeTxt) ageDays)
                perm <- forAll (Gen.shuffle preceded)
                original <- liftIO (decide preceded p)
                shuffled <- liftIO (decide perm p)
                canonical original === canonical shuffled

        it "the install-script deny always wins at default precedences" $
            hedgehog $ do
                scopeTxt <- forAll genScope
                ageDays <- forAll genAgeDays
                let rules = map atDefaultPrecedence [AllowScope (mkScope scopeTxt), DenyInstallTimeExecution]
                    p = withInstallScripts (pkg (Just scopeTxt) ageDays)
                d <- liftIO (decide rules p)
                blockedBy d === Just "DenyInstallTimeExecution"

    describe "renderDecision" $ do
        let pd = pkg (Just "myorg") 0
        it "renders an admission naming the rule and its reason" $
            renderDecision pd (Admitted "AllowScope" "scope @myorg is allow-listed")
                `shouldSatisfy` (\t -> T.isInfixOf "AllowScope" t && T.isInfixOf "approved" t)
        it "renders a block naming the rule and its reason" $
            renderDecision pd (Blocked "DenyAdvisory" "affected by an advisory")
                `shouldSatisfy` (\t -> T.isInfixOf "DenyAdvisory" t && T.isInfixOf "affected by an advisory" t)
        it "renders a deny-by-default explaining no rule allowed it" $
            renderDecision pd (BlockedByDefault ["scope is not the allow-listed @myorg"])
                `shouldSatisfy` (\t -> T.isInfixOf "no rule allowed it" t && T.isInfixOf "allow-listed" t)
        it "renders an undecidable outcome explaining it could not be evaluated" $
            renderDecision pd (Undecidable (WillResolve Nothing) "the advisory source is down")
                `shouldSatisfy` (\t -> T.isInfixOf "could not be evaluated" t && T.isInfixOf "advisory source is down" t)
