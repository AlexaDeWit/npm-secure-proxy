-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Core.Package.IntegritySpec (spec) where

import Prelude hiding (universe)

import Data.Universe.Class (Universe (..))
import Test.Hspec

import Ecluse.Core.Package (
    Artifact (artFilename),
    HashAlg (Blake2b, MD5, SHA1, SHA256, SHA384, SHA512, SRI),
    isComputable,
 )
import Ecluse.Core.Package.Integrity (
    VersionIntegrity (BelowFloor, MeetsFloor, NoIntegrity),
    assertedAlg,
    classifyArtifacts,
    meetsFloor,
    mkMinIntegrity,
    mkMinTrustedIntegrity,
    parseMinIntegrity,
    parseMinTrustedIntegrity,
    partitionByFloor,
    unMinIntegrity,
    unMinTrustedIntegrity,
 )
import Ecluse.Test.Package (
    artifactWith,
    defaultMinIntegrity,
    defaultMinTrustedIntegrity,
    unsafeHash,
    validSha1,
    validSha256,
    validSha256Sri,
    validSha384Sri,
    validSha512Sri,
 )
import Ecluse.Test.Support (expectRight)

spec :: Spec
spec = do
    describe "the worker verifies what the public floor admits (the #409 invariant)" $ do
        it "every algorithm that meets the default public floor is computable" $
            -- The floor admits by algorithm authority ('meetsFloor') and the worker verifies by
            -- computation ('isComputable'), so the computable set must cover the floor-clearing
            -- set. Otherwise the mirror enqueues an admitted public artifact and then drops it
            -- permanently.
            [alg | alg <- universe, meetsFloor defaultMinIntegrity alg, not (isComputable alg)]
                `shouldBe` []

        it "the bare SRI wrapper neither clears the floor nor is computable (it names no algorithm)" $ do
            -- The one constructor both sides exclude: SRI is a wrapper that
            -- 'assertedAlg' resolves, never a floor candidate or a compute target.
            meetsFloor defaultMinIntegrity SRI `shouldBe` False
            isComputable SRI `shouldBe` False

    describe "HashAlg Ord" $ do
        it "uses the explicit checksum-authority order, not constructor order" $ do
            let ranks = [SRI, MD5, SHA1, SHA256, SHA384, Blake2b, SHA512]
            and (zipWith (<) ranks (drop 1 ranks)) `shouldBe` True

    describe "assertedAlg" $ do
        it "reads a plain tag directly" $
            assertedAlg (unsafeHash SHA256 validSha256) `shouldBe` Just SHA256

        it "resolves an SRI to its inner algorithm (sha512, sha384, sha256)" $ do
            assertedAlg (unsafeHash SRI validSha512Sri) `shouldBe` Just SHA512
            assertedAlg (unsafeHash SRI validSha384Sri) `shouldBe` Just SHA384
            assertedAlg (unsafeHash SRI validSha256Sri) `shouldBe` Just SHA256

    describe "meetsFloor" $ do
        it "admits an algorithm at or above the default (SHA-256) floor" $ do
            meetsFloor defaultMinIntegrity SHA256 `shouldBe` True
            meetsFloor defaultMinIntegrity SHA384 `shouldBe` True
            meetsFloor defaultMinIntegrity SHA512 `shouldBe` True
            meetsFloor defaultMinIntegrity Blake2b `shouldBe` True

        it "rejects SHA-384 and Blake2b when the floor is raised to SHA-512" $ do
            sha512Floor <- expectRight (mkMinIntegrity SHA512)
            meetsFloor sha512Floor SHA384 `shouldBe` False
            meetsFloor sha512Floor Blake2b `shouldBe` False

        it "rejects an algorithm below the default floor (SHA-1, MD5)" $ do
            meetsFloor defaultMinIntegrity SHA1 `shouldBe` False
            meetsFloor defaultMinIntegrity MD5 `shouldBe` False

        it "rejects SHA-256 when the floor is raised to SHA-512" $ do
            sha512Floor <- expectRight (mkMinIntegrity SHA512)
            meetsFloor sha512Floor SHA256 `shouldBe` False
            meetsFloor sha512Floor SHA512 `shouldBe` True

    describe "mkMinIntegrity / parseMinIntegrity" $ do
        it "defaults to SHA-256" $
            unMinIntegrity defaultMinIntegrity `shouldBe` SHA256

        it "accepts an algorithm at or above the hard SHA-256 floor" $ do
            (unMinIntegrity <$> mkMinIntegrity SHA256) `shouldBe` Right SHA256
            (unMinIntegrity <$> mkMinIntegrity SHA512) `shouldBe` Right SHA512
            (unMinIntegrity <$> mkMinIntegrity Blake2b) `shouldBe` Right Blake2b

        it "rejects a floor below SHA-256 with a precise message (a sub-floor is a config error)" $ do
            -- Compared by value rather than by isLeft alone, so the case pins the
            -- operator-facing message and the rejected algorithm's rendered name.
            mkMinIntegrity SHA1 `shouldBe` Left "the minimum public integrity algorithm must be SHA-256 or stronger, not sha1"
            mkMinIntegrity MD5 `shouldBe` Left "the minimum public integrity algorithm must be SHA-256 or stronger, not md5"
            mkMinIntegrity SRI `shouldBe` Left "the minimum public integrity algorithm must be SHA-256 or stronger, not sri"

        it "parses algorithm names, case- and separator-insensitively" $ do
            (unMinIntegrity <$> parseMinIntegrity "sha256") `shouldBe` Right SHA256
            (unMinIntegrity <$> parseMinIntegrity "sha384") `shouldBe` Right SHA384
            (unMinIntegrity <$> parseMinIntegrity "SHA-384") `shouldBe` Right SHA384
            (unMinIntegrity <$> parseMinIntegrity "SHA-512") `shouldBe` Right SHA512
            (unMinIntegrity <$> parseMinIntegrity "blake2b") `shouldBe` Right Blake2b

        it "rejects a below-floor name and an unknown name with distinct messages" $ do
            -- A recognised but weak name fails the floor. An unrecognised name fails the parse.
            -- The distinct texts tell the operator which mistake they made.
            parseMinIntegrity "sha1" `shouldBe` Left "the minimum public integrity algorithm must be SHA-256 or stronger, not sha1"
            parseMinIntegrity "md5" `shouldBe` Left "the minimum public integrity algorithm must be SHA-256 or stronger, not md5"
            parseMinIntegrity "frobnicate" `shouldBe` Left "unknown integrity algorithm: frobnicate"

    describe "mkMinTrustedIntegrity / parseMinTrustedIntegrity (the loosenable trusted floor)" $ do
        it "defaults to SHA-256, the same secure default as the public floor" $
            unMinTrustedIntegrity defaultMinTrustedIntegrity `shouldBe` SHA256

        it "accepts any concrete algorithm -- including the broken SHA-1 and MD5 (loosenable)" $ do
            -- The trusted floor has no hard minimum: an operator may loosen it below
            -- SHA-256 for a legacy private mirror, where trust substitutes for strength.
            (unMinTrustedIntegrity <$> mkMinTrustedIntegrity SHA1) `shouldBe` Right SHA1
            (unMinTrustedIntegrity <$> mkMinTrustedIntegrity MD5) `shouldBe` Right MD5
            (unMinTrustedIntegrity <$> mkMinTrustedIntegrity SHA256) `shouldBe` Right SHA256
            (unMinTrustedIntegrity <$> mkMinTrustedIntegrity SHA512) `shouldBe` Right SHA512

        it "rejects the bare SRI wrapper (it names no concrete algorithm)" $
            mkMinTrustedIntegrity SRI
                `shouldBe` Left "the minimum trusted integrity algorithm must name a concrete algorithm, not a bare SRI"

        it "parses sub-SHA-256 names (sha1, md5) that the public floor would reject" $ do
            (unMinTrustedIntegrity <$> parseMinTrustedIntegrity "sha1") `shouldBe` Right SHA1
            (unMinTrustedIntegrity <$> parseMinTrustedIntegrity "md5") `shouldBe` Right MD5
            (unMinTrustedIntegrity <$> parseMinTrustedIntegrity "SHA-256") `shouldBe` Right SHA256

        it "rejects an unknown algorithm name" $
            parseMinTrustedIntegrity "frobnicate" `shouldBe` Left "unknown integrity algorithm: frobnicate"

    describe "meetsFloor / classifyArtifacts over the trusted floor (one ranking backs both floors)" $ do
        it "a loosened (SHA-1) trusted floor admits SHA-1 but not MD5" $ do
            sha1Floor <- expectRight (mkMinTrustedIntegrity SHA1)
            meetsFloor sha1Floor SHA1 `shouldBe` True
            meetsFloor sha1Floor SHA256 `shouldBe` True
            meetsFloor sha1Floor MD5 `shouldBe` False

        it "the default (SHA-256) trusted floor rejects a SHA-1 digest" $
            meetsFloor defaultMinTrustedIntegrity SHA1 `shouldBe` False

        it "classifies a SHA-1-only version BelowFloor by default, MeetsFloor when loosened to SHA-1" $ do
            sha1Floor <- expectRight (mkMinTrustedIntegrity SHA1)
            classifyArtifacts defaultMinTrustedIntegrity (artifactWith [unsafeHash SHA1 validSha1] :| [])
                `shouldBe` BelowFloor
            classifyArtifacts sha1Floor (artifactWith [unsafeHash SHA1 validSha1] :| [])
                `shouldBe` MeetsFloor

        it "a hashless version is NoIntegrity under any trusted floor (no digest can meet a floor)" $ do
            sha1Floor <- expectRight (mkMinTrustedIntegrity SHA1)
            classifyArtifacts defaultMinTrustedIntegrity (artifactWith [] :| []) `shouldBe` NoIntegrity
            classifyArtifacts sha1Floor (artifactWith [] :| []) `shouldBe` NoIntegrity

    describe "classifyArtifacts" $ do
        let classify floorAlg hs =
                classifyArtifacts floorAlg (artifactWith hs :| [])

        it "MeetsFloor when a digest clears the floor (SHA-256, sha512-SRI)" $ do
            classify defaultMinIntegrity [unsafeHash SHA256 validSha256] `shouldBe` MeetsFloor
            classify defaultMinIntegrity [unsafeHash SRI validSha512Sri] `shouldBe` MeetsFloor

        it "MeetsFloor when the only digest is a sha384 SRI (clears the SHA-256 floor)" $
            classify defaultMinIntegrity [unsafeHash SRI validSha384Sri] `shouldBe` MeetsFloor

        it "MeetsFloor when a strong digest sits beside a weak one" $
            classify defaultMinIntegrity [unsafeHash SHA1 validSha1, unsafeHash SHA256 validSha256] `shouldBe` MeetsFloor

        it "BelowFloor for a SHA-1-only version (a digest, but too weak)" $
            classify defaultMinIntegrity [unsafeHash SHA1 validSha1] `shouldBe` BelowFloor

        it "NoIntegrity for a version carrying no digest at all" $
            classify defaultMinIntegrity [] `shouldBe` NoIntegrity

        it "BelowFloor for a SHA-256-only version when the floor is SHA-512" $ do
            sha512Floor <- expectRight (mkMinIntegrity SHA512)
            classify sha512Floor [unsafeHash SHA256 validSha256] `shouldBe` BelowFloor

    describe "partitionByFloor (the per-artifact gate)" $ do
        let named filename hs = (artifactWith hs){artFilename = filename}
            partition :: NonEmpty Artifact -> Either VersionIntegrity (NonEmpty Text)
            partition arts = fmap (fmap artFilename) (partitionByFloor defaultMinIntegrity arts)

        it "keeps the files that clear the floor and drops the ones that do not" $
            -- A release loses only the files that cannot be tied to a tamper-evident
            -- fingerprint, rather than disappearing whole.
            partition (named "ok.whl" [unsafeHash SHA256 validSha256] :| [named "legacy.tar.gz" [unsafeHash SHA1 validSha1]])
                `shouldBe` Right ("ok.whl" :| [])

        it "keeps every file when every file clears the floor" $
            partition (named "a.whl" [unsafeHash SHA256 validSha256] :| [named "b.whl" [unsafeHash SRI validSha512Sri]])
                `shouldBe` Right ("a.whl" :| ["b.whl"])

        it "reports BelowFloor when no file clears it but some carry a digest" $
            partition (named "legacy.tar.gz" [unsafeHash SHA1 validSha1] :| [])
                `shouldBe` Left BelowFloor

        it "reports NoIntegrity when no file carries a digest at all" $
            partition (named "bare.whl" [] :| [named "also-bare.tar.gz" []])
                `shouldBe` Left NoIntegrity

        it "reports BelowFloor when a digest-carrying file sits beside a hashless one" $
            partition (named "legacy.tar.gz" [unsafeHash SHA1 validSha1] :| [named "bare.whl" []])
                `shouldBe` Left BelowFloor

        it "either keeps or drops a singleton entire, matching the whole-version verdict" $ do
            -- npm's artifact set is always a singleton, so the partition is exactly the
            -- classification it replaces and npm's behaviour does not move.
            partition (named "one.tgz" [unsafeHash SHA256 validSha256] :| []) `shouldBe` Right ("one.tgz" :| [])
            partition (named "one.tgz" [unsafeHash SHA1 validSha1] :| []) `shouldBe` Left BelowFloor
