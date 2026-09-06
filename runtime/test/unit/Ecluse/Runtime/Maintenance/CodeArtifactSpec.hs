-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

module Ecluse.Runtime.Maintenance.CodeArtifactSpec (spec) where

import Data.Text qualified as T
import Lens.Micro ((.~), (?~), (^.))
import Test.Hspec

import Amazonka qualified as AWS
import Amazonka.Auth (fromKeys)
import Amazonka.CodeArtifact qualified as CA
import Amazonka.CodeArtifact.Lens qualified as CAL

import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.Fault (TransportCause (TransportProtocol), tfDetail, transportFault)
import Ecluse.Core.Package (PackageName, mkPackageName, renderPackageName)
import Ecluse.Core.Registry.Maintenance (
    CompletionNotion (CompletesOnCall),
    ConsentVerdict (ConsentGranted, ConsentWithheld),
    DeleteCeiling (AtMost),
    NameAlphabet,
    RefillPosture (RefillPermitted),
    RetryAdvice (RetryFutile),
    StoreClass (StoreDestroyable, StorePreserved),
    StoreCursor (..),
    StoreFacts (..),
    StoreFault (..),
    StoreMaintenance (..),
    StoredVersion (..),
    VersionOutcome (VersionRefused, VersionRemoved, VersionUnreached),
    VersionPresence (VersionServed),
    collectPages,
    mkNameAlphabet,
    refusalCode,
    renderNamePrefix,
 )
import Ecluse.Core.Version (Version, mkVersion)
import Ecluse.Runtime.Maintenance.CodeArtifact (
    ControlPlane (..),
    maintenanceFor,
    maintenanceForEnv,
 )
import Ecluse.Runtime.Maintenance.CodeArtifact.Decide (
    CodeArtifactStore (..),
    codeArtifactFormat,
    consentTagKey,
    consentTagValue,
    cursorTagKey,
 )
import Ecluse.Test.Maintenance (unwiredRead, withBucket)

{- | The CodeArtifact handle's facts and the sequencing around its calls, driven over 'ControlPlane'
answers built from @amazonka@'s own types. Each decision is covered in "Ecluse.Runtime.Maintenance.CodeArtifact.DecideSpec".
-}
spec :: Spec
spec = maybe noNpmFormat handleCases npmStore

noNpmFormat :: Spec
noNpmFormat = it "has a CodeArtifact format for npm" $ expectationFailure "npm resolved to no CodeArtifact format"

handleCases :: CodeArtifactStore -> Spec
handleCases store = do
    factCases store
    enumerationCases store
    deleteCases store
    consentCases store
    classificationCases store
    cursorCases store

factCases :: CodeArtifactStore -> Spec
factCases store = describe "the CodeArtifact handle's standing facts" $ do
    it "names the backend the Dredger's boot line records" $ do
        facts <- factsFor store
        factBackend facts `shouldBe` "codeArtifact"

    it "accepts 100 versions per destructive call" $ do
        facts <- factsFor store
        factDeleteCeiling facts `shouldBe` AtMost 100

    it "records that CodeArtifact re-admits a version published again after a delete" $ do
        facts <- factsFor store
        factRefill facts `shouldBe` RefillPermitted

    it "records that the delete is done by the time the call answers" $ do
        facts <- factsFor store
        factCompletion facts `shouldBe` CompletesOnCall

    it "carries the alphabet it was built with, which is the mount ecosystem's own" $ do
        facts <- factsFor store
        factNameAlphabet facts `shouldBe` testAlphabet

    it "reads a manifest through the read it was handed, never through the control plane" $ do
        outcome <- readStoreManifest (handleOver store inertPlane) aPackage
        fmap detailOf (leftToMaybe outcome) `shouldBe` Just "the spec wired no manifest read"

    it "offers no rehearsal, because CodeArtifact has no call that reports one" $ do
        handle <- handleFor store
        isJust (rehearseDelete handle) `shouldBe` False

enumerationCases :: CodeArtifactStore -> Spec
enumerationCases store = describe "the handle's paged enumerations" $ do
    it "pages the package listing to exhaustion, sending back the token the last page returned" $ do
        tokens <- newIORef []
        answer <- answersFrom [packagesPage (Just "p2") ["lodash"], packagesPage Nothing ["axios"]]
        let plane = inertPlane{cpListPackages = \request -> record tokens (request ^. CAL.listPackages_nextToken) >> answer}
        outcome <- listBucket store plane ""
        fmap (map renderPackageName) outcome `shouldBe` Right ["lodash", "axios"]
        readIORef tokens `shouldReturn` [Nothing, Just "p2"]

    it "reads a package page carrying no packages field as an empty page" $ do
        let plane = inertPlane{cpListPackages = \_ -> pure (Right (CA.newListPackagesResponse 200))}
        listBucket store plane "" `shouldReturn` Right []

    it "sends the bucket as the listing's own package prefix, so the store does the filtering" $ do
        prefixes <- newIORef []
        answer <- answersFrom [packagesPage Nothing ["lodash"]]
        let plane = inertPlane{cpListPackages = \request -> record prefixes (request ^. CAL.listPackages_packagePrefix) >> answer}
        _ <- listBucket store plane "l"
        readIORef prefixes `shouldReturn` [Just "l"]

    it "sends no prefix at all for the bucket that covers the whole store" $ do
        prefixes <- newIORef []
        answer <- answersFrom [packagesPage Nothing ["lodash"]]
        let plane = inertPlane{cpListPackages = \request -> record prefixes (request ^. CAL.listPackages_packagePrefix) >> answer}
        _ <- listBucket store plane ""
        readIORef prefixes `shouldReturn` [Nothing]

    it "pages a package's versions to exhaustion, sending back the token the last page returned" $ do
        tokens <- newIORef []
        answer <- answersFrom [versionsPage (Just "v2") ["1.0.0"], versionsPage Nothing ["1.1.0"]]
        let plane = inertPlane{cpListVersions = \request -> record tokens (request ^. CAL.listPackageVersions_nextToken) >> answer}
        outcome <- enumerateVersions (handleOver store plane) aPackage
        outcome `shouldBe` Right [served "1.0.0", served "1.1.0"]
        readIORef tokens `shouldReturn` [Nothing, Just "v2"]

    it "reads a version page carrying no versions field as an empty page" $ do
        let plane = inertPlane{cpListVersions = \_ -> pure (Right (CA.newListPackageVersionsResponse 200))}
        enumerateVersions (handleOver store plane) aPackage `shouldReturn` Right []

deleteCases :: CodeArtifactStore -> Spec
deleteCases store = describe "the handle's chunked delete" $ do
    it "splits 101 versions into a call of 100 and a call of 1, and reports one outcome each" $ do
        sizes <- newIORef []
        let plane =
                inertPlane
                    { cpDeleteVersions = \request -> do
                        let submitted = request ^. CAL.deletePackageVersions_versions
                        record sizes (length submitted)
                        pure (Right (allRemoved submitted))
                    }
        outcomes <- deleteVersions (handleOver store plane) aPackage (versionRun 101)
        readIORef sizes `shouldReturn` [100, 1]
        map snd outcomes `shouldBe` replicate 101 VersionRemoved

    it "refuses a version the store answered for neither way, never reports it removed" $ do
        let plane = inertPlane{cpDeleteVersions = \_ -> pure (Right (CA.newDeletePackageVersionsResponse 200))}
        outcomes <- deleteVersions (handleOver store plane) aPackage (versionRun 2)
        map (refusalCodeOf . snd) outcomes `shouldBe` replicate 2 (Just "UNREPORTED")

    it "stops at the first faulted chunk and marks every submitted version unreached" $ do
        calls <- newIORef (0 :: Int)
        let plane = inertPlane{cpDeleteVersions = \_ -> modifyIORef' calls (+ 1) >> pure (Left storeUnreachable)}
        outcomes <- deleteVersions (handleOver store plane) aPackage (versionRun 101)
        readIORef calls `shouldReturn` 1
        map snd outcomes `shouldBe` replicate 101 (VersionUnreached storeUnreachable)

consentCases :: CodeArtifactStore -> Spec
consentCases store = describe "the handle's consent read" $ do
    it "describes the repository before it reads the tags, because a tag read is addressed by ARN" $ do
        calls <- newIORef []
        verdict <- consentUnder store calls (Right describedWithArn) (Right (taggedWith [markerTag]))
        readIORef calls `shouldReturn` ["describe", "tags"]
        verdict `shouldBe` Right ConsentGranted

    it "withholds consent from a repository carrying no marker tag" $ do
        calls <- newIORef []
        verdict <- consentUnder store calls (Right describedWithArn) (Right (taggedWith []))
        verdict `shouldSatisfy` either (const False) withheld

    it "reports a describe that did not land, and reads no tags after it" $ do
        calls <- newIORef []
        verdict <- consentUnder store calls (Left storeUnreachable) (Right (taggedWith [markerTag]))
        verdict `shouldBe` Left storeUnreachable
        readIORef calls `shouldReturn` ["describe"]

    it "refuses a description carrying no ARN rather than read tags off an invented one" $ do
        calls <- newIORef []
        verdict <- consentUnder store calls (Right describedWithoutArn) (Right (taggedWith [markerTag]))
        first detailOf verdict `shouldBe` Left "the store described the repository without an ARN"
        readIORef calls `shouldReturn` ["describe"]

classificationCases :: CodeArtifactStore -> Spec
classificationCases store = describe "the handle's store classification" $ do
    it "classifies a repository holding only what was published to it as destroyable" $
        classifyUnder store (Right describedWithArn) `shouldReturn` Right StoreDestroyable

    it "names the upstream that would serve a deleted version again" $ do
        verdict <- classifyUnder store (Right (describing routedDescription))
        verdict `shouldSatisfy` either (const False) (preservedNaming "shared")

    it "reports a describe that did not land" $
        classifyUnder store (Left storeUnreachable) `shouldReturn` Left storeUnreachable

    it "refuses a response describing no repository rather than invent a verdict for one" $ do
        verdict <- classifyUnder store (Right (CA.newDescribeRepositoryResponse 200))
        first detailOf verdict `shouldBe` Left "the store described no repository"

cursorCases :: CodeArtifactStore -> Spec
cursorCases store = describe "the handle's walk cursor" $ do
    it "offers one, because a repository tag is somewhere to keep it" $
        isJust (storeCursor (handleOver store inertPlane)) `shouldBe` True

    it "reads back the bucket the cursor tag records, describing the repository first" $ do
        calls <- newIORef []
        let plane =
                inertPlane
                    { cpDescribeRepository = \_ -> record calls "describe" >> pure (Right describedWithArn)
                    , cpListTags = \_ -> record calls "tags" >> pure (Right (taggedWith [markerTag, cursorTag "l"]))
                    }
        withCursor store plane $ \cursor -> do
            outcome <- readCursor cursor
            fmap (fmap renderNamePrefix) outcome `shouldBe` Right (Just "l")
            readIORef calls `shouldReturn` (["describe", "tags"] :: [Text])

    it "reads no cursor from a repository carrying the consent tag alone" $ do
        let plane =
                inertPlane
                    { cpDescribeRepository = \_ -> pure (Right describedWithArn)
                    , cpListTags = \_ -> pure (Right (taggedWith [markerTag]))
                    }
        withCursor store plane $ \cursor -> readCursor cursor `shouldReturn` Right Nothing

    it "writes exactly the one cursor key, so the consent tag stays out of its reach" $ do
        written <- newIORef []
        let plane =
                inertPlane
                    { cpDescribeRepository = \_ -> pure (Right describedWithArn)
                    , cpTagResource = \request -> do
                        record written (map (^. CAL.tag_key) (request ^. CAL.tagResource_tags))
                        pure (Right (CA.newTagResourceResponse 200))
                    }
        withBucket "l" $ \completed -> withCursor store plane $ \cursor -> do
            writeCursor cursor completed `shouldReturn` Right ()
            readIORef written `shouldReturn` [[cursorTagKey Npm]]
            cursorTagKey Npm `shouldNotBe` consentTagKey

    it "clears the walk by removing that one key and no other" $ do
        removed <- newIORef []
        let plane =
                inertPlane
                    { cpDescribeRepository = \_ -> pure (Right describedWithArn)
                    , cpUntagResource = \request -> do
                        record removed (request ^. CAL.untagResource_tagKeys)
                        pure (Right (CA.newUntagResourceResponse 200))
                    }
        withCursor store plane $ \cursor -> do
            clearCursor cursor `shouldReturn` Right ()
            readIORef removed `shouldReturn` [[cursorTagKey Npm]]

    it "reports a describe that did not land, and writes nothing after it" $ do
        let plane = inertPlane{cpDescribeRepository = \_ -> pure (Left storeUnreachable)}
        withBucket "l" $ \completed -> withCursor store plane $ \cursor ->
            writeCursor cursor completed `shouldReturn` Left storeUnreachable

    it "refuses a description carrying no ARN rather than address a tag call to an invented one" $ do
        let plane = inertPlane{cpDescribeRepository = \_ -> pure (Right describedWithoutArn)}
        withCursor store plane $ \cursor ->
            first detailOf <$> readCursor cursor
                `shouldReturn` Left "the store described the repository without an ARN"

    it "reports a tag read that did not land" $ do
        let plane =
                inertPlane
                    { cpDescribeRepository = \_ -> pure (Right describedWithArn)
                    , cpListTags = \_ -> pure (Left storeUnreachable)
                    }
        withCursor store plane $ \cursor -> readCursor cursor `shouldReturn` Left storeUnreachable

    it "reports a cursor write that did not land" $ do
        let plane =
                inertPlane
                    { cpDescribeRepository = \_ -> pure (Right describedWithArn)
                    , cpTagResource = \_ -> pure (Left storeUnreachable)
                    }
        withBucket "l" $ \completed -> withCursor store plane $ \cursor ->
            writeCursor cursor completed `shouldReturn` Left storeUnreachable

    it "reports a clear that did not land, so a halted walk keeps the cursor it had" $ do
        let plane =
                inertPlane
                    { cpDescribeRepository = \_ -> pure (Right describedWithArn)
                    , cpUntagResource = \_ -> pure (Left storeUnreachable)
                    }
        withCursor store plane $ \cursor -> clearCursor cursor `shouldReturn` Left storeUnreachable

{- Run one cursor call over a wired plane. The handle offers a cursor on every CodeArtifact
repository, so a case that finds none has found a regression rather than a backend arm. -}
withCursor :: CodeArtifactStore -> ControlPlane -> (StoreCursor -> Expectation) -> Expectation
withCursor store plane act = case storeCursor (handleOver store plane) of
    Nothing -> expectationFailure "the CodeArtifact handle offers a walk cursor"
    Just cursor -> act cursor

cursorTag :: Text -> CA.Tag
cursorTag = CA.newTag (cursorTagKey Npm)

-- | Read the consent verdict over a plane that records the order of the two calls.
consentUnder ::
    CodeArtifactStore ->
    IORef [Text] ->
    Either StoreFault CA.DescribeRepositoryResponse ->
    Either StoreFault CA.ListTagsForResourceResponse ->
    IO (Either StoreFault ConsentVerdict)
consentUnder store calls described tagged =
    verifyConsent . handleOver store $
        inertPlane
            { cpDescribeRepository = \_ -> record calls "describe" >> pure described
            , cpListTags = \_ -> record calls "tags" >> pure tagged
            }

-- | Classify the store over a plane whose describe call answers with the given outcome.
classifyUnder :: CodeArtifactStore -> Either StoreFault CA.DescribeRepositoryResponse -> IO (Either StoreFault StoreClass)
classifyUnder store described =
    classifyStore (handleOver store inertPlane{cpDescribeRepository = \_ -> pure described})

{- Every call answers with a fault naming itself, so a case wires only the fields it drives and a
call it did not expect reads as a failure rather than a silent success. -}
inertPlane :: ControlPlane
inertPlane =
    ControlPlane
        { cpListPackages = unexpected "ListPackages"
        , cpListVersions = unexpected "ListPackageVersions"
        , cpDeleteVersions = unexpected "DeletePackageVersions"
        , cpListTags = unexpected "ListTagsForResource"
        , cpDescribeRepository = unexpected "DescribeRepository"
        , cpTagResource = unexpected "TagResource"
        , cpUntagResource = unexpected "UntagResource"
        }
  where
    unexpected name _ = pure (Left (faultSaying ("the spec wired no " <> name <> " answer")))

-- Answer from a fixed sequence, one response per call, so a paging walk is drivable.
answersFrom :: [a] -> IO (IO (Either StoreFault a))
answersFrom responses = do
    remaining <- newIORef responses
    pure . atomicModifyIORef' remaining $ \case
        [] -> ([], Left (faultSaying "the spec ran out of responses"))
        (response : rest) -> (rest, Right response)

record :: IORef [a] -> a -> IO ()
record ref value = modifyIORef' ref (<> [value])

packagesPage :: Maybe Text -> [Text] -> CA.ListPackagesResponse
packagesPage token names =
    CA.newListPackagesResponse 200
        & (CAL.listPackagesResponse_nextToken .~ token)
        & (CAL.listPackagesResponse_packages ?~ [CA.newPackageSummary & CAL.packageSummary_package ?~ name | name <- names])

versionsPage :: Maybe Text -> [Text] -> CA.ListPackageVersionsResponse
versionsPage token raws =
    CA.newListPackageVersionsResponse 200
        & (CAL.listPackageVersionsResponse_nextToken .~ token)
        & (CAL.listPackageVersionsResponse_versions ?~ [CA.newPackageVersionSummary raw CA.PackageVersionStatus_Published | raw <- raws])

allRemoved :: [Text] -> CA.DeletePackageVersionsResponse
allRemoved raws =
    CA.newDeletePackageVersionsResponse 200
        & (CAL.deletePackageVersionsResponse_successfulVersions ?~ fromList [(raw, CA.newSuccessfulPackageVersionInfo) | raw <- raws])

taggedWith :: [CA.Tag] -> CA.ListTagsForResourceResponse
taggedWith tags = CA.newListTagsForResourceResponse 200 & (CAL.listTagsForResourceResponse_tags ?~ tags)

markerTag :: CA.Tag
markerTag = CA.newTag consentTagKey consentTagValue

describing :: CA.RepositoryDescription -> CA.DescribeRepositoryResponse
describing description =
    CA.newDescribeRepositoryResponse 200 & (CAL.describeRepositoryResponse_repository ?~ description)

describedWithArn :: CA.DescribeRepositoryResponse
describedWithArn =
    describing (CA.newRepositoryDescription & CAL.repositoryDescription_arn ?~ "arn:aws:codeartifact:::repository/acme/mirror")

describedWithoutArn :: CA.DescribeRepositoryResponse
describedWithoutArn = describing CA.newRepositoryDescription

routedDescription :: CA.RepositoryDescription
routedDescription =
    CA.newRepositoryDescription
        & (CAL.repositoryDescription_upstreams ?~ [CA.newUpstreamRepositoryInfo & CAL.upstreamRepositoryInfo_repositoryName ?~ "shared"])

-- What a fault says, so an assertion reads the refusal rather than only that one happened.
detailOf :: StoreFault -> Text
detailOf = tfDetail . faultTransport

refusalCodeOf :: VersionOutcome -> Maybe Text
refusalCodeOf = \case
    VersionRefused refusal -> Just (refusalCode refusal)
    _ -> Nothing

served :: Text -> StoredVersion
served raw = StoredVersion{storedVersion = mkVersion Npm raw, storedPresence = VersionServed}

withheld :: ConsentVerdict -> Bool
withheld = \case
    ConsentWithheld _ -> True
    ConsentGranted -> False

preservedNaming :: Text -> StoreClass -> Bool
preservedNaming named = \case
    StorePreserved reason -> named `T.isInfixOf` reason
    StoreDestroyable -> False

storeUnreachable :: StoreFault
storeUnreachable = faultSaying "the store did not answer"

faultSaying :: Text -> StoreFault
faultSaying detail =
    StoreFault{faultTransport = transportFault TransportProtocol detail, faultRetry = RetryFutile}

aPackage :: PackageName
aPackage = mkPackageName Npm Nothing "lodash"

versionRun :: Int -> [Version]
versionRun n = [mkVersion Npm ("1.0." <> show i) | i <- [1 .. n]]

factsFor :: CodeArtifactStore -> IO StoreFacts
factsFor store = storeFacts <$> handleFor store

{- A two-character alphabet over the names these cases seed, so the bucket the handle sends is
readable without this spec knowing an ecosystem's grammar. -}
testAlphabet :: NameAlphabet
testAlphabet = mkNameAlphabet "al"

handleOver :: CodeArtifactStore -> ControlPlane -> StoreMaintenance
handleOver = maintenanceFor testAlphabet unwiredRead

listBucket :: CodeArtifactStore -> ControlPlane -> Text -> IO (Either StoreFault [PackageName])
listBucket store plane raw =
    withBucket raw (collectPages . listPackagesIn (handleOver store plane))

-- Dummy static credentials: the handle is held and read, never sent anywhere.
handleFor :: CodeArtifactStore -> IO StoreMaintenance
handleFor store =
    maintenanceForEnv testAlphabet unwiredRead store
        <$> AWS.newEnv (pure . fromKeys (AWS.AccessKey "AKIDtestkey") (AWS.SecretKey "testsecretkey"))

npmStore :: Maybe CodeArtifactStore
npmStore = coordinates <$> codeArtifactFormat Npm
  where
    coordinates format =
        CodeArtifactStore
            { casDomain = "acme"
            , casDomainOwner = "111122223333"
            , casRegion = "eu-west-1"
            , casRepository = "mirror"
            , casFormat = format
            }
