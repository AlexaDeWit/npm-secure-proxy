-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The values the worker unit specs decide over: the stub upstream's tarball bytes and every
digest computed from them, the job and version-snapshot fixtures, the npm re-evaluation policies,
and the small predicates that read an outcome back.

The digests come in matching and non-matching pairs, because the worker's tamper gate is the
axis most of these specs vary. "Ecluse.Worker.Support.Runtime" holds the effectful doubles.
-}
module Ecluse.Worker.Support.Fixtures (
    -- * The stub upstream's bytes, and digests over them
    tarballBytes,
    trueSha1,
    trueSri,
    trueSha512Hex,
    trueSha256,
    trueSha256Sri,
    trueBlake2b,
    trueSha384Sri,
    trueSha384Hex,
    falseSha384Sri,
    falseSri,
    caseVariantSri,
    wrongSha1,
    someBlake2b,
    someSha256,
    someMd5,
    someSha256Sri,

    -- * Job and version-snapshot fixtures
    epoch,
    pkg,
    ver,
    otherVer,
    jobWith,
    sampleArtifact,
    sampleDetails,
    presentResolver,
    refusingResolver,
    resolverWithArtifact,

    -- * Worker policies, and the overrides a case applies to them
    npmPolicies,
    npmPolicy,
    unwiredPublish,
    admitPolicies,
    admitPoliciesWithDigests,
    withPublish,
    withFirstParty,
    withHostGate,
    withArtifactRequest,
    withArtifactCap,

    -- * Artifact URLs a fetch cannot serve
    unreachableUrl,
    credentialBearingUnreachableUrl,
    unformableUrl,

    -- * Supervision
    testSupervision,

    -- * Reading an outcome back
    stringAt,
    isMismatch,
    mismatchDetail,
    isDropped,
    isRetried,
) where

import Data.Aeson (Key, Value (Object, String))
import Data.Aeson.KeyMap qualified as KeyMap
import Data.Map.Strict qualified as Map
import Data.Text qualified as T
import Data.Time (UTCTime (UTCTime), fromGregorian, secondsToDiffTime)
import Network.HTTP.Client (Request)
import UnliftIO.Exception (throwIO)

import Ecluse.Core.Credential (ClientCredential)
import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.Package (
    Artifact (..),
    Hash,
    HashAlg (SRI),
    PackageDetails (..),
    PackageName,
 )
import Ecluse.Core.Queue (MirrorJob (..))
import Ecluse.Core.Registry (ParseError (ParseError), UrlFormationError)
import Ecluse.Core.Registry.Adapter.Capability (AdapterArtifact (artifactByUrl))
import Ecluse.Core.Registry.Metadata (VersionEvaluation (VersionPresent))
import Ecluse.Core.Registry.Publish (MirrorPublish (..))
import Ecluse.Core.Rules (PreparedRule)
import Ecluse.Core.Security (HostPort, Limits (maxBodyBytes), defaultLimits)
import Ecluse.Core.Security.Egress.DevHttp (loopbackRegistryUrl)
import Ecluse.Core.Supervision (
    BackoffSchedule (BackoffSchedule, bsBaseMicros, bsCapMicros),
    FaultDisposition (Transient),
    SupervisionPolicy (SupervisionPolicy, spBackoff, spClassify, spLabel),
 )
import Ecluse.Core.Version (Version, mkVersion)
import Ecluse.Core.Worker (
    IntegrityResult (IntegrityMismatch, IntegrityVerified),
    JobOutcome (Dropped, Retried),
    WorkerPolicies,
    WorkerPolicy (wpArtifact, wpArtifactHostHonoured, wpArtifactLimits, wpFirstParty, wpPublish),
 )
import Ecluse.Test.Package (
    unsafeFilename,
    unsafeHash,
    validBlake2b,
    validMd5,
    validSha1,
    validSha256,
    validSha256Sri,
 )
import Ecluse.Test.Package qualified as Package
import Ecluse.Test.Rules (admitRule)
import Ecluse.Test.Support (TestContractEscape (TestContractEscape))
import Ecluse.Test.Worker (npmPolicyWith)

{- | The tarball bytes the stub upstream serves. The digests in the job fixtures are
computed over exactly these bytes.
-}
tarballBytes :: ByteString
tarballBytes = "the-real-artifact-bytes"

-- | The lower-cased hex SHA-1 of 'tarballBytes': the shasum a faithful job carries.
trueSha1 :: Text
trueSha1 = Package.hexSha1Of tarballBytes

-- | The SRI (@sha512-<base64>@) of 'tarballBytes'.
trueSri :: Text
trueSri = Package.sriSha512Of tarballBytes

{- | The lower-cased hex SHA-512 of 'tarballBytes': the form a __raw 'SHA512'-tagged__
digest carries, as opposed to the base64 inside an SRI string.
-}
trueSha512Hex :: Text
trueSha512Hex = Package.hexSha512Of tarballBytes

-- | The lower-cased hex SHA-256 of 'tarballBytes' (a digest the worker computes).
trueSha256 :: Text
trueSha256 = Package.hexSha256Of tarballBytes

-- | The SRI (@sha256-<base64>@) of 'tarballBytes', the resolved-and-computable SRI form.
trueSha256Sri :: Text
trueSha256Sri = Package.sriSha256Of tarballBytes

-- | The lower-cased hex Blake2b-512 of 'tarballBytes' (a digest the worker computes).
trueBlake2b :: Text
trueBlake2b = Package.hexBlake2bOf tarballBytes

-- | The SRI (@sha384-<base64>@) of 'tarballBytes': a genuine sha384 the worker computes.
trueSha384Sri :: Text
trueSha384Sri = Package.sriSha384Of tarballBytes

{- | The lower-cased hex SHA-384 of 'tarballBytes': the form a __raw 'SHA384'-tagged__
digest carries, as opposed to the base64 inside an SRI string.
-}
trueSha384Hex :: Text
trueSha384Hex = Package.hexSha384Of tarballBytes

{- | A well-formed sha384 SRI that does NOT match 'tarballBytes', because it is the digest
of different bytes: the sha384 tamper-direction fixture.
-}
falseSha384Sri :: Text
falseSha384Sri = Package.sriSha384Of "completely-different-bytes"

{- | A well-formed sha512 SRI that does NOT match 'tarballBytes', because it is the digest
of different bytes: the tamper-direction fixture.
-}
falseSri :: Text
falseSri = Package.sriSha512Of "completely-different-bytes"

{- | A well-formed sha512 SRI whose base64 body is the correct digest with its letter case
flipped. base64 is case-sensitive, so a case-folding comparison would wrongly admit it.
-}
caseVariantSri :: Text
caseVariantSri = "sha512-" <> T.toUpper (fromMaybe "" (T.stripPrefix "sha512-" trueSri))

{- | The canonical empty-input SHA-1 fixture, used here as a well-formed digest that does not
match 'tarballBytes': the mismatch fixture, distinct from a malformed one.
-}
wrongSha1 :: Text
wrongSha1 = validSha1

-- Canonical empty-input digests ('Ecluse.Test.Package') that do not match 'tarballBytes'.
-- 'someMd5' drives the uncomputable MD5 arm (fail-closed). The worker recomputes the rest.
someBlake2b, someSha256, someMd5, someSha256Sri :: Text
someBlake2b = validBlake2b
someSha256 = validSha256
someMd5 = validMd5
someSha256Sri = validSha256Sri

-- | A fixed reference instant for the heartbeat-staleness assertions.
epoch :: UTCTime
epoch = UTCTime (fromGregorian 2020 1 1) (secondsToDiffTime 0)

pkg :: PackageName
pkg = Package.thingName

ver :: Version
ver = Package.v1_0_0

{- | A different version of the same package. A present-at-mirror probe fixture lists it
to prove the worker judges presence per version, never per package.
-}
otherVer :: Version
otherVer = mkVersion Npm "0.9.0"

{- | A mirror job for the conventional @thing-1.0.0.tgz@ artifact at the given stub upstream.
The digests the worker verifies against live on the policies' resolved snapshot, never on the job.
-}
jobWith :: Text -> MirrorJob
jobWith url =
    MirrorJob
        { jobPackage = pkg
        , jobVersion = ver
        , -- The flag-gated loopback former: these suites point jobs at in-process
          -- http stubs, which the production https-only former would refuse.
          jobArtifactUrl = loopbackRegistryUrl url
        , jobArtifactFilename = unsafeFilename "thing-1.0.0.tgz"
        , jobTraceContext = Nothing
        }

{- | The artifact of a projected version snapshot. Its filename must match 'jobWith''s, and its
sha512 SRI must be over 'tarballBytes', because the tamper gate verifies against this artifact.
-}
sampleArtifact :: Artifact
sampleArtifact =
    Package.sampleArtifact
        { artUrl = "https://registry.npmjs.org/thing/-/thing-1.0.0.tgz"
        , artHashes = [unsafeHash SRI trueSri]
        }

{- | A minimal projected version snapshot. The injected rules ignore its contents, so it stands
in for what the shared single-version fetch would project.
-}
sampleDetails :: PackageName -> Version -> PackageDetails
sampleDetails name version =
    (Package.sampleDetails name version){pkgArtifacts = sampleArtifact :| []}

{- | A resolver that always reports the version present (projected), so the worker runs the
rules over its 'PackageDetails'.
-}
presentResolver :: PackageName -> Version -> IO VersionEvaluation
presentResolver name version = pure (VersionPresent (sampleDetails name version))

{- | A resolver that throws if it is consulted, so a case proving a job was decided ahead of
the public leg cannot hide a metadata request behind a passing assertion.
-}
refusingResolver :: PackageName -> Version -> IO VersionEvaluation
refusingResolver _ _ = throwIO (TestContractEscape "refusingResolver: public metadata consulted")

{- | A resolver whose resolved snapshot carries the given artifact, for the ingest-gate cases where
current metadata changed shape after the job was enqueued.
-}
resolverWithArtifact :: Artifact -> PackageName -> Version -> IO VersionEvaluation
resolverWithArtifact art rName rVersion =
    pure (VersionPresent ((sampleDetails rName rVersion){pkgArtifacts = art :| []}))

{- | Worker policies for npm, clocked at the fixed 'epoch'. The injected rules are not
time-sensitive.
-}
npmPolicies :: (PackageName -> Version -> IO VersionEvaluation) -> [PreparedRule] -> WorkerPolicies
npmPolicies resolve rules = Map.singleton Npm (npmPolicy resolve rules)

{- | One npm re-evaluation bundle at 'epoch', with a generous artifact cap: these tests fetch
tiny fixtures, so the cap never bites, and it matches the worker default.
-}
npmPolicy :: (PackageName -> Version -> IO VersionEvaluation) -> [PreparedRule] -> WorkerPolicy
npmPolicy = npmPolicyWith (pure epoch) (512 * 1024 * 1024) unwiredPublish

{- | The publish placeholder 'npmPolicy' carries. The runtime builders swap in the
recording double ('withPublish'), so any effectful use here fails loudly.
-}
unwiredPublish :: MirrorPublish
unwiredPublish =
    MirrorPublish
        { mpProbeMetadata = const (throwIO (TestContractEscape "unwiredPublish: probe consulted"))
        , mpParseVersionList = const (Left (ParseError "unwiredPublish: nothing to parse"))
        , mpPublishArtifact = \_ _ _ _ -> throwIO (TestContractEscape "unwiredPublish: publish consulted")
        }

{- | The default admitting policy. The version resolves present and an always-admit rule
clears it, so re-evaluation never blocks.
-}
admitPolicies :: WorkerPolicies
admitPolicies = npmPolicies presentResolver [admitRule]

{- | 'admitPolicies' with the resolved artifact's digests replaced, so a test chooses a faithful
mirror or a tamper here, independent of what the job payload carries.
-}
admitPoliciesWithDigests :: [Hash] -> WorkerPolicies
admitPoliciesWithDigests hashes =
    npmPolicies (resolverWithArtifact sampleArtifact{artHashes = hashes}) [admitRule]

-- | Give every bundle in the map the same publish capability.
withPublish :: MirrorPublish -> WorkerPolicies -> WorkerPolicies
withPublish publish = Map.map (\p -> p{wpPublish = publish})

{- | Override the first-party predicate of every policy in the map, so a case drives a job
whose namespace the deployment declared after the enqueue.
-}
withFirstParty :: (PackageName -> Bool) -> WorkerPolicies -> WorkerPolicies
withFirstParty owned = Map.map (\p -> p{wpFirstParty = owned})

{- | Override the tarball-host gate of every policy in the map: the payload
re-gating tests refuse (or admit) every authority wholesale.
-}
withHostGate :: (Maybe HostPort -> Bool) -> WorkerPolicies -> WorkerPolicies
withHostGate gate = Map.map (\p -> p{wpArtifactHostHonoured = gate})

{- | Override the artifact request formation of every policy in the map, so a refusing builder
proves which bundle's formation a job rides.
-}
withArtifactRequest :: (Maybe ClientCredential -> Text -> Either UrlFormationError Request) -> WorkerPolicies -> WorkerPolicies
withArtifactRequest builder = Map.map (\p -> p{wpArtifact = (wpArtifact p){artifactByUrl = builder}})

-- | Set every bundle's artifact fetch cap, so a test drives an over-cap fetch.
withArtifactCap :: Int -> WorkerPolicies -> WorkerPolicies
withArtifactCap cap = Map.map (\p -> p{wpArtifactLimits = defaultLimits{maxBodyBytes = cap}})

{- | An address with nothing listening. A fetch against it is refused at connect, the
genuine transient fault. Port 1 is in the privileged range and never bound.
-}
unreachableUrl :: Text
unreachableUrl = "http://127.0.0.1:1/thing/-/thing-1.0.0.tgz"

{- | 'unreachableUrl' dressed as a hostile artifact location: the userinfo and signed query a
@dist.tarball@ can hide a credential in. It still fails at connect, so no network is touched.
-}
credentialBearingUnreachableUrl :: Text
credentialBearingUnreachableUrl = "http://deploy:hunter2@127.0.0.1:1/x?sig=abc"

{- | A job artifact URL that cannot be parsed into a request, so the by-URL build fails before
any fetch.
-}
unformableUrl :: Text
unformableUrl = "not a url"

{- | The loop tests' supervision policy. It drops the shell's wiring-fault classifications,
which live with the shell's types.
-}
testSupervision :: SupervisionPolicy
testSupervision =
    SupervisionPolicy
        { spLabel = "worker-test"
        , spClassify = const Transient
        , spBackoff = BackoffSchedule{bsBaseMicros = 1_000_000, bsCapMicros = 1_000_000}
        }

-- Follow a path of object keys into a decoded JSON 'Value' and return the string at the
-- leaf. Any step that is absent or the wrong shape yields 'Nothing'.
stringAt :: [Key] -> Value -> Maybe Text
stringAt [] (String t) = Just t
stringAt (k : ks) (Object o) = KeyMap.lookup k o >>= stringAt ks
stringAt _ _ = Nothing

isMismatch :: IntegrityResult -> Bool
isMismatch = \case
    IntegrityMismatch _ -> True
    IntegrityVerified -> False

-- The operator-facing detail of an integrity mismatch, or 'Nothing' when verified.
mismatchDetail :: IntegrityResult -> Maybe Text
mismatchDetail = \case
    IntegrityMismatch detail -> Just detail
    IntegrityVerified -> Nothing

isDropped :: JobOutcome -> Bool
isDropped = \case
    Dropped _ -> True
    _ -> False

isRetried :: JobOutcome -> Bool
isRetried = \case
    Retried _ -> True
    _ -> False
