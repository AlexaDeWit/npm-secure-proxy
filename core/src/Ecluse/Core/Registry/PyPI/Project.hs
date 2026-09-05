-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Projection of the PEP 691 Simple index into the ecosystem-agnostic domain model, the
second half of the PyPI protocol boundary. "Ecluse.Core.Registry.PyPI.Wire" captures what the
index said; this module turns that into 'PackageInfo' and 'PackageDetails', so nothing above
the adapter sees PyPI wire data. The projection is pure and total: it returns 'Either'
'ParseError' and never throws.

== A release is a set of files

PyPI indexes files, not releases, so the release a file belongs to is read out of its name
('fileCoordinate'). Files that name one release become that version's 'pkgArtifacts', an sdist
beside any number of wheels. Three version-level signals are folds over that set: installing
runs code when __any__ file is an sdist, the age signal is the __newest__ upload instant, so a
wheel added later cannot let a release out of quarantine early, and a release is withdrawn only
when __every__ file of it is yanked.

== Version identity

A release is keyed by its canonical PEP 440 spelling ('canonicalPep440'), so a private and a
public index that spell one release differently merge into one entry rather than listing it
twice. The spelling each file was published under survives in its own name. A file whose
version does not parse as PEP 440 is dropped: no resolver could install it, and admitting it
would key a release on text that another spelling of the same release would not match.

== Per-file graceful degradation

A file whose name names no coordinate for this project, or whose version does not parse, is
dropped as an 'Ecluse.Core.Package.InvalidIndexFile' rather than failing the index. A release
drops when no file of it survives. A document is denied wholesale only when its top-level
structure is unusable: an index that does not decode, or an absent or unusable @name@.

== Name as a validation input

The requested 'PackageName' is the validation authority for the served index's name, never a
rewrite of it, through the shared 'Ecluse.Core.Registry.WireSupport.Projection' agreement.
'projectName' is the one splitter for PyPI identifiers, so the route, the URL rewrite, and the
publish guard read one spelling with one verdict. It sits on
'Ecluse.Core.Registry.WireSupport.parseNameComponent', the non-empty, ASCII, path-safe floor
Écluse holds ecosystem-wide, and adds PEP 508's own grammar: an ASCII alphanumeric at each end,
and @-@, @_@ or @.@ between. A name over 100 characters never parses, the cap PyPI itself
applies.
-}
module Ecluse.Core.Registry.PyPI.Project (
    -- * Projection
    projectSimpleIndexFromValue,

    -- * File coordinates
    FileCoordinate (..),
    fileCoordinate,
    fileVersionKey,

    -- * Name validation
    projectName,
    canonicalName,
    isCanonicalName,
    pypiNameLeadChars,
) where

import Data.Aeson (Value, toJSON)
import Data.Aeson.Types (parseEither, parseJSON)
import Data.Char (isAlphaNum, isAscii)
import Data.List.NonEmpty qualified as NE
import Data.Map.Strict qualified as Map
import Data.Text qualified as T

import Ecluse.Core.Ecosystem (Ecosystem (PyPI))
import Ecluse.Core.Package (
    Artifact (..),
    ArtifactKind (Sdist, Wheel),
    Availability (Available, Yanked),
    CodeExecSignal (NoCodeOnInstall, RunsCodeOnInstall),
    Hash,
    InvalidEntry,
    InvalidEntryKind (InvalidIndexFile),
    PackageDetails (..),
    PackageInfo (..),
    PackageName,
    Trust (TrustUnknown),
    canonicalise,
    mkHash,
    mkInvalidEntry,
    mkPackageName,
    parseHashAlg,
    renderPackageName,
 )
import Ecluse.Core.Registry (ParseError (..))
import Ecluse.Core.Registry.PyPI.Wire (
    IndexFile (..),
    SimpleIndex (..),
    YankState (FileOffered, FileWithdrawn),
 )
import Ecluse.Core.Registry.WireSupport (
    NameRefusal (NameEmpty, NameNotAscii, NameUnsafeComponent),
    Projection,
    checkNameAgreement,
    parseNameComponent,
 )
import Ecluse.Core.Version (Version, canonicalPep440, mkVersion, selectLatest)

{- | Project an already-decoded Simple index @Value@ into a 'Projection' for the requested
project, reusing that parse instead of the bytes. A @Value@ that is not a Simple index gives a
'ParseError'.
-}
projectSimpleIndexFromValue :: PackageName -> Value -> Either ParseError (Projection PackageInfo)
projectSimpleIndexFromValue requestedName value = do
    index <- first (ParseError . toText) (parseEither parseJSON value)
    reportedName <- projectName (siName index)
    pure (checkNameAgreement requestedName reportedName (projectIndex reportedName index))

{- Project a decoded index under the name it reported for itself. 'projectSimpleIndexFromValue'
owns checking that name against the request. -}
projectIndex :: PackageName -> SimpleIndex -> PackageInfo
projectIndex name index =
    PackageInfo
        { infoName = name
        , infoVersions = versions
        , infoDistTags = latestTag versions
        , infoInvalidEntries = siInvalidEntries index <> fileDrops
        }
  where
    (versions, fileDrops) = projectVersions name (siFiles index)

{- Group the index's files by the release each names, projecting one 'PackageDetails' per
release. A file whose name names no coordinate for this project is dropped and recorded. -}
projectVersions :: PackageName -> [IndexFile] -> (Map Text PackageDetails, [InvalidEntry])
projectVersions name files =
    (Map.map (projectDetails name) grouped, drops)
  where
    (grouped, drops) = foldr place (Map.empty, []) files

    place file (byVersion, dropAcc) = case fileCoordinate name (ifFilename file) of
        Just coordinate ->
            ( Map.insertWith (<>) (fcVersionKey coordinate) ((file, coordinate) :| []) byVersion
            , dropAcc
            )
        Nothing -> (byVersion, uncoordinatedDrop file : dropAcc)

{- Record a file whose name names no release of this project. The value is the file's location,
which 'mkInvalidEntry' reduces to its authority before the record reaches a log line. -}
uncoordinatedDrop :: IndexFile -> InvalidEntry
uncoordinatedDrop file =
    mkInvalidEntry
        InvalidIndexFile
        (ifFilename file)
        (toJSON (ifUrl file))
        "file name names no PEP 440 release of this project"

{- | @dist-tags@ for a PyPI project. The wire carries no @latest@ pointer, so the projection
computes one under the shared keep-unless-denied, stable-preferring rule, which with no
upstream choice to keep is the highest release, a final one ahead of a pre-release.
-}
latestTag :: Map Text PackageDetails -> Map Text Version
latestTag versions =
    maybe Map.empty (Map.singleton "latest") (selectLatest Nothing (map pkgVersion (Map.elems versions)))

{- Project one release's files into its 'PackageDetails'. The version-level signals are folds
over the file set, documented in the module header. -}
projectDetails :: PackageName -> NonEmpty (IndexFile, FileCoordinate) -> PackageDetails
projectDetails name entries =
    PackageDetails
        { pkgName = name
        , pkgVersion = mkVersion PyPI (fcVersionKey (snd (NE.head entries)))
        , pkgPublishedAt = newestUpload
        , pkgInstallCode = installCode
        , pkgTrust = TrustUnknown
        , pkgAvailability = availability
        , pkgArtifacts = fmap (uncurry projectArtifact) entries
        , -- The Simple index declares neither a licence nor a publisher; both live in the
          -- distribution's own metadata, which this projection does not fetch.
          pkgLicenses = []
        , pkgPublisher = Nothing
        }
  where
    files = fmap fst entries

    -- The newest instant, so a wheel added later moves the whole release's age forward and the
    -- quarantine measures from the last thing published under it.
    newestUpload = case mapMaybe ifUploadTime (toList files) of
        [] -> Nothing
        earliest : rest -> Just (foldl' max earliest rest)

    installCode
        | any ((== Sdist) . fcKind . snd) entries =
            RunsCodeOnInstall "offers a source distribution, which runs its own build"
        | otherwise = NoCodeOnInstall

    availability = case traverse withdrawnReason files of
        Just reasons -> Yanked (asum reasons)
        Nothing -> Available

    withdrawnReason file = case ifYanked file of
        FileWithdrawn reason -> Just reason
        FileOffered -> Nothing

{- Project one file into an 'Artifact'. The location stays verbatim, and
'Ecluse.Core.Package.Filter' folds its scheme and authority against the egress and host
policies afterward. -}
projectArtifact :: IndexFile -> FileCoordinate -> Artifact
projectArtifact file coordinate =
    Artifact
        { artFilename = ifFilename file
        , artUrl = ifUrl file
        , artKind = fcKind coordinate
        , artHashes = mapMaybe indexHash (Map.toAscList (ifHashes file))
        , artSize = ifSize file
        , artInterpreter = ifRequiresPython file
        , artYanked = case ifYanked file of
            FileWithdrawn _ -> True
            FileOffered -> False
        , artProvenance = ifProvenance file
        }

{- One @hashes@ entry as a 'Hash', through the shared algorithm vocabulary and the validating
'mkHash'. An algorithm this build does not know, or a malformed digest, is absent rather than
degenerate: no bogus fingerprint may pass the integrity floor. -}
indexHash :: (Text, Text) -> Maybe Hash
indexHash (algorithm, digest) = do
    algo <- rightToMaybe (parseHashAlg algorithm)
    rightToMaybe (mkHash algo digest)

{- | What a distribution file name says about the file: which release it belongs to, and
whether installing it runs code.
-}
data FileCoordinate = FileCoordinate
    { fcVersionKey :: Text
    -- ^ The release key: the file's version in canonical PEP 440 form.
    , fcKind :: ArtifactKind
    -- ^ An 'Sdist', or a 'Wheel' carrying its compatibility tag (@py3-none-any@).
    }
    deriving stock (Eq, Show)

{- | Read the coordinate a distribution file name spells for @name@. 'Nothing' when the name
belongs to a different project, has no recognised archive form, or carries a version that is
not PEP 440: each is a file no client of this project could resolve, so the route denies it and
the projection drops it.
-}
fileCoordinate :: PackageName -> Text -> Maybe FileCoordinate
fileCoordinate name file = wheelCoordinate name file <|> sdistCoordinate name file

{- | The release key a distribution file belongs to, for an index that maps its files onto the
versions it serves. 'Nothing' on the same three refusals 'fileCoordinate' makes.
-}
fileVersionKey :: PackageName -> Text -> Maybe Text
fileVersionKey name = fmap fcVersionKey . fileCoordinate name

{- Read a PEP 427 wheel name: @{project}-{version}(-{build})?-{python}-{abi}-{platform}.whl@.
The project and version parts escape @-@ as @_@, so the parts split exactly and the project
part is compared whole. -}
wheelCoordinate :: PackageName -> Text -> Maybe FileCoordinate
wheelCoordinate name file = do
    stem <- T.stripSuffix ".whl" file
    parts <- nonEmpty (T.splitOn "-" stem)
    guard (length parts == 5 || length parts == 6)
    guard (canonicalise PyPI (NE.head parts) == canonicalName name)
    version <- canonicalPep440 =<< (toList parts !!? 1)
    pure (FileCoordinate version (Wheel (T.intercalate "-" (lastThree parts))))
  where
    lastThree parts = drop (length parts - 3) (toList parts)

{- Read a source-distribution name: @{project}-{version}{archive suffix}@. A legacy project
name can carry the separator a version can, so the split takes the longest project part that
canonicalises to this project. -}
sdistCoordinate :: PackageName -> Text -> Maybe FileCoordinate
sdistCoordinate name file = do
    stem <- asum (map (`T.stripSuffix` file) sdistSuffixes)
    version <- canonicalPep440 =<< afterProjectName name stem
    pure (FileCoordinate version Sdist)

-- The archive forms a Python index serves a source distribution under.
sdistSuffixes :: [Text]
sdistSuffixes = [".tar.gz", ".tgz", ".zip", ".tar.bz2", ".tar.xz"]

{- The part of a file-name stem after the project name it must begin with. 'Nothing' when the
stem names another project, which on the artifact route is a path-confusion attempt. -}
afterProjectName :: PackageName -> Text -> Maybe Text
afterProjectName name stem =
    listToMaybe (mapMaybe remainderAfter longestFirst)
  where
    segments = T.split isNameSeparator stem

    -- Longest project part first, so a name carrying a separator wins over a prefix of itself.
    longestFirst = [length segments - 1, length segments - 2 .. 1]

    remainderAfter parts =
        let prefixLength = sum (map T.length (take parts segments)) + parts - 1
         in if canonicalise PyPI (T.take prefixLength stem) == canonicalName name
                then Just (T.drop (prefixLength + 1) stem)
                else Nothing

-- The characters PEP 503 treats as one separator when it normalises a name.
isNameSeparator :: Char -> Bool
isNameSeparator c = c == '-' || c == '_' || c == '.'

{- | A project's canonical PEP 503 key as characters: the spelling a file name is compared
against, and the one segment an upstream Simple-index URL is built from.
-}
canonicalName :: PackageName -> Text
canonicalName = canonicalise PyPI . renderPackageName

{- | Parse a PyPI project name into the domain 'PackageName': the one splitter every PyPI entry
point reads a name through. PyPI carries no namespace, so a name is one component.
-}
projectName :: Text -> Either ParseError PackageName
projectName raw = do
    withinNameLimit raw
    mkPackageName PyPI Nothing <$> nameComponent raw

{- | Whether a name is already in PEP 503 canonical form. The serve route claims only the
canonical spelling, so a client that sends another one takes the structural @404@ rather than a
redirect Écluse would have to speak on the upstream's behalf.
-}
isCanonicalName :: Text -> Bool
isCanonicalName raw = canonicalise PyPI raw == raw

{- One PyPI project name on the shared name floor, plus PEP 508's own grammar. 'projectName'
owns the length cap. -}
nameComponent :: Text -> Either ParseError Text
nameComponent component = do
    onFloor <- first (refusalText component) (parseNameComponent component)
    if usableComponent onFloor
        then Right onFloor
        else Left (ParseError ("unusable PyPI project name: " <> show component))

-- PyPI's own wording for each way the shared floor refuses a name.
refusalText :: Text -> NameRefusal -> ParseError
refusalText component = \case
    NameEmpty -> ParseError "empty PyPI project name"
    NameNotAscii -> ParseError ("non-ASCII PyPI project name: " <> show component)
    NameUnsafeComponent -> ParseError ("unusable PyPI project name: " <> show component)

{- | The characters a PyPI project name may begin with, in its canonical form. A store walk
partitions a name space by them, so they are declared here beside the grammar that admits them
rather than restated at the walk.
-}
pypiNameLeadChars :: [Char]
pypiNameLeadChars = ['a' .. 'z'] <> ['0' .. '9']

{- PEP 508's name grammar on top of the floor: an ASCII alphanumeric at each end, and only
@-@, @_@ or @.@ between them. -}
usableComponent :: Text -> Bool
usableComponent component =
    T.all nameChar component
        && maybe False (nameEdge . fst) (T.uncons component)
        && maybe False (nameEdge . snd) (T.unsnoc component)
  where
    nameChar ch = nameEdge ch || isNameSeparator ch
    nameEdge ch = isAscii ch && isAlphaNum ch

{- Refuse a name over PyPI's own cap. 'T.compareLength' stops at the cap rather than measuring
a hostile length in full. -}
withinNameLimit :: Text -> Either ParseError ()
withinNameLimit raw
    | T.compareLength raw pypiNameLimit == GT = Left (ParseError overLong)
    | otherwise = Right ()
  where
    overLong :: Text
    overLong = "PyPI project name over " <> show pypiNameLimit <> " characters, starting " <> show (T.take 24 raw)

-- PyPI's own cap on a project name, the one its own validator applies.
pypiNameLimit :: Int
pypiNameLimit = 100
