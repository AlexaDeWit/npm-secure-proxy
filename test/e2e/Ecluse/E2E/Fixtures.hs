-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | npm fixtures for the nginx upstream in end-to-end tests.
Versions predate quarantine, and artifact integrity matches the served bytes
except in the tampering fixture.
-}
module Ecluse.E2E.Fixtures (
    PkgSpec (..),
    defaultPkgSpec,
    allowPkg,
    denyPkg,
    mirrorPkg,
    dredgerPkg,
    dredgerKeepPkg,
    dredgerDryRunPkg,
    tamperPkg,
    headPkg,
    telemetryPkg,
    telemetryDdPkg,
    fixturePackages,
    buildFixtures,
) where

import Data.Aeson (Value, object, (.=))
import Data.Aeson qualified as Aeson
import Data.Aeson.Types (Pair)
import Data.ByteString qualified as BS
import System.Directory (createDirectoryIfMissing)
import System.FilePath ((</>))
import System.Process.Typed (proc, runProcess_)

import Ecluse.Test.Package (sriSha512Of)
import Ecluse.Test.Registry.Npm (VersionSpec (..), packumentValue, versionSpec, versionValue)

-- | One fixture package: its identity plus the two behaviours the scenarios turn on.
data PkgSpec = PkgSpec
    { psName :: Text
    -- ^ The package name (also the mount-relative path the stub serves it at).
    , psVersion :: Text
    -- ^ The single published version.
    , psInstallScript :: Bool
    -- ^ Declare an install script: the @DenyInstallTimeExecution@ trigger.
    , psTamper :: Bool
    -- ^ Corrupt the served bytes after computing their declared integrity.
    }
    deriving stock (Eq, Show)

-- | One backdated version with no install script or altered artifact bytes.
defaultPkgSpec :: Text -> PkgSpec
defaultPkgSpec name =
    PkgSpec{psName = name, psVersion = "1.0.0", psInstallScript = False, psTamper = False}

-- | An allow-listed package for the install path.
allowPkg :: PkgSpec
allowPkg = defaultPkgSpec "e2e-allow"

-- | A package with an install script: denied at the public surface.
denyPkg :: PkgSpec
denyPkg = (defaultPkgSpec "e2e-deny"){psInstallScript = True}

-- | A package used to exercise the mirror round-trip (served, then mirrored).
mirrorPkg :: PkgSpec
mirrorPkg = defaultPkgSpec "e2e-mirror"

-- | A package with tampered artifact bytes: the worker must refuse to mirror it.
tamperPkg :: PkgSpec
tamperPkg = (defaultPkgSpec "e2e-tamper"){psTamper = True}

-- | A package reserved for @HEAD@ probes, so no install can seed its mirror entry.
headPkg :: PkgSpec
headPkg = defaultPkgSpec "e2e-head"

-- | A package reserved for deletion by the Dredger scenario.
dredgerPkg :: PkgSpec
dredgerPkg = defaultPkgSpec "e2e-dredger"

-- | A mirrored package that the Dredger's deny rule does not name.
dredgerKeepPkg :: PkgSpec
dredgerKeepPkg = defaultPkgSpec "e2e-dredger-keep"

-- | A package condemned only by a dry run, which must preserve it.
dredgerDryRunPkg :: PkgSpec
dredgerDryRunPkg = defaultPkgSpec "e2e-dredger-dry-run"

-- | A package used to exercise telemetry domain-span emission.
telemetryPkg :: PkgSpec
telemetryPkg = defaultPkgSpec "e2e-telemetry"

-- | A package for correlating mirrored requests with Datadog telemetry.
telemetryDdPkg :: PkgSpec
telemetryDdPkg = defaultPkgSpec "e2e-telemetry-datadog"

-- | The full fixture set the stub serves.
fixturePackages :: [PkgSpec]
fixturePackages = [allowPkg, denyPkg, mirrorPkg, tamperPkg, headPkg, dredgerPkg, dredgerKeepPkg, dredgerDryRunPkg, telemetryPkg, telemetryDdPkg]

-- | Write nginx fixtures with matching artifact integrity, then apply any requested tampering.
buildFixtures :: FilePath -> [PkgSpec] -> IO ()
buildFixtures root = traverse_ (buildOne root)

buildOne :: FilePath -> PkgSpec -> IO ()
buildOne root spec = do
    let name = toString (psName spec)
        ver = toString (psVersion spec)
        pkgDir = root </> name
        tarDir = pkgDir </> "-"
        tgzPath = tarDir </> (name <> "-" <> ver <> ".tgz")
        -- A scratch directory holding the package tree `tar` archives.
        workPkg = root </> (".work-" <> name) </> "package"
    createDirectoryIfMissing True tarDir
    createDirectoryIfMissing True workPkg
    -- The artifact's package.json (npm tarballs root everything under `package/`).
    writeFileLBS (workPkg </> "package.json") (Aeson.encode (tarballPackageJson spec))
    writeFileLBS (workPkg </> "index.js") "module.exports = {};\n"
    -- Deterministic gzip (fixed mtime) so a rebuild yields identical bytes.
    runProcess_ $
        proc
            "tar"
            [ "--sort=name"
            , "--mtime=2020-01-01 00:00:00Z"
            , "--owner=0"
            , "--group=0"
            , "--numeric-owner"
            , "-czf"
            , tgzPath
            , "-C"
            , root </> (".work-" <> name)
            , "package"
            ]
    bytes <- BS.readFile tgzPath
    let sri = sha512Sri bytes
    -- @<name>@ cannot be both a file and a directory, so the packument sits inside the package
    -- directory and the nginx stub config maps @/<name>@ to it.
    writeFileLBS (pkgDir </> "packument.json") (Aeson.encode (packument spec sri))
    when (psTamper spec) $
        -- Corrupt the served artifact after the SRI is fixed: the worker's integrity
        -- gate and npm's own check must now reject these bytes.
        BS.appendFile tgzPath "tampered"

sha512Sri :: ByteString -> Text
sha512Sri = sriSha512Of

tarballPackageJson :: PkgSpec -> Value
tarballPackageJson spec =
    object $
        [ "name" .= psName spec
        , "version" .= psVersion spec
        ]
            <> ["scripts" .= object ["install" .= ("node -e \"\"" :: Text)] | psInstallScript spec]

packument :: PkgSpec -> Text -> Value
packument spec sri =
    packumentValue
        (psName spec)
        (psVersion spec)
        [(psVersion spec, versionMeta)]
        [ "created" .= backdated
        , "modified" .= backdated
        , fromString (toString (psVersion spec)) .= backdated
        ]
        []
  where
    backdated :: Text
    backdated = "2020-01-01T00:00:00.000Z"

    versionMeta :: Value
    versionMeta =
        versionValue
            ( (versionSpec (psName spec) (psVersion spec) tarballUrl)
                { vsIntegrity = Just sri
                , vsHasInstallScript = psInstallScript spec
                , vsExtraPairs = installScriptFields
                }
            )

    tarballUrl :: Text
    tarballUrl =
        "https://upstream/"
            <> psName spec
            <> "/-/"
            <> psName spec
            <> "-"
            <> psVersion spec
            <> ".tgz"

    installScriptFields :: [Pair]
    installScriptFields
        | psInstallScript spec =
            [ "hasInstallScript" .= True
            , "scripts" .= object ["install" .= ("node -e \"\"" :: Text)]
            ]
        | otherwise = []
