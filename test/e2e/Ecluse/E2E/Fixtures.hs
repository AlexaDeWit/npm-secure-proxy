-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Fixture generation for the end-to-end suite: the static file tree the nginx
public-upstream stub serves.

Each fixture package is an npm-format packument plus a real gzipped tar artifact.
Its __sha-512 SRI covers the bytes actually written__. The proxy's serve path, the
worker's integrity gate, and npm's own SRI check therefore see one digest. The tamper
case makes that digest deliberately inconsistent. The builder backdates each version
well past the default @min-age@ quarantine, so the age rule does not gate the allow path
shut.

The tree mirrors the npm registry layout the stub serves over HTTP:

> \<name\>            -- the packument JSON
> \<name\>/-/\<name\>-\<version\>.tgz -- the artifact

so a packument's @dist.tarball@ (@https:\/\/upstream\/\<name\>\/-\/…@) resolves on the
same stub.
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
    {- ^ Corrupt the artifact bytes after the packument's SRI is computed, so the
    served bytes no longer match the declared integrity.
    -}
    }
    deriving stock (Eq, Show)

-- | A benign package: one backdated version, no install script, untampered bytes.
defaultPkgSpec :: Text -> PkgSpec
defaultPkgSpec name =
    PkgSpec{psName = name, psVersion = "1.0.0", psInstallScript = False, psTamper = False}

-- | An allow-listed package: installs cleanly end to end.
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

{- | A package used only for @HEAD@ probes. No scenario installs or @GET@s it, so an empty
mirror is attributable to the @HEAD@ alone.
-}
headPkg :: PkgSpec
headPkg = defaultPkgSpec "e2e-head"

{- | A package the Dredger deletes from the mirror. No other case installs or observes it, so an
absence after a sweep is attributable to that sweep alone.
-}
dredgerPkg :: PkgSpec
dredgerPkg = defaultPkgSpec "e2e-dredger"

{- | A package that is mirrored beside 'dredgerPkg' and that no deny names, so a sweep that
deleted it would prove the sweep deletes more than the rule condemned.
-}
dredgerKeepPkg :: PkgSpec
dredgerKeepPkg = defaultPkgSpec "e2e-dredger-keep"

{- | A package a rehearsal condemns and no real sweep touches, so its survival is what shows a
dry run deleted nothing.
-}
dredgerDryRunPkg :: PkgSpec
dredgerDryRunPkg = defaultPkgSpec "e2e-dredger-dry-run"

-- | A package used to exercise telemetry domain-span emission.
telemetryPkg :: PkgSpec
telemetryPkg = defaultPkgSpec "e2e-telemetry"

telemetryDdPkg :: PkgSpec
telemetryDdPkg = defaultPkgSpec "e2e-telemetry-datadog"

-- | The full fixture set the stub serves.
fixturePackages :: [PkgSpec]
fixturePackages = [allowPkg, denyPkg, mirrorPkg, tamperPkg, headPkg, dredgerPkg, dredgerKeepPkg, dredgerDryRunPkg, telemetryPkg, telemetryDdPkg]

{- | Write every fixture package under @root@, the nginx stub's document root, with each
packument's @dist.integrity@ fixed to the artifact's real sha-512.
-}
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

-- | @sha512-<base64>@ Subresource-Integrity string over the given bytes.
sha512Sri :: ByteString -> Text
sha512Sri = sriSha512Of

-- | The artifact's @package.json@: identity plus, for the deny case, an install script.
tarballPackageJson :: PkgSpec -> Value
tarballPackageJson spec =
    object $
        [ "name" .= psName spec
        , "version" .= psVersion spec
        ]
            <> ["scripts" .= object ["install" .= ("node -e \"\"" :: Text)] | psInstallScript spec]

{- | The npm packument the stub serves: one backdated version whose integrity is the real
digest. The deny case adds @hasInstallScript@ and a declared install script.
-}
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
