-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Smoke test for the paged store walk no emulator carries: 'listPackagesIn' over a __live__
CodeArtifact repository, whose packages it only reads. It never gates a merge, and __pends__
without a configured repository:

> ECLTEST_SMOKE_CODEARTIFACT_REGION=us-east-1 ECLTEST_SMOKE_CODEARTIFACT_DOMAIN=sandbox \
> ECLTEST_SMOKE_CODEARTIFACT_DOMAIN_OWNER=111122223333 \
> ECLTEST_SMOKE_CODEARTIFACT_REPOSITORY=mirror cabal test ecluse-smoke
-}
module Ecluse.Runtime.Maintenance.CodeArtifactSmokeSpec (spec) where

import Amazonka qualified as AWS
import Amazonka.CodeArtifact qualified as CA
import Amazonka.CodeArtifact.Lens qualified as CAL
import Data.Conduit (fuseBoth, runConduit)
import Data.Conduit.List qualified as CL
import Lens.Micro ((?~))
import Test.Hspec

import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.Package (PackageName)
import Ecluse.Core.Registry.Adapter.Capability (AdapterMaintenance (maintenanceAlphabet))
import Ecluse.Core.Registry.Maintenance (
    NameAlphabet,
    StoreFault,
    StoreMaintenance (listPackagesIn),
    wholeNameSpace,
 )
import Ecluse.Core.Registry.Npm.Maintenance (npmMaintenance)
import Ecluse.Core.Text (nonBlank)
import Ecluse.Runtime.Aws.Env (newAwsEnv)
import Ecluse.Runtime.Maintenance.CodeArtifact (
    ControlPlane (cpListPackages),
    controlPlaneFor,
    maintenanceFor,
    newCodeArtifactMaintenance,
 )
import Ecluse.Runtime.Maintenance.CodeArtifact.Decide (
    CodeArtifactStore (..),
    codeArtifactFormat,
 )
import Ecluse.Test.Maintenance (unwiredRead)

spec :: Spec
spec = describe "live CodeArtifact ListPackages" $
    it "walks a multi-page result over a real repository, threading each page's token" $ do
        mStore <- storeFromEnv
        maybe (pendingWith unconfigured) walksItsPages mStore

{- The walk over the bucket that covers the whole repository, at a page size that makes a boundary
reachable, and then again as the Dredger itself sends it. -}
walksItsPages :: CodeArtifactStore -> Expectation
walksItsPages store = do
    env <- newAwsEnv (Just (casRegion store)) Nothing CA.defaultService
    (mFault, pages) <- walk (maintenanceFor npmAlphabet unwiredRead store (onePageAtATime env))
    shouldHaveFinished mFault
    -- Counted off the stream rather than read back from the name total, because one page
    -- carrying every name is the outcome this case exists to rule out.
    length pages `shouldSatisfy` (>= 2)
    let names = concat pages
    names `shouldNotSatisfy` null
    -- A token threaded back wrongly re-serves a page it already gave.
    ordNub names `shouldBe` names
    -- The production request carries no page size, so this second pass proves the shape the
    -- Dredger sends still walks the repository to its end at whatever size the service picks.
    production <- newCodeArtifactMaintenance npmAlphabet unwiredRead store
    walk production >>= shouldHaveFinished . fst

-- One bucket's stream as its pages and the fault that ended it, so the page count is observed.
walk :: StoreMaintenance -> IO (Maybe StoreFault, [[PackageName]])
walk handle = runConduit (fuseBoth (listPackagesIn handle wholeNameSpace) CL.consume)

-- A walk that reached the end of its bucket carries no trailing fault.
shouldHaveFinished :: Maybe StoreFault -> Expectation
shouldHaveFinished = maybe pass (\fault -> expectationFailure ("the walk stopped: " <> show fault))

{- The control plane with one package per page, so a repository holding two of them pages. The
production request sets no page size, and the service's own default is not a number we choose. -}
onePageAtATime :: AWS.Env -> ControlPlane
onePageAtATime env = plane{cpListPackages = cpListPackages plane . (CAL.listPackages_maxResults ?~ 1)}
  where
    plane = controlPlaneFor env

-- The alphabet npm spells its names with, which is the one an npm mount's own walk carries.
npmAlphabet :: NameAlphabet
npmAlphabet = maintenanceAlphabet npmMaintenance

{- The repository these coordinates name, or 'Nothing' for an environment that configures none.
The credential is the standard AWS chain's, so no variable of ours carries one. -}
storeFromEnv :: IO (Maybe CodeArtifactStore)
storeFromEnv = do
    region <- coordinate "REGION"
    domain <- coordinate "DOMAIN"
    owner <- coordinate "DOMAIN_OWNER"
    repository <- coordinate "REPOSITORY"
    pure $ do
        format <- codeArtifactFormat Npm
        coordinates <- (,,,) <$> domain <*> owner <*> region <*> repository
        let (theDomain, theOwner, theRegion, theRepository) = coordinates
        pure
            CodeArtifactStore
                { casDomain = theDomain
                , casDomainOwner = theOwner
                , casRegion = theRegion
                , casRepository = theRepository
                , casFormat = format
                }

-- One coordinate, where a variable exported empty reads the same as one never exported at all.
coordinate :: Text -> IO (Maybe Text)
coordinate name =
    (>>= nonBlank . toText) <$> lookupEnv (toString ("ECLTEST_SMOKE_CODEARTIFACT_" <> name))

unconfigured :: String
unconfigured =
    "CodeArtifact repository not configured (set ECLTEST_SMOKE_CODEARTIFACT_REGION, _DOMAIN, \
    \_DOMAIN_OWNER, and _REPOSITORY); listing smoke test skipped"
