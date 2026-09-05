-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | npm's entry in the ecosystem adapter registry: the
'Ecluse.Core.Registry.Adapter.Types.RegistryAdapter' assembled from the existing npm modules.
Pure assembly, with no protocol logic of its own: every field names a function one of the
@Ecluse.Core.Registry.Npm.*@ modules already exports.
-}
module Ecluse.Core.Registry.Npm.Adapter (
    npmAdapter,
) where

import Ecluse.Core.Ecosystem (Ecosystem (Npm))
import Ecluse.Core.Registry.Adapter.Types (
    AdapterArtifact (..),
    AdapterMetadata (..),
    AdapterPublish (..),
    AdapterServe (..),
    RegistryAdapter (..),
 )
import Ecluse.Core.Registry.Npm (relayPublishDocument)
import Ecluse.Core.Registry.Npm.Credential (npmCredential)
import Ecluse.Core.Registry.Npm.Filter (assembleMergedDocument, serialiseMergedDocument)
import Ecluse.Core.Registry.Npm.Maintenance (npmMaintenance)
import Ecluse.Core.Registry.Npm.Metadata (fetchNpmManifest, newNpmMetadataClient)
import Ecluse.Core.Registry.Npm.Project (projectName)
import Ecluse.Core.Registry.Npm.Publish (declaredNames, npmPublishCodec)
import Ecluse.Core.Registry.Npm.Request qualified as NpmRequest
import Ecluse.Core.Registry.Npm.Route qualified as NpmRoute
import Ecluse.Core.Registry.Origin (OriginClient (ocBaseUrl, ocToken))
import Ecluse.Core.Security.Egress (registryUrlText)

-- | npm's capability record.
npmAdapter :: RegistryAdapter
npmAdapter =
    RegistryAdapter
        { adapterEcosystem = Npm
        , adapterServe =
            AdapterServe
                { serveRouter = NpmRoute.npmRouter
                , serveRoutes = NpmRoute.npmRouteSpecs
                , serveCredential = npmCredential
                }
        , adapterMetadata =
            AdapterMetadata
                { metadataNewClient = newNpmMetadataClient
                , metadataAssemble = assembleMergedDocument
                , metadataSerialise = serialiseMergedDocument
                , metadataFetchManifest = fetchNpmManifest
                }
        , adapterArtifact =
            AdapterArtifact
                { artifactByFile = \origin -> NpmRequest.artifactRequestByFile (registryUrlText (ocBaseUrl origin)) (ocToken origin)
                , artifactByUrl = NpmRequest.artifactRequestByUrl
                , artifactHosts = NpmRequest.npmArtifactHosts
                }
        , adapterProjectName = rightToMaybe . projectName
        , adapterPublish =
            AdapterPublish
                { publishRelay = relayPublishDocument
                , publishDeclaredNames = declaredNames
                , publishCodec = npmPublishCodec
                }
        , adapterMaintenance = npmMaintenance
        }
