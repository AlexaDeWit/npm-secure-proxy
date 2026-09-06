-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The mirror worker's artifact download: fetch the bytes named on a job under the worker's
own byte cap. It runs through the shared bounded exchange ("Ecluse.Core.Registry.Exchange"),
so it reports the same 'FetchFault' vocabulary the serve path reads under the same response
bound. The retry-versus-drop decision over that vocabulary lives with the outcome type in
"Ecluse.Core.Worker.Job".
-}
module Ecluse.Core.Worker.Fetch (
    fetchArtifactBytes,
) where

import Network.HTTP.Client (Request)

import Ecluse.Core.Credential (ClientCredential)
import Ecluse.Core.Registry (FetchFault (FetchUrlUnformable), RegistryResponse (responseBody), UrlFormationError)
import Ecluse.Core.Registry.Exchange (boundedFetch, formThen)
import Ecluse.Core.Security (Limits)
import Ecluse.Core.Security.Egress (RegistryUrl, registryUrlText)
import Ecluse.Core.Worker.Types (WorkerM, wrManager)

{- | Fetch the artifact bytes into memory under the caller's byte cap. Bounded-buffered rather
than streamed, because the whole tarball must be in hand to verify it before the publish.
-}
fetchArtifactBytes ::
    Limits ->
    (Maybe ClientCredential -> Text -> Either UrlFormationError Request) ->
    RegistryUrl ->
    WorkerM (Either FetchFault ByteString)
fetchArtifactBytes limits buildRequest url = do
    manager <- asks wrManager
    -- The job's URL is absolute and the public artifact fetch is anonymous, so the builder
    -- names no origin and no token.
    liftIO
        ( formThen
            FetchUrlUnformable
            (fmap (fmap responseBody) . boundedFetch manager limits)
            (buildRequest Nothing (registryUrlText url))
        )
