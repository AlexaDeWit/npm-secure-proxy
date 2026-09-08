-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Shared endpoint policy for boot refusals, advisories,
and publication targets.
-}
module Ecluse.Composition.Endpoints (
    -- * The endpoint pass
    VettedEndpoints (..),
    vetEndpoints,

    -- * The endpoints it clears
    PublicationTarget,
    publicationTargetUrl,
) where

import Data.Map.Strict qualified as Map

import Ecluse.Composition.BootError (
    BootError (
        MirrorTargetOnMountEndpoint,
        MirrorTargetOnPublicUpstream,
        PrivateUpstreamOnPublicUpstream,
        PublicationTargetOnMountEndpoint,
        PublicationTargetOnPublicUpstream,
        StoreTagConflict
    ),
 )
import Ecluse.Composition.Types (RegistryRole (MirrorPruner, MirrorWriter))
import Ecluse.Composition.Vet (
    Severity (Advise, Refuse),
    Vet,
    rule,
 )
import Ecluse.Config (
    MountConfig (..),
    PublicationEndpoint (peTarget),
    StoreTag (TagRegistry),
    Target (Target, tgtTag, tgtUrl),
    meTarget,
    sameRegistry,
    storeTagName,
 )
import Ecluse.Core.Ecosystem (Ecosystem, ecosystemName)
import Ecluse.Core.Security (hostAddress)
import Ecluse.Core.Security.Egress (RegistryUrl, registryUrlText)

-- | The endpoints one role's pass cleared it to use, keyed by the mount that declares them.
newtype VettedEndpoints = VettedEndpoints
    { vePublicationTargets :: Map Ecosystem PublicationTarget
    -- ^ Each mount's cleared publish endpoint.
    }

{- | Vet every mount's declared endpoints against each other: the refusals and advisories this
role earns, and the endpoints a pass that refused nothing clears it to use.
-}
vetEndpoints :: Map Ecosystem MountConfig -> Vet VettedEndpoints
vetEndpoints mounts = cleared <$ endpointRules mounts
  where
    cleared = VettedEndpoints (Map.mapMaybe (fmap (PublicationTarget . tgtUrl . peTarget) . mntPublicationTarget) mounts)

{- | A publication target that holds no other registry role. The publish path relays the
publisher's own credential, so the relay takes this vetted value and never a configured URL.
-}
newtype PublicationTarget = PublicationTarget RegistryUrl
    deriving stock (Eq, Show)

-- | The vetted endpoint the publish relay dials.
publicationTargetUrl :: PublicationTarget -> RegistryUrl
publicationTargetUrl (PublicationTarget url) = url

{- Every endpoint rule, in the order a boot report lists them. A mirror target on another mount's
publication target is 'publicationOffNeighbourEndpoints', read from the publishing side. -}
endpointRules :: Map Ecosystem MountConfig -> Vet ()
endpointRules mounts =
    publicationOffPublicUpstreams mounts
        *> publicationOffNeighbourEndpoints mounts
        *> mirrorOffPublicUpstreams mounts
        *> mirrorOffPrivateUpstreams mounts
        *> mirrorOffOwnPublicationTarget mounts
        *> privateOffPublicUpstream mounts
        *> oneTagPerStore mounts

-- A publish relays the publisher's own credential, which must never reach a public registry.
publicationOffPublicUpstreams :: Map Ecosystem MountConfig -> Vet ()
publicationOffPublicUpstreams =
    vetCollisions (const (Refuse publicationOnPublicUpstream)) $
        EndpointComparison KeyPublicationTarget [KeyPublicUpstream] AnyMount ByHost

-- A publish must not be relayed into a role the operator declared for something else.
publicationOffNeighbourEndpoints :: Map Ecosystem MountConfig -> Vet ()
publicationOffNeighbourEndpoints =
    vetCollisions (const (Refuse publicationOnMountEndpoint)) $
        EndpointComparison
            KeyPublicationTarget
            [KeyPrivateUpstream, KeyMirrorTarget, KeyPublicationTarget]
            OtherMount
            ByRegistry

-- The mirror write carries this proxy's own credential, which must never reach a public registry.
mirrorOffPublicUpstreams :: Map Ecosystem MountConfig -> Vet ()
mirrorOffPublicUpstreams =
    vetCollisions (const (Refuse mirrorOnPublicUpstream)) $
        EndpointComparison KeyMirrorTarget [KeyPublicUpstream] AnyMount ByHost

mirrorOffPrivateUpstreams :: Map Ecosystem MountConfig -> Vet ()
mirrorOffPrivateUpstreams =
    vetCollisions mirrorCollapse $
        EndpointComparison KeyMirrorTarget [KeyPrivateUpstream] AnyMount ByRegistry

mirrorOffOwnPublicationTarget :: Map Ecosystem MountConfig -> Vet ()
mirrorOffOwnPublicationTarget =
    vetCollisions mirrorCollapse $
        EndpointComparison KeyMirrorTarget [KeyPublicationTarget] SameMount ByRegistry

privateOffPublicUpstream :: Map Ecosystem MountConfig -> Vet ()
privateOffPublicUpstream =
    vetCollisions (const (Refuse privateOnPublicUpstream)) $
        EndpointComparison KeyPrivateUpstream [KeyPublicUpstream] SameMount ByRegistry

{- One store cannot be two backends. It sits outside the comparison table because it puts every
declared endpoint against every other, and each unordered pair is read once. -}
oneTagPerStore :: Map Ecosystem MountConfig -> Vet ()
oneTagPerStore = traverse_ (rule (const (Refuse storeTagConflict)) divergentTag) . distinctPairs

divergentTag :: EndpointPair -> Maybe EndpointPair
divergentTag pair
    | sameRegistry (tgtUrl subject) (tgtUrl other), tgtTag subject /= tgtTag other = Just pair
    | otherwise = Nothing
  where
    subject = epTarget pair
    other = epOtherTarget pair

storeTagConflict :: EndpointPair -> BootError
storeTagConflict pair =
    StoreTagConflict
        (epMount pair)
        (taggedKeyName (epKey pair) (epTarget pair))
        (epOtherMount pair)
        (taggedKeyName (epOtherKey pair) (epOtherTarget pair))
        (registryUrlText (tgtUrl (epTarget pair)))

-- A mirror target on another declared endpoint: the deleting role refuses, the writing roles warn.
mirrorCollapse :: RegistryRole -> Severity EndpointPair
mirrorCollapse = \case
    MirrorWriter -> advise pruningStaysManual
    MirrorPruner -> Refuse mirrorOnMountEndpoint
  where
    pruningStaysManual =
        "the Dredger refuses this configuration, so pruning this mirror stays manual"

{- The advisory builder every rule here goes through, so each line carries the mount, the keys
and the registry 'advisoryLine' names ahead of its consequence clause. -}
advise :: Text -> Severity EndpointPair
advise = Advise . advisoryLine

publicationOnPublicUpstream :: EndpointPair -> BootError
publicationOnPublicUpstream pair =
    PublicationTargetOnPublicUpstream (epMount pair) (epOtherMount pair) (pairRegistry pair)

publicationOnMountEndpoint :: EndpointPair -> BootError
publicationOnMountEndpoint pair =
    PublicationTargetOnMountEndpoint
        (epMount pair)
        (epOtherMount pair)
        (endpointKeyName (epOtherKey pair))
        (pairRegistry pair)

mirrorOnPublicUpstream :: EndpointPair -> BootError
mirrorOnPublicUpstream pair =
    MirrorTargetOnPublicUpstream (epMount pair) (epOtherMount pair) (pairRegistry pair)

privateOnPublicUpstream :: EndpointPair -> BootError
privateOnPublicUpstream pair =
    PrivateUpstreamOnPublicUpstream (epMount pair) (pairRegistry pair)

-- A sweep deletes from the mirror target, so a store another role holds loses that role's data.
mirrorOnMountEndpoint :: EndpointPair -> BootError
mirrorOnMountEndpoint pair =
    MirrorTargetOnMountEndpoint
        (epMount pair)
        (epOtherMount pair)
        (endpointKeyName (epOtherKey pair))
        (pairRegistry pair)

pairRegistry :: EndpointPair -> Text
pairRegistry = registryUrlText . tgtUrl . epTarget

-- A registry endpoint of a mount, named by the key the configuration declares it under.
data EndpointKey
    = KeyPublicUpstream
    | KeyPrivateUpstream
    | KeyMirrorTarget
    | KeyPublicationTarget
    deriving stock (Eq, Show)

-- Which mounts a rule compares: one mount's own endpoints, its neighbours', or both.
data MountScope = SameMount | OtherMount | AnyMount
    deriving stock (Eq, Show)

{- How a rule compares two endpoints. Full-URL equality is what store identity needs, because
CodeArtifact repositories share one domain and differ only in path. -}
data RegistryMatch = ByHost | ByRegistry
    deriving stock (Eq, Show)

{- Which endpoints a rule puts against each other: the key whose role is at stake, the keys it
must not land on, the mounts those keys are read from, and how the two are compared. -}
data EndpointComparison = EndpointComparison
    { cmpSubject :: EndpointKey
    , cmpAgainst :: [EndpointKey]
    , cmpScope :: MountScope
    , cmpMatch :: RegistryMatch
    }

-- Two declared endpoints a comparison reads side by side, each named by its mount and its key.
data EndpointPair = EndpointPair
    { epMount :: Ecosystem
    , epKey :: EndpointKey
    , epTarget :: Target
    , epOtherMount :: Ecosystem
    , epOtherKey :: EndpointKey
    , epOtherTarget :: Target
    }

vetCollisions :: (RegistryRole -> Severity EndpointPair) -> EndpointComparison -> Map Ecosystem MountConfig -> Vet ()
vetCollisions severity cmp mounts =
    traverse_ (rule severity (collidingPair (cmpMatch cmp))) (comparedPairs cmp mounts)

comparedPairs :: EndpointComparison -> Map Ecosystem MountConfig -> [EndpointPair]
comparedPairs cmp mounts =
    [ EndpointPair eco (cmpSubject cmp) target other otherKey otherTarget
    | (eco, mcfg) <- Map.toAscList mounts
    , Just target <- [endpointOf (cmpSubject cmp) mcfg]
    , (other, otherCfg) <- Map.toAscList mounts
    , withinScope (cmpScope cmp) eco other
    , otherKey <- cmpAgainst cmp
    , Just otherTarget <- [endpointOf otherKey otherCfg]
    ]

-- Each unordered pair of declared endpoints once, so one collision earns one refusal.
distinctPairs :: Map Ecosystem MountConfig -> [EndpointPair]
distinctPairs mounts =
    [ EndpointPair eco key target other otherKey otherTarget
    | (eco, key, target) : rest <- tails (declaredEndpoints mounts)
    , (other, otherKey, otherTarget) <- rest
    ]

declaredEndpoints :: Map Ecosystem MountConfig -> [(Ecosystem, EndpointKey, Target)]
declaredEndpoints mounts =
    [ (eco, key, target)
    | (eco, mcfg) <- Map.toAscList mounts
    , key <- [KeyPublicUpstream, KeyPrivateUpstream, KeyMirrorTarget, KeyPublicationTarget]
    , Just target <- [endpointOf key mcfg]
    ]

collidingPair :: RegistryMatch -> EndpointPair -> Maybe EndpointPair
collidingPair match pair
    | sameStore match (tgtUrl (epTarget pair)) (tgtUrl (epOtherTarget pair)) = Just pair
    | otherwise = Nothing

{- The endpoint a mount declares under one key. Only @registry@ is admitted on the public
upstream, so its tag is the one the parser pinned rather than one the mount wrote. -}
endpointOf :: EndpointKey -> MountConfig -> Maybe Target
endpointOf key mcfg = case key of
    KeyPublicUpstream -> Just (Target TagRegistry (mntPublicUpstream mcfg))
    KeyPrivateUpstream -> mntPrivateUpstream mcfg
    KeyMirrorTarget -> meTarget <$> mntMirrorTarget mcfg
    KeyPublicationTarget -> peTarget <$> mntPublicationTarget mcfg

withinScope :: MountScope -> Ecosystem -> Ecosystem -> Bool
withinScope scope eco other = case scope of
    SameMount -> eco == other
    OtherMount -> eco /= other
    AnyMount -> True

sameStore :: RegistryMatch -> RegistryUrl -> RegistryUrl -> Bool
sameStore = \case
    ByHost -> sameHost
    ByRegistry -> sameRegistry

{- Whether two endpoints dial the same host, compared case-insensitively. An unreadable authority
yields the empty host, which matches no real one, so that endpoint fails later at the relay. -}
sameHost :: RegistryUrl -> RegistryUrl -> Bool
sameHost a b = hostOf a == hostOf b
  where
    hostOf = hostAddress . registryUrlText

endpointKeyName :: EndpointKey -> Text
endpointKeyName = \case
    KeyPublicUpstream -> "publicUpstream"
    KeyPrivateUpstream -> "privateUpstream"
    KeyMirrorTarget -> "mirrorTarget"
    KeyPublicationTarget -> "publicationTarget"

-- The key path down to the tag, the depth a tag refusal must name to be actionable.
taggedKeyName :: EndpointKey -> Target -> Text
taggedKeyName key target = endpointKeyName key <> "." <> storeTagName (tgtTag target)

-- One advisory line: the collapsed pair, the registry they share, and the consequence.
advisoryLine :: Text -> EndpointPair -> Text
advisoryLine advice pair =
    "mount \""
        <> ecosystemName (epMount pair)
        <> "\": "
        <> endpointKeyName (epKey pair)
        <> " and "
        <> otherRef
        <> " resolve to the same registry ("
        <> pairRegistry pair
        <> "); "
        <> advice
  where
    otherRef
        | epOtherMount pair == epMount pair = endpointKeyName (epOtherKey pair)
        | otherwise =
            "mount \""
                <> ecosystemName (epOtherMount pair)
                <> "\" "
                <> endpointKeyName (epOtherKey pair)
