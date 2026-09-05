-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | Outbound-request guards for the proxy's data plane: defending where the proxy fetches.

Écluse builds outbound HTTP requests from two untrusted sources: client-supplied
package identifiers (the request path), and upstream-supplied artifact locations (a
packument's @dist.tarball@). This module provides the pure guard layer that keeps
hostile input from steering the proxy.

'isAllowedUpstreamHost' restricts outbound fetches to the configured upstream
@host:port@ pairs. 'isBlockedTarget' rejects internal address ranges (cloud instance
metadata, loopback, RFC1918) that the proxy's network position can otherwise reach.
Together they are the SSRF gate: a target must be both on the allowlist /and/ not an
internal address. The two compare different projections of a target on purpose.
Authorisation compares the full authority ('HostPort', the host with its effective
port, 443 when none is written), because the fetch dials the port too. The
internal-range block classifies the bare host alone, because an address is internal
regardless of port.
-}
module Ecluse.Core.Security.Host (
    -- * Outbound host:port allowlist
    AllowedHostPorts,
    allowedHostPorts,
    isAllowedUpstreamHost,

    -- * Internal-range block
    isBlockedTarget,
    isBlockedIP,
    parseBlockedRange,

    -- * Artifact-host gate
    Origin (..),
    tarballHostAllowed,
    artifactAuthorityHonoured,
    ecosystemArtifactAuthorities,
    TarballHostGate (..),
    tarballHostGate,
) where

import Data.IP (
    IP (IPv4, IPv6),
    IPRange (IPv4Range, IPv6Range),
    fromIPv6b,
    isMatchedTo,
    toIPv4,
    toIPv6,
 )
import Data.Set qualified as Set
import Data.Text qualified as T

import Ecluse.Core.Security.Authority (HostPort (..), hostPortAddress)
import Ecluse.Core.Security.IpLiteral (IpAddr (IpV4, IpV6), parseIpLiteral)

{- | The @host:port@ pairs the host guards authorise, each host already canonicalised
by 'allowedHostPorts', its only constructor.

An entry authorises exactly its own pair, and one built from a URL with no explicit port
authorises port 443 alone.
-}
newtype AllowedHostPorts = AllowedHostPorts (Set HostPort)
    deriving stock (Eq, Show)

{- | Normalise configured upstream authorities to the canonical key form the host guards
match on (see 'canonicalHostKey').

Equivalent spellings of one IP literal collapse to one key, so an operator who opts in
@0:0:0:0:0:0:0:1@ matches an incoming @::1@.
-}
allowedHostPorts :: Set HostPort -> AllowedHostPorts
allowedHostPorts = AllowedHostPorts . Set.map canonicalEntry
  where
    canonicalEntry (HostPort host port) = HostPort (canonicalHostKey host) port

{- | Whether @target@ dials one of the configured upstream authorities. It is the first
guard on every outbound fetch, and the allowlist half of the SSRF gate. Pair it with
'isBlockedTarget' for the internal-range half.

Matching the @host:port@ pair rather than the host alone is load-bearing: an allowlisted
host on an attacker-chosen port (@registry.npmjs.org:9443@) is an unauthorised target.
-}
isAllowedUpstreamHost :: AllowedHostPorts -> HostPort -> Bool
isAllowedUpstreamHost (AllowedHostPorts allowed) (HostPort host port) =
    not (T.null host) && HostPort (canonicalHostKey host) port `Set.member` allowed

{- | Whether @host@ is an internal-address literal the proxy must not fetch: the fixed
'blockedRanges' plus the operator's @ECLUSE_EGRESS__ADDITIONAL_BLOCKED_RANGES@.

An attacker who steers a fetch aims it at addresses only the privileged proxy reaches, the
cloud metadata endpoint above all. A DNS name is not blocked here: the host allowlist and
the validating-TLS manager ('Ecluse.Core.Security.Egress') close that class.
-}
isBlockedTarget :: [IPRange] -> Text -> Bool
isBlockedTarget additionalRanges host =
    maybe False (isBlockedIP additionalRanges . ipAddrToIP) (parseIpLiteral host)

{- | Whether an 'IP' falls in a blocked internal range: 'blockedRanges' plus the
caller-supplied @additionalRanges@.

An IPv6 address embedding an IPv4 one decodes first and tests against the IPv4 ranges,
because an embedded internal literal (@::ffff:169.254.169.254@, or its NAT64 spelling
@64:ff9b::a9fe:a9fe@) is a recognised SSRF smuggling form. An RFC 6052 network-specific
prefix cannot be enumerated here, so an operator whose fabric translates under one extends
the block with @additionalRanges@.
-}
isBlockedIP :: [IPRange] -> IP -> Bool
isBlockedIP additionalRanges ip = any matches (blockedRanges <> additionalRanges)
  where
    decoded = decodeEmbeddedV4 ip
    matches = \case
        IPv4Range r -> case decoded of
            IPv4 a -> a `isMatchedTo` r
            IPv6 _ -> False
        IPv6Range r -> case decoded of
            IPv6 a -> a `isMatchedTo` r
            IPv4 _ -> False

{- The internal ranges the proxy refuses to fetch from, as @iproute@ CIDR values. An
operator cannot narrow this fixed set, only extend it through the @additionalRanges@
'isBlockedIP' also consults.
-}
blockedRanges :: [IPRange]
blockedRanges =
    [ "0.0.0.0/8" -- unspecified / this-host (reaches loopback on Linux)
    , "10.0.0.0/8" -- RFC1918 private
    , "100.64.0.0/10" -- CGNAT shared (RFC 6598)
    , "127.0.0.0/8" -- loopback
    , "169.254.0.0/16" -- link-local (incl. 169.254.169.254 metadata)
    , "172.16.0.0/12" -- RFC1918 private
    , "192.168.0.0/16" -- RFC1918 private
    , "::/128" -- IPv6 unspecified
    , "::1/128" -- IPv6 loopback
    , "fe80::/10" -- IPv6 link-local
    , "fc00::/7" -- IPv6 unique-local (incl. AWS IMDSv6 fd00:ec2::254)
    ]

{- | Parse one operator-configured @ECLUSE_EGRESS__ADDITIONAL_BLOCKED_RANGES@ entry (one
CIDR, e.g. @"203.0.113.0\/24"@) into an 'IPRange', or 'Nothing' for anything malformed.

This is total: @iproute@'s 'Read' instance returns no parse rather than calling 'error',
unlike its partial 'IsString' instance. A malformed entry must fail closed at boot, never
be silently dropped or accepted as an unblocked range.
-}
parseBlockedRange :: Text -> Maybe IPRange
parseBlockedRange = readMaybe . toString

{- Convert a recognised literal to an @iproute@ 'IP' for the membership test. The
embedded-IPv4 decode stays with 'isBlockedIP', so an embedding literal rides here as the
IPv6 it textually is.
-}
ipAddrToIP :: IpAddr -> IP
ipAddrToIP = \case
    IpV4 a b c d -> IPv4 (toIPv4 (map fromIntegral [a, b, c, d]))
    IpV6 groups -> IPv6 (toIPv6 (map fromIntegral groups))

{- The canonical comparison key for a host: an IP literal renders through @iproute@'s
'show', so equivalent spellings of one address (@::1@, @0:0:0:0:0:0:0:1@) collapse to one
key. A DNS name is only case-folded.

Both host guards fold through this one function, which is what guarantees a configured
entry and a queried host render identically.
-}
canonicalHostKey :: Text -> Text
canonicalHostKey host = case parseIpLiteral host of
    Just addr -> show (ipAddrToIP addr)
    Nothing -> T.toLower host

{- Decode the fixed-prefix IPv4 embeddings so 'isBlockedIP' tests the embedded address
against the IPv4 ranges: IPv4-mapped and IPv4-compatible (RFC 4291), and the NAT64
well-known @64:ff9b::\/96@ (RFC 6052) and local-use @64:ff9b:1::\/48@ (RFC 8215) prefixes.

No embedding prefix falls in a blocked IPv6 range, so without this decode
@::169.254.169.254@ and @64:ff9b::a9fe:a9fe@ would pass the SSRF block.
-}
decodeEmbeddedV4 :: IP -> IP
decodeEmbeddedV4 = \case
    IPv6 v6 -> case fromIPv6b v6 of
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, a, b, c, d] ->
            IPv4 (toIPv4 [a, b, c, d])
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, a, b, c, d] ->
            IPv4 (toIPv4 [a, b, c, d])
        [0x00, 0x64, 0xFF, 0x9B, 0, 0, 0, 0, 0, 0, 0, 0, a, b, c, d] ->
            IPv4 (toIPv4 [a, b, c, d])
        [0x00, 0x64, 0xFF, 0x9B, 0x00, 0x01, _, _, _, _, _, _, a, b, c, d] ->
            IPv4 (toIPv4 [a, b, c, d])
        _ -> IPv6 v6
    ip -> ip

{- | The trust of the origin a @dist.tarball@ comes from.

The distinction governs the literal internal-range block alone, since a private registry
may legitimately live on an internal address. It never relaxes the host allowlist or the
same-authority clause, which gate both origins identically.
-}
data Origin
    = -- | The operator-configured private upstream: exempt from the literal internal-range block.
      TrustedOrigin
    | -- | The public upstream, and any attacker-influenceable target: subject to the literal internal-range block.
      UntrustedOrigin
    deriving stock (Eq, Show)

{- | Whether a @dist.tarball@ authority may be fetched, given the origin's trust and the
authority that served the packument. It composes on top of the host allowlist and the
internal-range block, and over-blocking is the fail-safe.

An upstream's @dist.tarball@ is server-chosen data (@docs\/architecture\/security.md@ →
"Why @dist.tarball@ is honoured"), so the target must equal the packument authority, host
and port both. The one equivalence is @ecosystemHosts@, the hosts an ecosystem serves
artifact bytes from by design (npm has none, PyPI's is @files.pythonhosted.org@). The
packument authority is only compared, never re-validated here: it was already gated when
the packument itself was fetched.
-}
tarballHostAllowed ::
    -- | The ecosystem's canonical artifact authorities, same-host-equivalent.
    AllowedHostPorts ->
    Origin ->
    -- | The @host:port@ allowlist (the same one every outbound fetch is gated by).
    AllowedHostPorts ->
    {- | The operator-configured ranges extending the fixed internal-range block
    (untrusted origin).
    -}
    [IPRange] ->
    -- | The authority that served the packument, when one could be extracted.
    Maybe HostPort ->
    -- | The authority of the candidate @dist.tarball@, when one could be extracted.
    Maybe HostPort ->
    Bool
tarballHostAllowed ecosystemHosts origin allowed additionalBlockedRanges packumentOrigin tarballTarget =
    artifactAuthorityHonoured ecosystemHosts packumentOrigin tarballTarget
        -- A target no authority extracts from is unfetchable, so it authorises nothing.
        && maybe False (\target -> isAllowedUpstreamHost allowed target && internalRangeOk target) tarballTarget
  where
    -- The internal-range block classifies the bare host: an address is internal whatever
    -- port it is dialled on. The trusted private origin is exempt (see 'Origin').
    internalRangeOk :: HostPort -> Bool
    internalRangeOk target = case origin of
        TrustedOrigin -> True
        UntrustedOrigin -> not (isBlockedTarget additionalBlockedRanges (hpHost target))

{- | Whether an artifact's authority is honoured for a document the given authority served: the
same dial target, or one the ecosystem serves artifact bytes from by design. The projection
drops a file this refuses and 'tarballHostAllowed' refuses the same file at download, so the
served listing and the download gate cannot disagree. A missing authority on either side is
'False'.
-}
artifactAuthorityHonoured :: AllowedHostPorts -> Maybe HostPort -> Maybe HostPort -> Bool
artifactAuthorityHonoured ecosystemHosts packumentOrigin artifactTarget =
    case (packumentOrigin, artifactTarget) of
        (Just packument, Just target) ->
            sameAuthority target packument || isAllowedUpstreamHost ecosystemHosts target
        _ -> False

{- | The authority set of an ecosystem's declared artifact hosts. 'tarballHostGate' and each
adapter's projection derive 'artifactAuthorityHonoured''s first argument through it, so the two
read one set.
-}
ecosystemArtifactAuthorities :: [Text] -> AllowedHostPorts
ecosystemArtifactAuthorities = allowedHostPorts . Set.fromList . mapMaybe hostPortAddress

-- Whether two authorities are one dial target: equal canonical host keys and equal
-- effective ports.
sameAuthority :: HostPort -> HostPort -> Bool
sameAuthority (HostPort host port) (HostPort host' port') =
    canonicalHostKey host == canonicalHostKey host' && port == port'

{- | The mount-constant inputs to the per-request 'tarballHostAllowed' gate, extracted
once by 'tarballHostGate'.

The gate runs on the hot artifact path, and a mount's configuration fixes its allowlist
and upstream authorities at boot. Precomputing them collapses a per-request set rebuild
and URL re-parse to a few field reads. Only the dynamic public @dist.tarball@ authority is
parsed per request.
-}
data TarballHostGate = TarballHostGate
    { thgAllowlist :: AllowedHostPorts
    {- ^ The canonicalised @host:port@ allowlist of the mount's configured upstreams plus the
    ecosystem's artifact hosts, the same set every outbound fetch is gated against
    (security.md invariant 2). A URL that writes no port contributes its host at 443.
    -}
    , thgEcosystemHosts :: AllowedHostPorts
    {- ^ The ecosystem's canonical artifact authorities, supplied by the adapter: npm has
    none, PyPI's is @files.pythonhosted.org@. They are the one same-host equivalence
    'tarballHostAllowed' grants, and they stay internal-range-gated like any target.
    -}
    , thgPrivateHostPort :: Maybe HostPort
    {- ^ The private upstream's authority, extracted once. 'Nothing' when the configured
    URL yields no dialable authority, which authorises nothing (fail closed).
    -}
    , thgPublicHostPort :: Maybe HostPort
    {- ^ The public upstream's authority, extracted once. 'Nothing' has the same
    fail-closed reading.
    -}
    }
    deriving stock (Eq, Show)

{- | Build the 'TarballHostGate' from the ecosystem's canonical artifact hosts and a
mount's private, public, and mirror-target upstream URLs. The composition root calls it
once per mount.

A URL from which no authority extracts contributes no allowlist entry and leaves its
reference authority 'Nothing', so a misconfigured or absent upstream authorises nothing
rather than something unintended.
-}
tarballHostGate :: [Text] -> Maybe Text -> Text -> Maybe Text -> TarballHostGate
tarballHostGate ecosystemHostUrls privateUrl publicUrl mirrorUrl =
    TarballHostGate
        { thgAllowlist =
            allowedHostPorts
                ( Set.fromList
                    (catMaybes ([privateHostPort, publicHostPort, hostPortAddress =<< mirrorUrl] <> map hostPortAddress ecosystemHostUrls))
                )
        , thgEcosystemHosts = ecosystemArtifactAuthorities ecosystemHostUrls
        , thgPrivateHostPort = privateHostPort
        , thgPublicHostPort = publicHostPort
        }
  where
    privateHostPort = hostPortAddress =<< privateUrl
    publicHostPort = hostPortAddress publicUrl
