-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The outbound-credential handle: it mints the bearer token Écluse uses to
__write__ approved packages to the mirror target.

This is one of the two cloud handles. The other is "Ecluse.Core.Queue". It stays
separate from the protocol handle "Ecluse.Core.Registry" because protocol and
authentication are orthogonal axes. Every managed npm registry speaks the same npm
protocol and differs only in how it hands out a bearer token. That holds for AWS
CodeArtifact, GCP Artifact Registry, and a self-hosted Verdaccio alike (see
@docs\/architecture\/cloud-backends.md@ → "Credential Provider").

A 'CredentialProvider' serves the mirror-target write __only__, never a read on a
user's behalf. A private-upstream read forwards the /client's/ own credential, and a
public read is anonymous (see @docs\/architecture\/registry-model.md@ → "Credential
flow and authority"). A deployment therefore configures exactly one provider.

Like the other handles, the effectful field returns __'IO', not @App@__. An adapter
closes over its own backend state (an @amazonka@ env, an HTTP manager) and never
imports the proxy's @Env@\/@App@. Backends therefore stay decoupled from the core (see
@docs\/architecture\/technology-stack.md@ → "Key Decisions").

This module holds the handle and its payload types. 'staticProvider' is the
in-memory leaf: a fixed token with no expiry. The refresh, cache, and expiry policy
that wraps a per-cloud token mint lives in "Ecluse.Core.Credential.Refresh".
-}
module Ecluse.Core.Credential (
    -- * Provider handle
    CredentialProvider (..),
    mintSecret,

    -- * Tokens
    AuthToken (..),

    -- * Secrets
    Secret,
    mkSecret,
    unSecret,

    -- * A client's presented credential
    ClientCredential (..),
    bareCredential,

    -- * In-memory double
    staticProvider,
) where

import Data.Aeson (FromJSON (..), ToJSON (..), Value (String), withText)
import Data.ByteArray qualified as BA
import Data.Time (UTCTime)
import Text.Show (showString, showsPrec)

{- | A short-lived secret (an access token).

Redacted in 'Show' and compared in constant time, so holding one cannot disclose it. Build one
with 'mkSecret' and recover the text __only__ at the point of use with 'unSecret'.
-}
newtype Secret = Secret Text

{- | Constant-time equality over the UTF-8 encoding of the wrapped token.

The @ECLUSE_SERVER__AUTH_TOKEN@ edge gate compares a client's token through this instance.
A short-circuiting compare would leak the secret's prefix length to a remote attacker. The token
length still leaks, and Écluse accepts that.
-}
instance Eq Secret where
    Secret a == Secret b = BA.constEq (encodeUtf8 a :: ByteString) (encodeUtf8 b :: ByteString)

{- | Render a fixed placeholder, __never__ the secret text, so no @show@-based signal can
disclose it. It defines 'showsPrec' because relude re-exports a polymorphic @show@ that is not
the class method.
-}
instance Show Secret where
    showsPrec _ _ = showString "Secret <REDACTED>"

{- | A credential as a client presents it: the secret, and the username half a Basic
presentation carries beside it.

The username is not part of the secret. An edge gate compares 'credSecret' alone, so one
configured token serves a client that sends it as a bearer token and one that sends it as a
Basic password under a username of its own choosing. A passthrough leg renders the pair
verbatim, because a private registry has username conventions of its own.
-}
data ClientCredential = ClientCredential
    { credUsername :: Maybe Text
    -- ^ The username the client presented, when its scheme carries one.
    , credSecret :: Secret
    -- ^ The secret half, the only half any gate compares.
    }
    deriving stock (Eq, Show)

{- | A credential carrying no username: what a bearer scheme recovers, and the form a
configured token takes on its way outbound.
-}
bareCredential :: Secret -> ClientCredential
bareCredential = ClientCredential Nothing

-- | Wrap raw token text as a 'Secret'.
mkSecret :: Text -> Secret
mkSecret = Secret

{- | Recover the raw token text from a 'Secret'. Call this __only__ at the point of
use, when setting the auth header. Never log or otherwise render the result.
-}
unSecret :: Secret -> Text
unSecret (Secret s) = s

-- | The JSON encoding redacts the secret, so it never leaks into a JSON log.
instance ToJSON Secret where
    toJSON _ = String "<REDACTED>"

-- | Decoding reads the secret from configuration, for example the environment AST.
instance FromJSON Secret where
    parseJSON = withText "Secret" (pure . mkSecret)

{- | A bearer token for a registry endpoint, with its expiry when known.

Cloud token lifetimes run from CodeArtifact's ~12h to ADC's ~1h, so a refresh schedules off
'authExpiresAt' rather than a fixed interval.
-}
data AuthToken = AuthToken
    { authSecret :: Secret
    -- ^ The bearer secret itself (redacted in 'Show').
    , authExpiresAt :: Maybe UTCTime
    -- ^ When the token expires. 'Nothing' for a static token, which does not expire.
    }
    deriving stock (Eq, Show)

{- | The credential handle: it yields the token currently valid for the mirror target and
refreshes it before expiry internally, so no caller blocks on a mint on the hot path.
'currentToken' returns 'IO', not @App@, which keeps adapters decoupled from the core.
-}
newtype CredentialProvider = CredentialProvider
    { currentToken :: IO AuthToken
    -- ^ The bearer token to use now. An adapter refreshes it behind this field.
    }

{- | A 'CredentialProvider' that always returns the same token, the @static@ leaf. It never
refreshes, so it fits a registry reached with a long-lived credential.
-}
staticProvider :: AuthToken -> CredentialProvider
staticProvider token = CredentialProvider{currentToken = pure token}

{- | The secret a provider's current token carries, for a caller that presents it and reads no
expiry. It refreshes behind the provider, so a long-lived caller mints per use.
-}
mintSecret :: CredentialProvider -> IO Secret
mintSecret = fmap authSecret . currentToken
