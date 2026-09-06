-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | An in-memory 'CveLookup' for pure-tier tests.

Rule-evaluation specs in the core suite use this fake instead of SQLite. The
app-tier conformance spec runs the same behavioural cases against this fake
and the real handle, so the two cannot drift apart.
-}
module Ecluse.Test.Cve (
    fakeCveLookup,
) where

import Ecluse.Core.Cve (AdvisoryRange (..), CveLookup (..))
import Ecluse.Core.Osv.Types (UpperBound (FixedBefore))

{- | Build the fake from (package name, range) rows. The remediation probe is exact string equality
on the fixed bound, matching the artifact's verbatim version text.
-}
fakeCveLookup :: [(Text, AdvisoryRange)] -> CveLookup
fakeCveLookup rows =
    CveLookup
        { cveRemediationProbe = \name version ->
            pure (any (\(n, ar) -> n == name && arUpperBound ar == FixedBefore version) rows)
        , cveAdvisoriesFor = \name -> pure [ar | (n, ar) <- rows, n == name]
        , cveCoveredNames = pure (ordNub (map fst rows))
        }
