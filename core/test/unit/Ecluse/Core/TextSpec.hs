-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

-- | Shared text parsing contracts and ISO-8601 rendering parity.
module Ecluse.Core.TextSpec (spec) where

import Data.Time (UTCTime (UTCTime), fromGregorian, picosecondsToDiffTime)
import Data.Time.Format.ISO8601 (iso8601Show)
import Hedgehog (forAll, (===))
import Hedgehog.Gen qualified as Gen
import Hedgehog.Range qualified as Range
import Test.Hspec
import Test.Hspec.Hedgehog (hedgehog)

import Ecluse.Core.Text (afterFirst, joinUrlPath, nonBlank, readDecimalText, readHexText, renderIso8601Utc, stripTrailingSlash, urlFilename, urlFilenameComponent)

-- | Text parsing contracts and ISO-8601 rendering parity.
spec :: Spec
spec = do
    nonBlankSpec
    trailingSlashSpec
    joinUrlPathSpec
    urlFilenameSpec
    urlFilenameComponentSpec
    afterFirstSpec
    readDecimalTextSpec
    readHexTextSpec
    renderIso8601Spec

afterFirstSpec :: Spec
afterFirstSpec = describe "afterFirst" $ do
    it "returns the text after the needle's first occurrence, never a later one" $
        afterFirst "://" "https://169.254.169.254/x?u=https://registry.npmjs.org"
            `shouldBe` "169.254.169.254/x?u=https://registry.npmjs.org"

    it "returns the whole input when the needle is absent" $
        afterFirst "://" "registry.npmjs.org:443" `shouldBe` "registry.npmjs.org:443"

readDecimalTextSpec :: Spec
readDecimalTextSpec = describe "readDecimalText" $ do
    it "reads a bare decimal run, leading zeros included" $ do
        readDecimalText "1234567890" `shouldBe` Just (1234567890 :: Integer)
        readDecimalText "0" `shouldBe` Just (0 :: Integer)
        readDecimalText "007" `shouldBe` Just (7 :: Integer)

    it "refuses an empty run, a sign, and a fractional value" $ do
        readDecimalText @Integer "" `shouldBe` Nothing
        readDecimalText @Integer "-123" `shouldBe` Nothing
        readDecimalText @Integer "+123" `shouldBe` Nothing
        readDecimalText @Integer "123.456" `shouldBe` Nothing

    it "refuses trailing or interior text" $ do
        readDecimalText @Integer "123a456" `shouldBe` Nothing
        readDecimalText @Integer "123 456" `shouldBe` Nothing
        readDecimalText @Integer "12s" `shouldBe` Nothing

    -- The forms 'readMaybe' accepts and this refuses. A config numeric and a network
    -- literal take one spelling of a number, so 0x10 is not 16 and (5) is not 5.
    it "refuses the base prefixes, padding, and brackets that readMaybe accepts" $ do
        readDecimalText @Integer "0x10" `shouldBe` Nothing
        readDecimalText @Integer "0o10" `shouldBe` Nothing
        readDecimalText @Integer "  5" `shouldBe` Nothing
        readDecimalText @Integer "5  " `shouldBe` Nothing
        readDecimalText @Integer "(5)" `shouldBe` Nothing

readHexTextSpec :: Spec
readHexTextSpec = describe "readHexText" $ do
    it "reads a bare hex run in either case" $ do
        readHexText "0123456789abcdef" `shouldBe` Just (81985529216486895 :: Integer)
        readHexText "ABCDEF" `shouldBe` Just (11259375 :: Integer)
        readHexText "aBcDeF" `shouldBe` Just (11259375 :: Integer)
        readHexText "f" `shouldBe` Just (15 :: Integer)

    it "refuses an empty run, a sign, and a non-hex character" $ do
        readHexText @Integer "" `shouldBe` Nothing
        readHexText @Integer "-1a" `shouldBe` Nothing
        readHexText @Integer "g" `shouldBe` Nothing
        readHexText @Integer "abc-def" `shouldBe` Nothing
        readHexText @Integer "abc def" `shouldBe` Nothing
        readHexText @Integer "0123456789abcdefg" `shouldBe` Nothing

    -- Data.Text.Read.hexadecimal takes the prefix. A caller that read one strips it and
    -- decides for itself, so an IPv6 group spelled 0x1a stays malformed.
    it "refuses the 0x prefix in either case" $ do
        readHexText @Integer "0x1a" `shouldBe` Nothing
        readHexText @Integer "0X1a" `shouldBe` Nothing

nonBlankSpec :: Spec
nonBlankSpec = describe "nonBlank" $ do
    it "treats the empty string as absent" $
        nonBlank "" `shouldBe` Nothing

    it "treats an all-whitespace value as absent" $
        nonBlank "   \t\n " `shouldBe` Nothing

    it "trims surrounding whitespace from a present value" $
        nonBlank "  api  " `shouldBe` Just "api"

    it "keeps internal whitespace untouched" $
        nonBlank "  a b  " `shouldBe` Just "a b"

    it "returns a value with no surrounding whitespace unchanged" $
        nonBlank "ecluse" `shouldBe` Just "ecluse"

trailingSlashSpec :: Spec
trailingSlashSpec = describe "stripTrailingSlash" $ do
    it "drops a single trailing slash" $
        stripTrailingSlash "https://host/" `shouldBe` "https://host"

    it "leaves a base without a trailing slash untouched" $
        stripTrailingSlash "https://host" `shouldBe` "https://host"

    it "drops every trailing slash" $
        stripTrailingSlash "https://r.example//" `shouldBe` "https://r.example"

    it "leaves an interior slash untouched" $
        stripTrailingSlash "https://host/path" `shouldBe` "https://host/path"

joinUrlPathSpec :: Spec
joinUrlPathSpec = describe "joinUrlPath" $ do
    it "joins a base and a path with exactly one slash" $
        joinUrlPath "https://host" "pkg" `shouldBe` "https://host/pkg"

    it "tolerates a trailing slash on the base without doubling the separator" $
        joinUrlPath "https://host/" "pkg" `shouldBe` "https://host/pkg"

    it "joins under a base written with several trailing slashes" $
        joinUrlPath "https://r.example//" "pkg" `shouldBe` "https://r.example/pkg"

    it "appends the path verbatim" $
        joinUrlPath "https://host" "@scope%2Fname" `shouldBe` "https://host/@scope%2Fname"

urlFilenameSpec :: Spec
urlFilenameSpec = describe "urlFilename" $ do
    it "returns the segment after the last slash" $
        urlFilename "https://host/thing/-/thing-1.0.0.tgz" `shouldBe` Just "thing-1.0.0.tgz"

    it "returns the whole string when it carries no slash" $
        urlFilename "thing-1.0.0.tgz" `shouldBe` Just "thing-1.0.0.tgz"

    it "is absent when the string ends in a slash" $
        urlFilename "https://host/thing/" `shouldBe` Nothing

    it "is absent for the empty string" $
        urlFilename "" `shouldBe` Nothing

    for_ ["a\\..\\..\\x", ".", "..", "bad\nname", "bad\0name"] $ \filename ->
        it ("refuses the unsafe filename " <> show filename) $
            urlFilename ("https://host/" <> filename) `shouldBe` Nothing

    for_ ["%2e", "%2E", ".%2e", "%2E.", "%2e%2e", "%2E%2e", "a%2fb", "a%2Fb", "a%5cb", "a%5Cb", "bad%00name", "bad%0Aname", "%ff", "%c0%ae"] $ \filename ->
        it ("refuses the once-decoded unsafe filename " <> show filename) $
            urlFilename ("https://host/" <> filename) `shouldBe` Nothing

    for_ ["archive..tgz", ".hidden", "two words.tgz", "%2e%2e.tgz", "two%20words.tgz", "caf%C3%A9.tgz", "name+tag.tgz", "%252e%252e", "%252f", "%255c", "literal%", "literal%2", "literal%zz"] $ \filename ->
        it ("keeps the valid filename " <> show filename) $
            urlFilename ("https://host/" <> filename <> "?sig=abc#hash") `shouldBe` Just filename

    it "drops a query string, as a presigned artifact URL carries" $
        urlFilename "https://cdn.host/f/thing-1.0.0.tgz?X-Amz-Signature=deadbeef"
            `shouldBe` Just "thing-1.0.0.tgz"

    it "drops a fragment, as a PEP 503 file URL carries" $
        urlFilename "https://files.host/f/thing-1.0.0.tar.gz#sha256=deadbeef"
            `shouldBe` Just "thing-1.0.0.tar.gz"

    it "drops both when the URL carries a query and a fragment" $
        urlFilename "https://cdn.host/f/thing-1.0.0.tgz?sig=abc#sha256=deadbeef"
            `shouldBe` Just "thing-1.0.0.tgz"

    it "cuts the query before the final slash, so a slash inside it cannot become the filename" $
        urlFilename "https://cdn.host/f/thing-1.0.0.tgz?redirect=https://evil.host/other.tgz"
            `shouldBe` Just "thing-1.0.0.tgz"

    it "is absent when the path ends in a slash before the query" $
        urlFilename "https://cdn.host/f/?sig=abc" `shouldBe` Nothing

urlFilenameComponentSpec :: Spec
urlFilenameComponentSpec = describe "urlFilenameComponent" $ do
    for_ ["", ".", "..", "a\\b", "a\nb", "%2e", "..%2Fx", "name+tag.tgz"] $ \filename ->
        it ("extracts the raw component without validation: " <> show filename) $
            urlFilenameComponent ("https://host/a/" <> filename <> "?redirect=/other#hash") `shouldBe` filename

    it "extracts a bare filename without a URL prefix" $
        urlFilenameComponent "..%2Fx" `shouldBe` "..%2Fx"

    it "returns an empty component for an empty URL" $
        urlFilenameComponent "" `shouldBe` ""

renderIso8601Spec :: Spec
renderIso8601Spec = describe "renderIso8601Utc" $ do
    it "matches iso8601Show byte-for-byte across the domain" $
        hedgehog $ do
            -- The whole fast-path domain plus the delegating edges: expanded-representation years
            -- on either side of 0-9999, and every picosecond fraction shape.
            year <- forAll (Gen.integral (Range.linearFrom 2020 (-50) 10500))
            month <- forAll (Gen.int (Range.linear 1 12))
            day <- forAll (Gen.int (Range.linear 1 31))
            picos <-
                forAll $
                    Gen.choice
                        [ (* 1_000_000_000_000) <$> Gen.integral (Range.linear 0 86_399) -- whole seconds
                        , Gen.integral (Range.linear 0 86_399_999_999_999_999) -- arbitrary instant
                        , (+ 114_000_000_000) . (* 1_000_000_000_000) <$> Gen.integral (Range.linear 0 86_399) -- millisecond shape
                        ]
            let t = UTCTime (fromGregorian year month day) (picosecondsToDiffTime picos)
            renderIso8601Utc t === toText (iso8601Show t)

    it "renders the canonical npm shapes" $ do
        let at y m d ps = UTCTime (fromGregorian y m d) (picosecondsToDiffTime ps)
        renderIso8601Utc (at 2015 1 11 ((0 * 3600 + 23 * 60 + 27) * 1_000_000_000_000 + 114_000_000_000))
            `shouldBe` "2015-01-11T00:23:27.114Z"
        renderIso8601Utc (at 2026 6 1 0) `shouldBe` "2026-06-01T00:00:00Z"
        renderIso8601Utc (at 44 12 31 (86_399 * 1_000_000_000_000 + 1))
            `shouldBe` "0044-12-31T23:59:59.000000000001Z"

    it "trims trailing fraction zeros without dropping significant ones" $ do
        let t = UTCTime (fromGregorian 2020 2 29) (picosecondsToDiffTime 100_000_000_000)
        renderIso8601Utc t `shouldBe` "2020-02-29T00:00:00.1Z"

    it "delegates a leap-second reading and stays parity-true" $ do
        let t = UTCTime (fromGregorian 2016 12 31) (picosecondsToDiffTime 86_400_500_000_000_000)
        renderIso8601Utc t `shouldBe` toText (iso8601Show t)
