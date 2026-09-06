-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT

{- | The route-table builders, held against a table with no ecosystem in it.

Every definition under test is engine glue an ecosystem's table calls rather than restates, so
this module builds a three-route table out of nothing but the engine and asserts on that. It
imports no registry module: if one were needed, the glue would not be shared.
-}
module Ecluse.Core.Server.RouteEngineSpec (spec) where

import Network.HTTP.Types (status404)
import Network.HTTP.Types.Method (
    Method,
    StdMethod (GET, HEAD, POST),
    methodDelete,
    methodGet,
    methodHead,
    methodPost,
    methodPut,
 )
import Test.Hspec

import Ecluse.Core.Server.Context (ResponseAction (AnswerLocally))
import Ecluse.Core.Server.Contract (
    BodySchema (SchemaEmpty, SchemaText),
    ResponseContract,
    ResponseDoc (responseBodySchema, responseStatus),
    ResponseStatus (ExactResponse),
    ResponseValue,
    emptyContract,
    mediaContract,
    responseValue,
 )
import Ecluse.Core.Server.Route (
    Capture (Capture),
    MediaNegotiation (AcceptsAnything),
    MethodMatch (MethodPost, MethodRead),
    PatternSeg (SegCap, SegLit),
    Route (Route, routeName),
    RouteName (RouteName),
    answering,
    isHead,
    matchRoute,
    safeSegment,
 )
import Ecluse.Core.Server.RouteSpec (
    ParamSpec (ParamSpec),
    PathSeg (Param),
    RouteSpec (rsMethod, rsName, rsOutcomes, rsPattern),
    catchAllSpecs,
    specsOf,
 )

spec :: Spec
spec = do
    describe "answering" $ do
        it "claims its route whatever the read method" $ do
            claimed methodGet ["-", "ping"] `shouldBe` Just (RouteName "ping")
            claimed methodHead ["-", "ping"] `shouldBe` Just (RouteName "ping")

        it "does not widen the route's method condition" $ do
            claimed methodPut ["-", "ping"] `shouldBe` Nothing
            claimed methodPost ["-", "ping"] `shouldBe` Nothing
            claimed methodDelete ["-", "ping"] `shouldBe` Nothing

    describe "methodMatches" $ do
        it "claims a POST route on POST" $
            claimed methodPost ["-", "upload"] `shouldBe` Just (RouteName "upload")

        it "claims a POST route on no other method" $
            map (`claimed` ["-", "upload"]) [methodGet, methodHead, methodPut, methodDelete]
                `shouldBe` [Nothing, Nothing, Nothing, Nothing]

    describe "safeSegment" $ do
        it "claims one leading segment and yields the tail" $
            safeSegment ToyFile ["report.txt", "rest"]
                `shouldBe` Just (ToyFile "report.txt", ["rest"])

        it "refuses a traversal, a separator, and a control character" $ do
            safeSegment ToyFile [".."] `shouldBe` Nothing
            safeSegment ToyFile ["a/b"] `shouldBe` Nothing
            safeSegment ToyFile ["a\tb"] `shouldBe` Nothing

        it "refuses an empty segment and an empty path" $ do
            safeSegment ToyFile [""] `shouldBe` Nothing
            safeSegment ToyFile [] `shouldBe` Nothing

        it "keeps an unsafe component out of the table it guards" $ do
            claimed methodGet ["thing", "-", "file.txt"] `shouldBe` Just (RouteName "file")
            claimed methodGet ["thing", "-", ".."] `shouldBe` Nothing

    describe "isHead" $
        it "holds for HEAD alone" $ do
            isHead methodHead `shouldBe` True
            map isHead [methodGet, methodPut, methodPost, methodDelete]
                `shouldBe` [False, False, False, False]

    describe "specsOf" $
        it "projects a POST route to one POST operation and no derived HEAD" $ do
            map rsMethod (specsOf uploadRoute) `shouldBe` [POST]
            map rsName (specsOf uploadRoute) `shouldBe` [RouteName "upload"]

    describe "catchAllSpecs" $ do
        it "documents the pair a mount needs, GET and its bodiless HEAD" $ do
            map rsMethod (toList catchAll) `shouldBe` [GET, HEAD]
            map rsName (toList catchAll)
                `shouldBe` [RouteName "unsupported", RouteName "unsupported.head"]

        it "carries the caller's path parameter on both" $
            map rsPattern (toList catchAll)
                `shouldBe` [[Param catchAllParam], [Param catchAllParam]]

        it "documents the refusal contract's status on both operations" $
            map (map responseStatus . rsOutcomes) (toList catchAll)
                `shouldBe` [[ExactResponse status404], [ExactResponse status404]]

        it "keeps the GET's body and drops the HEAD's" $
            map (map (isEmptyBody . responseBodySchema) . rsOutcomes) (toList catchAll)
                `shouldBe` [[False], [True]]

-- The table under test: three routes built from nothing but the engine's own builders.

data ToyCap
    = ToyName Text
    | ToyFile Text
    deriving stock (Eq, Show)

toyRoutes :: [Route ToyCap]
toyRoutes = [pingRoute, fileRoute, uploadRoute]

pingRoute :: Route ToyCap
pingRoute =
    Route
        (RouteName "ping")
        MethodRead
        AcceptsAnything
        [SegLit "-", SegLit "ping"]
        (answering (responseValue [] ()))
        "Liveness probe"
        "Answered locally."
        Nothing
        (emptyContract status404 "A refusal.")

fileRoute :: Route ToyCap
fileRoute =
    Route
        (RouteName "file")
        MethodRead
        AcceptsAnything
        [SegCap capName, SegLit "-", SegCap capFile]
        buildFile
        "Fetch a file"
        "Answered locally."
        Nothing
        (emptyContract status404 "A refusal.")
  where
    buildFile _method = \case
        [ToyName _, ToyFile _] -> Just (AnswerLocally (responseValue [] ()))
        _ -> Nothing

uploadRoute :: Route ToyCap
uploadRoute =
    Route
        (RouteName "upload")
        MethodPost
        AcceptsAnything
        [SegLit "-", SegLit "upload"]
        (answering (responseValue [] ()))
        "Submit a file"
        "Answered locally."
        Nothing
        (emptyContract status404 "A refusal.")

capName :: Capture ToyCap
capName = Capture "name" "The thing's name." (safeSegment ToyName) toySegment

capFile :: Capture ToyCap
capFile = Capture "file" "The file's name." (safeSegment ToyFile) toySegment

-- The name of the route that claims a request, or 'Nothing' when none does.
claimed :: Method -> [Text] -> Maybe RouteName
claimed method segments = routeName . fst <$> matchRoute toyRoutes method [] segments

catchAll :: NonEmpty RouteSpec
catchAll = catchAllSpecs refusalContract catchAllParam

refusalContract :: ResponseContract (ResponseValue LByteString)
refusalContract = mediaContract status404 "Unrecognised path; deny by default." (SchemaText "text/plain")

catchAllParam :: ParamSpec
catchAllParam = ParamSpec "unsupportedPath" "Any path under this mount no route claims."

isEmptyBody :: BodySchema -> Bool
isEmptyBody = \case
    SchemaEmpty -> True
    _ -> False

-- | The one segment a toy capture claims, written back out.
toySegment :: ToyCap -> [Text]
toySegment = \case
    ToyName name -> [name]
    ToyFile file -> [file]
