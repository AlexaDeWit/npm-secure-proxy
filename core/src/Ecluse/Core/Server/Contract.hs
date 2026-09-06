-- SPDX-FileCopyrightText: 2026 Alexandra de Wit
--
-- SPDX-License-Identifier: MIT
{-# LANGUAGE ExistentialQuantification #-}

{- | The response-contract algebra: one value interpreted as both wire behaviour and
OpenAPI documentation.

A 'ResponseContract' is indexed by the value a handler must produce. Its constructor is
private: callers can only build one from the leaf contracts in this module and combine
those leaves with 'chooseContract'. Each leaf owns both its 'ResponseDoc' and the function
that renders its payload, so those two interpretations cannot be supplied separately. The
served media type is one of them: a leaf reads it off the 'BodySchema' it documents, so the
type on the wire and the type in the manifest are one spelling.

The route layer existentially packages a contract with a handler producing that
contract's response type. The runtime gives the handler only the corresponding typed
responder. A handler therefore cannot reach WAI with a status or body outside its route's
contract. 'bodilessContract' is the same interpretation for @HEAD@: statuses and headers
are preserved while every documented and emitted body is removed.

Owned JSON bodies use the same @autodocodec@ 'JSONCodec' for encoding here and schema
generation in the manifest tier. An intentionally transparent upstream relay is
different. Its status, media type, and bytes are not Écluse's to constrain. The relay's
contract ('passthroughContract') therefore documents an explicit OpenAPI @default@
response, rather than claiming a false closed set.
-}
module Ecluse.Core.Server.Contract (
    -- * Documented body shapes
    BodySchema (..),
    RequestSpec (..),
    ResponseStatus (..),
    ResponseDoc (..),

    -- * A response contract
    ResponseContract,
    responseDocs,
    responseToWai,
    bodilessContract,

    -- * Exact response leaves
    ResponseValue,
    responseValue,
    jsonContract,
    mediaJsonContract,
    documentedJsonContract,
    mediaContract,
    optionalBodyContract,
    emptyContract,

    -- * Open response leaves
    VariableResponse,
    variableResponse,
    variableOpaqueContract,
    PassthroughBody (..),
    PassthroughResponse,
    passthroughResponse,
    passthroughContract,

    -- * Combining closed alternatives
    ResponseChoice (..),
    chooseContract,

    -- * Rendering JSON through a codec
    encodeBody,
) where

import Autodocodec (JSONCodec, toJSONVia)
import Data.Aeson qualified as Aeson
import Network.HTTP.Types (Header, Status, hContentType)
import Network.Wai (Response, StreamingBody, responseLBS, responseStream)

{- | The structural shape of a response body and the media type it is served under, kept
OpenAPI-free in the core.
-}
data BodySchema
    = -- | No body at all.
      SchemaEmpty
    | -- | Opaque bytes under one known media type.
      SchemaOpaque ByteString
    | -- | Text under one known media type.
      SchemaText ByteString
    | -- | Encoded from the same codec the manifest renders as a schema.
      forall a. SchemaJson ByteString (JSONCodec a)
    | -- | An imperatively assembled document with a named manifest schema.
      SchemaDocumented ByteString Text
    | -- | An upstream-controlled body under an upstream-controlled media type.
      SchemaPassthrough

{- | A request body a route accepts. A hand-authored request schema still owes the separate
conformance check the API-surface architecture describes.
-}
data RequestSpec = RequestSpec
    { reqDescription :: Text
    -- ^ What the body is (the OpenAPI request-body description).
    , reqRequired :: Bool
    -- ^ Whether the request is rejected without it.
    , reqSchema :: BodySchema
    -- ^ The shape of the accepted body.
    }

-- | Whether a documented response has one exact status or covers every other status.
data ResponseStatus
    = ExactResponse Status
    | DefaultResponse
    deriving stock (Eq, Show)

{- | One response entry for the OpenAPI spec. This is a projection of a
'ResponseContract' leaf, never independently supplied by a route.
-}
data ResponseDoc = ResponseDoc
    { responseStatus :: ResponseStatus
    -- ^ The exact HTTP status, or OpenAPI's @default@ response.
    , responseDescription :: Text
    -- ^ What the response means in the route's terms.
    , responseBodySchema :: BodySchema
    -- ^ The body shape this response carries.
    }

{- | A response contract indexed by the only value its handler may answer with. The constructor is
private, so the docs and the renderer extend together through this module's leaves and
'chooseContract'.
-}
data ResponseContract response = ResponseContract
    { contractDocs :: [ResponseDoc]
    , contractRender :: response -> Answer
    }

-- | The manifest projection of a response contract.
responseDocs :: ResponseContract response -> [ResponseDoc]
responseDocs = contractDocs

-- | A payload for an exact-status response, carrying additional response headers.
data ResponseValue a = ResponseValue [Header] a

-- | Supply the additional headers and payload for an exact response leaf.
responseValue :: [Header] -> a -> ResponseValue a
responseValue = ResponseValue

{- | A binary response choice. Nesting these forms a closed route response sum without type-level
programming, and 'chooseContract' builds the two matching interpretations together.
-}
data ResponseChoice a b
    = FirstResponse a
    | SecondResponse b

-- | Combine two response contracts into a closed choice of their alternatives.
chooseContract :: ResponseContract a -> ResponseContract b -> ResponseContract (ResponseChoice a b)
chooseContract left right =
    ResponseContract
        { contractDocs = contractDocs left <> contractDocs right
        , contractRender = \case
            FirstResponse value -> contractRender left value
            SecondResponse value -> contractRender right value
        }

-- | One exact JSON response, encoded through the codec its manifest schema uses.
jsonContract :: Status -> Text -> JSONCodec a -> ResponseContract (ResponseValue a)
jsonContract = mediaJsonContract applicationJson

{- | One exact response encoded through its codec and served under @media@, for a JSON-family
media type an ecosystem names itself.
-}
mediaJsonContract :: ByteString -> Status -> Text -> JSONCodec a -> ResponseContract (ResponseValue a)
mediaJsonContract media status description codec =
    ResponseContract
        { contractDocs = [ResponseDoc (ExactResponse status) description (SchemaJson media codec)]
        , contractRender = \(ResponseValue headers value) ->
            Answer status headers (MediaAnswer media (encodeBody codec value))
        }

{- | One exact JSON response whose bytes are assembled imperatively and whose schema is
the named hand-authored component in the manifest.
-}
documentedJsonContract :: Status -> Text -> Text -> ResponseContract (ResponseValue LByteString)
documentedJsonContract status description schema =
    mediaContract status description (SchemaDocumented applicationJson schema)

{- | One exact response, served under the media type its 'BodySchema' names and documented as
that same type. A schema naming no media type ('SchemaEmpty', 'SchemaPassthrough') emits no body.
-}
mediaContract :: Status -> Text -> BodySchema -> ResponseContract (ResponseValue LByteString)
mediaContract status description schema =
    ResponseContract
        { contractDocs = [ResponseDoc (ExactResponse status) description schema]
        , contractRender = \(ResponseValue headers bytes) ->
            Answer status headers (maybe NoAnswerBody (`MediaAnswer` bytes) (bodyMediaType schema))
        }

{- | One exact response whose body is optional, the refusal shape of an ecosystem whose upstream
answers a bare status. Both forms are one documented response rather than two.
-}
optionalBodyContract :: Status -> Text -> BodySchema -> ResponseContract (ResponseValue (Maybe LByteString))
optionalBodyContract status description schema =
    ResponseContract
        { contractDocs = [ResponseDoc (ExactResponse status) description schema]
        , contractRender = \(ResponseValue headers body) ->
            Answer status headers (maybe NoAnswerBody (mediaAnswer schema) body)
        }
  where
    mediaAnswer bodySchema bytes = maybe NoAnswerBody (`MediaAnswer` bytes) (bodyMediaType bodySchema)

-- The media type a body is served under, absent for a body this leaf does not put on the wire.
bodyMediaType :: BodySchema -> Maybe ByteString
bodyMediaType = \case
    SchemaEmpty -> Nothing
    SchemaOpaque media -> Just media
    SchemaText media -> Just media
    SchemaJson media _ -> Just media
    SchemaDocumented media _ -> Just media
    SchemaPassthrough -> Nothing

applicationJson :: ByteString
applicationJson = "application/json"

-- | One exact bodiless response.
emptyContract :: Status -> Text -> ResponseContract (ResponseValue ())
emptyContract status description =
    ResponseContract
        { contractDocs = [ResponseDoc (ExactResponse status) description SchemaEmpty]
        , contractRender = \(ResponseValue headers ()) -> Answer status headers NoAnswerBody
        }

{- | A response whose status is supplied by the handler while its media type remains
fixed by the contract. Used for the publication target's arbitrary JSON-labelled status.
-}
data VariableResponse a = VariableResponse Status [Header] a

-- | Supply a dynamic status, additional headers, and body to a variable-status leaf.
variableResponse :: Status -> [Header] -> a -> VariableResponse a
variableResponse = VariableResponse

{- | An OpenAPI @default@ response carrying opaque bytes under a fixed media type.

The schema is intentionally binary even for @application/json@. The proxy relays the
publication target's bytes without parsing them, so it must not promise they satisfy a
JSON schema it never checks.
-}
variableOpaqueContract :: ByteString -> Text -> ResponseContract (VariableResponse LByteString)
variableOpaqueContract media description =
    ResponseContract
        { contractDocs = [ResponseDoc DefaultResponse description (SchemaOpaque media)]
        , contractRender = \(VariableResponse status headers bytes) ->
            Answer status headers (MediaAnswer media bytes)
        }

-- | The body of a transparent upstream response.
data PassthroughBody
    = PassthroughBytes LByteString
    | PassthroughStream StreamingBody
    | PassthroughEmpty

-- | A transparent upstream response: status, headers, and body all remain upstream's.
data PassthroughResponse = PassthroughResponse Status [Header] PassthroughBody

-- | Build a transparent response value for 'passthroughContract'.
passthroughResponse :: Status -> [Header] -> PassthroughBody -> PassthroughResponse
passthroughResponse = PassthroughResponse

{- | An OpenAPI @default@ contract for a transparent upstream relay. The proxy forwards arbitrary
upstream statuses and media types, so any finite status set beside it would be inaccurate.
-}
passthroughContract :: Text -> ResponseContract PassthroughResponse
passthroughContract description =
    ResponseContract
        { contractDocs = [ResponseDoc DefaultResponse description SchemaPassthrough]
        , contractRender = \(PassthroughResponse status headers body) ->
            Answer status headers $ case body of
                PassthroughBytes bytes -> RawAnswer bytes
                PassthroughStream stream -> RawStreamAnswer stream
                PassthroughEmpty -> NoAnswerBody
        }

{- | Derive the @HEAD@ interpretation of a contract: the same response alternatives,
statuses, and headers, with no documented or emitted body.
-}
bodilessContract :: ResponseContract response -> ResponseContract response
bodilessContract contract =
    ResponseContract
        { contractDocs = map withoutDocumentedBody (contractDocs contract)
        , contractRender = withoutAnswerBody . contractRender contract
        }
  where
    withoutDocumentedBody doc = doc{responseBodySchema = SchemaEmpty}

{- | Render one value through its contract and into WAI. This is the only application
boundary at which a route response becomes an unrestricted WAI 'Response'.
-}
responseToWai :: ResponseContract response -> response -> Response
responseToWai contract = answerToResponse . contractRender contract

-- | Encode a JSON value to bytes through its @autodocodec@ codec.
encodeBody :: JSONCodec a -> a -> LByteString
encodeBody codec = Aeson.encode . toJSONVia codec

-- The concrete response is deliberately private: pipeline modules can select only a
-- value admitted by their route's public 'ResponseContract'.
data Answer = Answer Status [Header] AnswerBody

data AnswerBody
    = MediaAnswer ByteString LByteString
    | MediaStreamAnswer ByteString StreamingBody
    | RawAnswer LByteString
    | RawStreamAnswer StreamingBody
    | NoAnswerBody

withoutAnswerBody :: Answer -> Answer
withoutAnswerBody (Answer status headers body) =
    Answer status (contentTypeOf body <> headers) NoAnswerBody
  where
    contentTypeOf = \case
        MediaAnswer media _ -> [(hContentType, media)]
        MediaStreamAnswer media _ -> [(hContentType, media)]
        RawAnswer _ -> []
        RawStreamAnswer _ -> []
        NoAnswerBody -> []

answerToResponse :: Answer -> Response
answerToResponse (Answer status headers body) = case body of
    MediaAnswer media bytes -> responseLBS status ((hContentType, media) : headers) bytes
    MediaStreamAnswer media stream -> responseStream status ((hContentType, media) : headers) stream
    RawAnswer bytes -> responseLBS status headers bytes
    RawStreamAnswer stream -> responseStream status headers stream
    NoAnswerBody -> responseLBS status headers ""
