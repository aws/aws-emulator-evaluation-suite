"""invoke-model-response-stream-frames-verify-their-own-crc32."""
from __future__ import annotations

import base64
import json
import zlib

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

from behavioral_harness import tags

CHECK = "invoke-model-response-stream-frames-verify-their-own-crc32"
GROUP = "streaming"
SERVICES = ["bedrock-runtime"]

MODEL_ID = "amazon.nova-lite-v1:0"
_SIGNING_NAME = "bedrock"
_BODY = json.dumps({
    "messages": [{"role": "user",
                  "content": [{"text": "Reply with exactly the single word PONG and nothing "
                                       "else."}]}],
    "inferenceConfig": {"maxTokens": 64, "temperature": 0.0},
}, sort_keys=True)
_EVENTSTREAM_MIME = "application/vnd.amazon.eventstream"
_HEADER_TYPE_STRING = 7
_PRELUDE_LEN = 12
_MESSAGE_CRC_LEN = 4


def _crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def _u32(data: bytes, at: int) -> int:
    return int.from_bytes(data[at:at + 4], "big")


def _parse_headers(blob: bytes) -> dict:
    """Decode one event-stream header block. Only the string type is expected here; anything else
    raises with the type byte, because a silently ignored header is a silently ignored contract."""
    out: dict = {}
    i = 0
    while i < len(blob):
        name_len = blob[i]
        i += 1
        name = blob[i:i + name_len].decode("utf8")
        i += name_len
        value_type = blob[i]
        i += 1
        assert value_type == _HEADER_TYPE_STRING, (
            f"header {name!r} has event-stream value type {value_type}, but every header this "
            f"operation is documented to emit is the string type {_HEADER_TYPE_STRING}"
        )
        value_len = int.from_bytes(blob[i:i + 2], "big")
        i += 2
        out[name] = blob[i:i + value_len].decode("utf8")
        i += value_len
    return out


def _parse_frames(raw: bytes) -> list[tuple[dict, bytes]]:
    """Split the whole body into (headers, payload) pairs, verifying BOTH CRC-32s of every frame."""
    frames: list[tuple[dict, bytes]] = []
    offset = 0
    while offset < len(raw):
        remaining = len(raw) - offset
        assert remaining >= _PRELUDE_LEN, (
            f"the stream ended mid-prelude: {remaining} byte(s) left at offset {offset} of "
            f"{len(raw)}, and a prelude is {_PRELUDE_LEN} bytes"
        )
        total_length = _u32(raw, offset)
        headers_length = _u32(raw, offset + 4)
        declared_prelude_crc = _u32(raw, offset + 8)

        computed_prelude_crc = _crc32(raw[offset:offset + 8])
        assert computed_prelude_crc == declared_prelude_crc, (
            f"frame at offset {offset}: the prelude CRC-32 recomputed over its own first 8 bytes "
            f"is {computed_prelude_crc:#010x} but the frame declares {declared_prelude_crc:#010x} "
            f"(total_length={total_length} headers_length={headers_length})"
        )
        assert _PRELUDE_LEN + headers_length + _MESSAGE_CRC_LEN <= total_length, (
            f"frame at offset {offset}: total_length={total_length} cannot hold a {_PRELUDE_LEN}"
            f"-byte prelude, {headers_length} bytes of headers and a {_MESSAGE_CRC_LEN}-byte "
            f"message CRC"
        )
        assert total_length <= remaining, (
            f"frame at offset {offset} declares total_length={total_length} but only {remaining} "
            f"byte(s) remain in the body"
        )

        body_end = offset + total_length - _MESSAGE_CRC_LEN
        declared_message_crc = _u32(raw, body_end)
        computed_message_crc = _crc32(raw[offset:body_end])
        assert computed_message_crc == declared_message_crc, (
            f"frame at offset {offset}: the message CRC-32 recomputed over bytes "
            f"[{offset}, {body_end}) is {computed_message_crc:#010x} but the frame declares "
            f"{declared_message_crc:#010x}"
        )

        headers_start = offset + _PRELUDE_LEN
        headers = _parse_headers(raw[headers_start:headers_start + headers_length])
        frames.append((headers, raw[headers_start + headers_length:body_end]))
        offset += total_length
    return frames


@tags("axis:happy-path", "cap:c3", "cap:c6", "concern:data-plane", "concern:representation", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Raw InvokeModelWithResponseStream frames verify against their own recomputed CRC-32s, the
    inner content type is on X-Amzn-Bedrock-Content-Type, and the decoded text matches botocore.

    Reference: https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_InvokeModelWithResponseStream.html
    """
    # The request is hand-signed and parsed raw because botocore verifies the event-stream CRCs
    # itself, so an SDK-mediated read never sees malformed framing.
    import urllib3

    rt = ctx.client("bedrock-runtime")

    # The signing name is asserted so a change fails here rather than as an opaque 403.
    signing_name = rt.meta.service_model.signing_name
    assert signing_name == _SIGNING_NAME, (
        f"bedrock-runtime's signing name is {signing_name!r}, expected {_SIGNING_NAME!r}; the "
        f"hand-signed request below would be rejected with an opaque 403"
    )
    op = rt.meta.service_model.operation_model("InvokeModelWithResponseStream")
    assert op.has_event_stream_output, (
        "InvokeModelWithResponseStream no longer declares an event-stream output in the model, so "
        "the premise that this operation speaks vnd.amazon.eventstream no longer holds"
    )

    raw_creds = rt._request_signer._credentials
    creds = (raw_creds.get_frozen_credentials()
             if hasattr(raw_creds, "get_frozen_credentials") else raw_creds)
    endpoint = rt.meta.endpoint_url.rstrip("/")
    url = f"{endpoint}/model/{MODEL_ID}/invoke-with-response-stream"

    body = _BODY.encode()
    req = AWSRequest(method="POST", url=url, data=body, headers={
        "content-type": "application/json",
        "accept": _EVENTSTREAM_MIME,
        "x-amzn-bedrock-accept": "application/json",
    })
    SigV4Auth(creds, _SIGNING_NAME, ctx.region).add_auth(req)
    http = urllib3.PoolManager()
    resp = http.request("POST", url, body=body, headers=dict(req.headers.items()), retries=False)
    headers = {k.lower(): v for k, v in resp.headers.items()}
    assert resp.status == 200, (
        f"the hand-signed streaming invocation must succeed before its framing can be graded; got "
        f"HTTP {resp.status} headers={headers!r} body={resp.data[:400]!r}"
    )

    # The transport and model content types are bound to different headers on this operation.
    assert headers.get("content-type") == _EVENTSTREAM_MIME, (
        f"the transport Content-Type of a response-stream invocation must be "
        f"{_EVENTSTREAM_MIME!r}; got {headers.get('content-type')!r} (all headers {headers!r})"
    )
    assert headers.get("x-amzn-bedrock-content-type") == "application/json", (
        f"the MODEL's content type is bound to the X-Amzn-Bedrock-Content-Type header on this "
        f"operation, not to Content-Type; got "
        f"{headers.get('x-amzn-bedrock-content-type')!r} (all headers {headers!r})"
    )

    frames = _parse_frames(resp.data)
    assert len(frames) >= 2, (
        f"a real response stream must carry at least a content delta and a terminal metrics frame; "
        f"{len(resp.data)} body bytes parsed into {len(frames)} frame(s)"
    )
    for index, (frame_headers, _payload) in enumerate(frames):
        assert frame_headers.get(":message-type") == "event", (
            f"frame {index} is not an event: :message-type={frame_headers.get(':message-type')!r} "
            f"headers={frame_headers!r}"
        )
        assert frame_headers.get(":event-type") == "chunk", (
            f"frame {index} of a ResponseStream must be the 'chunk' union member; got "
            f":event-type={frame_headers.get(':event-type')!r} headers={frame_headers!r}"
        )
        assert frame_headers.get(":content-type") == "application/json", (
            f"frame {index} must declare a JSON payload; got "
            f":content-type={frame_headers.get(':content-type')!r} headers={frame_headers!r}"
        )

    # Each JSON payload wraps the model bytes under "bytes" (base64).
    hand_decoded = []
    for index, (_h, payload) in enumerate(frames):
        outer = json.loads(payload)
        assert isinstance(outer, dict) and "bytes" in outer, (
            f"frame {index}'s payload must be a JSON object carrying the base64 'bytes' member of "
            f"PayloadPart; got {outer!r}"
        )
        hand_decoded.append(json.loads(base64.b64decode(outer["bytes"])))

    hand_text = "".join(
        o["contentBlockDelta"]["delta"].get("text", "")
        for o in hand_decoded if "contentBlockDelta" in o)
    assert hand_text.strip(), (
        f"the hand-decoded frames carried no text, so the reassembly below is vacuous; decoded "
        f"chunk keys {[sorted(o) for o in hand_decoded]!r}"
    )

    # The SDK request body is byte-identical, so a correct target yields the same text.
    sdk = rt.invoke_model_with_response_stream(
        modelId=MODEL_ID, body=_BODY,
        contentType="application/json", accept="application/json")
    sdk_decoded = [json.loads(event["chunk"]["bytes"]) for event in sdk["body"]]
    sdk_text = "".join(
        o["contentBlockDelta"]["delta"].get("text", "")
        for o in sdk_decoded if "contentBlockDelta" in o)
    assert sdk_text.strip() == hand_text.strip(), (
        f"the text decoded from hand-parsed, CRC-verified frames must equal the text botocore's "
        f"own event-stream decoder yields for the byte-identical request; hand="
        f"{hand_text.strip()!r} sdk={sdk_text.strip()!r}"
    )
    assert "PONG" in hand_text.upper(), (
        f"the forced prompt must produce its token on the hand-decoded path, so the equality above "
        f"is between two real generations and not two empty strings; got {hand_text!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
