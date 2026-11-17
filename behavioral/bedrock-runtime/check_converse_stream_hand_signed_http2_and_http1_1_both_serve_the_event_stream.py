"""converse-stream-hand-signed-http2-and-http1-1-both-serve-the-event-stream."""
from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import tempfile
import zlib
from urllib.parse import urlsplit

import botocore.serialize
import requests
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "converse-stream-hand-signed-http2-and-http1-1-both-serve-the-event-stream"
GROUP = "data-plane"
SERVICES = ["bedrock-runtime"]

_MODEL_ID = "amazon.nova-lite-v1:0"
_PROMPT = "Say hi."
_MAX_TOKENS = 1
_RESPONSE_MS = 20000
_EVENTSTREAM_CONTENT_TYPE = "application/vnd.amazon.eventstream"
_EXPECTED_EVENT_TYPES = (
    "messageStart",
    "contentBlockDelta",
    "contentBlockStop",
    "messageStop",
    "metadata",
)

#: A minimal HTTP/2 unary request/response client that negotiates ALPN h2 only. node:http2 is
#: stdlib, nothing to install.
_NODE_SOURCE = r"""
const http2 = require("node:http2");
const fs = require("node:fs");
const conf = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const out = fs.createWriteStream(conf.out);
const result = { status: null, headers: {}, error: null, alpnProtocol: null };
let finished = false;
function done() {
  if (finished) return;
  finished = true;
  out.end(() => {
    process.stdout.write(JSON.stringify(result) + "\n");
    process.exit(0);
  });
}
const session = http2.connect(conf.origin);
session.on("error", (e) => { result.error = "session: " + e.message; done(); });
session.on("connect", () => { result.alpnProtocol = session.alpnProtocol; });
const req = session.request(conf.headers);
req.on("response", (h) => {
  result.status = String(h[":status"]);
  for (const k of Object.keys(h)) { result.headers[k] = String(h[k]); }
});
req.on("data", (c) => { out.write(c); });
req.on("error", (e) => { result.error = "stream: " + e.message; done(); });
req.on("end", () => { session.close(); done(); });
req.write(Buffer.from(conf.body, "base64"));
req.end();
setTimeout(() => { result.error = result.error || "timeout"; try { session.close(); } catch (e) {} done(); }, conf.maxMs);
"""


@tags(
    "axis:happy-path",
    "cap:c6",
    "concern:data-plane",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """ConverseStream, hand-signed and sent raw, serves the same event stream whether the
    connection offers only h2 via ALPN or speaks plain HTTP/1.1: both return :status 200,
    content-type application/vnd.amazon.eventstream, and the model's one-token answer.
    """
    require_tools("node")
    rt = ctx.client("bedrock-runtime")
    control = rt.converse(
        modelId=_MODEL_ID,
        messages=[{"role": "user", "content": [{"text": _PROMPT}]}],
        inferenceConfig={"maxTokens": _MAX_TOKENS},
    )
    assert control["stopReason"] == "max_tokens", (
        f"positive control: Converse against {_MODEL_ID!r} with maxTokens={_MAX_TOKENS} reported "
        f"stopReason {control['stopReason']!r}; expected 'max_tokens' — without this neither raw "
        "transport's event stream below can be judged against a known answer"
    )

    parts, path, body, headers = _build_request(ctx, rt)

    h2_body, h2_meta = _send_over_http2(ctx, parts, path, body, headers)
    assert h2_meta["error"] is None, (
        f"ConverseStream over hand-signed HTTP/2 to {parts.netloc} failed: {h2_meta['error']!r}"
    )
    assert h2_meta["alpnProtocol"] == "h2", (
        f"the HTTP/2 client negotiated ALPN protocol {h2_meta['alpnProtocol']!r}; expected 'h2' — "
        "the connection must offer only h2 for this to be an HTTP/2 request"
    )
    _assert_event_stream_response(h2_meta["status"], h2_meta["headers"], h2_body, transport="HTTP/2")

    h1_body, h1_meta = _send_over_http1(ctx, parts, path, body, headers)
    assert h1_meta["protocol_version"] == 11, (
        f"the HTTP/1.1 control negotiated protocol version {h1_meta['protocol_version']!r}; "
        "expected 11 (HTTP/1.1) — the control must not be an HTTP/2 request"
    )
    _assert_event_stream_response(
        str(h1_meta["status"]), h1_meta["headers"], h1_body, transport="HTTP/1.1"
    )


def _build_request(ctx, rt):
    """Serialize ConverseStream for ``_MODEL_ID`` and SigV4-sign it for the client's own endpoint."""
    params = {
        "modelId": _MODEL_ID,
        "messages": [{"role": "user", "content": [{"text": _PROMPT}]}],
        "inferenceConfig": {"maxTokens": _MAX_TOKENS},
    }
    op_model = rt.meta.service_model.operation_model("ConverseStream")
    serializer = botocore.serialize.create_serializer(rt.meta.service_model.protocol)
    request_dict = serializer.serialize_to_request(params, op_model)

    endpoint = rt.meta.endpoint_url
    parts = urlsplit(endpoint)
    body = request_dict["body"]

    raw_creds = rt._request_signer._credentials
    frozen = (
        raw_creds.get_frozen_credentials()
        if hasattr(raw_creds, "get_frozen_credentials")
        else raw_creds
    )
    sign_headers = dict(request_dict["headers"])
    sign_headers["host"] = parts.netloc
    awsreq = AWSRequest(
        method="POST", url=endpoint + request_dict["url_path"], data=body, headers=sign_headers
    )
    SigV4Auth(frozen, rt._request_signer.signing_name, ctx.region).add_auth(awsreq)
    signed = {k.lower(): v for k, v in awsreq.headers.items() if k.lower() != "host"}
    return parts, request_dict["url_path"], body, signed


def _send_over_http2(ctx, parts, path: str, body: bytes, signed_headers: dict[str, str]):
    """Send one hand-signed unary HTTP/2 request over a connection that offers only ALPN h2."""
    headers = dict(signed_headers)
    headers[":method"] = "POST"
    headers[":path"] = path
    headers[":authority"] = parts.netloc

    workdir = tempfile.mkdtemp(prefix="sim2real-bedrock-h2-")
    ctx.on_cleanup(lambda: shutil.rmtree(workdir, ignore_errors=True))
    script = os.path.join(workdir, "h2.js")
    conf_path = os.path.join(workdir, "conf.json")
    out_path = os.path.join(workdir, "body.bin")
    with open(script, "w", encoding="utf-8") as handle:
        handle.write(_NODE_SOURCE)
    with open(conf_path, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "origin": f"{parts.scheme}://{parts.netloc}",
                "headers": headers,
                "body": base64.b64encode(body).decode(),
                "out": out_path,
                "maxMs": _RESPONSE_MS,
            },
            handle,
        )

    completed = subprocess.run(
        ["node", script, conf_path],
        env=ctx.subprocess_env(),
        capture_output=True,
        timeout=(_RESPONSE_MS / 1000.0) + 30.0,
        check=False,
    )
    assert completed.returncode == 0, (
        f"the node HTTP/2 client exited {completed.returncode}; stderr: "
        f"{completed.stderr.decode(errors='replace')[:500]!r}"
    )
    lines = [line for line in completed.stdout.decode().splitlines() if line.strip()]
    assert lines, (
        "the node HTTP/2 client printed no result line; stderr: "
        f"{completed.stderr.decode(errors='replace')[:500]!r}"
    )
    meta = json.loads(lines[-1])
    with open(out_path, "rb") as handle:
        raw = handle.read()
    return raw, meta


def _send_over_http1(ctx, parts, path: str, body: bytes, signed_headers: dict[str, str]):
    """Send the same hand-signed request as plain HTTP/1.1, the control for the HTTP/2 path."""
    url = f"{parts.scheme}://{parts.netloc}{path}"
    resp = requests.request(
        "POST", url, headers=signed_headers, data=body, timeout=30, verify=ctx.http_verify
    )
    meta = {
        "status": resp.status_code,
        "headers": {k.lower(): v for k, v in resp.headers.items()},
        "protocol_version": resp.raw.version,
    }
    return resp.content, meta


def _assert_event_stream_response(status: str, headers: dict[str, str], raw: bytes, *, transport: str):
    """Assert the raw response is a well-formed ConverseStream event stream for a 1-token answer."""
    assert status == "200", (
        f"ConverseStream over hand-signed {transport} returned :status {status!r}; expected '200'"
    )
    content_type = headers.get("content-type")
    assert content_type == _EVENTSTREAM_CONTENT_TYPE, (
        f"ConverseStream over {transport} responded with content-type {content_type!r}; expected "
        f"{_EVENTSTREAM_CONTENT_TYPE!r}"
    )
    assert raw, f"the {transport} response body was empty; expected an event-stream carrying the answer"

    messages = _parse_eventstream(raw)
    assert messages, (
        f"parsed zero complete event-stream messages out of {len(raw)} {transport} response bytes; "
        f"the first 32 bytes were {raw[:32]!r}"
    )
    event_types = []
    payloads = {}
    for frame_headers, payload in messages:
        assert frame_headers.get(":message-type") == "event", (
            f"a {transport} event-stream message carried :message-type "
            f"{frame_headers.get(':message-type')!r}; expected 'event'"
        )
        assert frame_headers.get(":content-type") == "application/json", (
            f"a {transport} event-stream message carried :content-type "
            f"{frame_headers.get(':content-type')!r}; expected 'application/json'"
        )
        event_type = frame_headers.get(":event-type")
        event_types.append(event_type)
        payloads[event_type] = json.loads(payload)

    assert tuple(event_types) == _EXPECTED_EVENT_TYPES, (
        f"ConverseStream over {transport} delivered event types {event_types!r}; expected exactly "
        f"{_EXPECTED_EVENT_TYPES!r} for a {_MAX_TOKENS}-token answer"
    )
    assert payloads["messageStart"]["role"] == "assistant", (
        f"ConverseStream over {transport}'s messageStart carried role "
        f"{payloads['messageStart']['role']!r}; expected 'assistant'"
    )
    assert payloads["messageStop"]["stopReason"] == "max_tokens", (
        f"ConverseStream over {transport}'s messageStop carried stopReason "
        f"{payloads['messageStop']['stopReason']!r}; expected 'max_tokens' for a "
        f"{_MAX_TOKENS}-token limit"
    )
    usage = payloads["metadata"]["usage"]
    assert usage["outputTokens"] == _MAX_TOKENS, (
        f"ConverseStream over {transport}'s metadata reported outputTokens "
        f"{usage['outputTokens']!r}; expected exactly {_MAX_TOKENS}"
    )
    assert usage["totalTokens"] == usage["inputTokens"] + usage["outputTokens"], (
        f"ConverseStream over {transport}'s metadata reported totalTokens {usage['totalTokens']!r}, "
        f"inputTokens {usage['inputTokens']!r} and outputTokens {usage['outputTokens']!r}, which do "
        "not sum"
    )


def _parse_eventstream(raw: bytes) -> list[tuple[dict[str, str], bytes]]:
    """Decode AWS event-stream messages, RECOMPUTING both CRC-32s over the bytes on the wire.

    Layout per message:
      [total_length:4][headers_length:4][prelude_crc:4][headers][payload][message_crc:4]
    A trailing partial message is dropped; a message whose CRC does not recompute RAISES.
    """
    messages: list[tuple[dict[str, str], bytes]] = []
    offset = 0
    while offset + 16 <= len(raw):
        total_length = int.from_bytes(raw[offset : offset + 4], "big")
        headers_length = int.from_bytes(raw[offset + 4 : offset + 8], "big")
        prelude_crc = int.from_bytes(raw[offset + 8 : offset + 12], "big")
        computed_prelude = zlib.crc32(raw[offset : offset + 8])
        if computed_prelude != prelude_crc:
            raise AssertionError(
                f"event-stream prelude CRC-32 mismatch at byte {offset}: the wire says "
                f"{prelude_crc:#010x}, CRC-32 over the 8 prelude bytes "
                f"{raw[offset : offset + 8]!r} is {computed_prelude:#010x}"
            )
        if total_length < 16 or headers_length > total_length - 16:
            raise AssertionError(
                f"event-stream message at byte {offset} declares total_length={total_length} and "
                f"headers_length={headers_length}, which cannot both be true"
            )
        if offset + total_length > len(raw):
            break  # the stream was cut mid-message; a partial tail is expected, not a defect.
        message = raw[offset : offset + total_length]
        message_crc = int.from_bytes(message[-4:], "big")
        computed_message = zlib.crc32(message[:-4])
        if computed_message != message_crc:
            raise AssertionError(
                f"event-stream message CRC-32 mismatch at byte {offset}: the wire says "
                f"{message_crc:#010x}, CRC-32 over the preceding {total_length - 4} bytes is "
                f"{computed_message:#010x}"
            )
        headers = _parse_headers(message[12 : 12 + headers_length])
        payload = message[12 + headers_length : -4]
        messages.append((headers, payload))
        offset += total_length
    return messages


def _parse_headers(buf: bytes) -> dict[str, str]:
    """Decode an event-stream header block. Bedrock Runtime uses value type 7 (UTF-8 string)."""
    headers: dict[str, str] = {}
    index = 0
    while index < len(buf):
        name_length = buf[index]
        index += 1
        name = buf[index : index + name_length].decode("utf-8")
        index += name_length
        value_type = buf[index]
        index += 1
        if value_type != 7:
            raise AssertionError(
                f"event-stream header {name!r} used value type {value_type}; expected 7 (UTF-8 "
                "string)"
            )
        value_length = int.from_bytes(buf[index : index + 2], "big")
        index += 2
        headers[name] = buf[index : index + value_length].decode("utf-8")
        index += value_length
    return headers


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
