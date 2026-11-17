"""converse-stream-hand-signed-http2-model-needing-inference-profile-rejected-as-plain-json."""
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
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "converse-stream-hand-signed-http2-model-needing-inference-profile-rejected-as-plain-json"
GROUP = "overly-permissive"
SERVICES = ["bedrock-runtime"]

#: Reachable only through a cross-region inference profile, never by its bare id.
_PROFILE_ONLY_MODEL = "amazon.nova-micro-v1:0"
#: On-demand invocable by its bare id; the positive control.
_ON_DEMAND_MODEL = "amazon.nova-lite-v1:0"
_PROMPT = "Say hi."
_MAX_TOKENS = 1
_EVENTSTREAM_CONTENT_TYPE = "application/vnd.amazon.eventstream"
_EXPECTED_MESSAGE = (
    "Invocation of model ID amazon.nova-micro-v1:0 with on-demand throughput isn’t "
    "supported. Retry your request with the ID or ARN of an inference profile that contains "
    "this model."
)
_RESPONSE_MS = 20000

#: A minimal HTTP/2 unary request/response client. node:http2 is stdlib, nothing to install.
_NODE_SOURCE = r"""
const http2 = require("node:http2");
const fs = require("node:fs");
const conf = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const out = fs.createWriteStream(conf.out);
const result = { status: null, headers: {}, error: null };
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
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """ConverseStream over hand-signed HTTP/2 refuses a model reachable only through a
    cross-region inference profile with ValidationException delivered as plain JSON, never an
    event stream; the same request against an on-demand model succeeds and returns one instead.
    """
    require_tools("node")
    rt = ctx.client("bedrock-runtime")

    try:
        rt.converse(
            modelId=_PROFILE_ONLY_MODEL,
            messages=[{"role": "user", "content": [{"text": _PROMPT}]}],
            inferenceConfig={"maxTokens": _MAX_TOKENS},
        )
        raise AssertionError(
            f"Converse against {_PROFILE_ONLY_MODEL!r} unexpectedly succeeded through the SDK; "
            "the raw ConverseStream refusal asserted below would then be testing an unreachable "
            "model, not a routing rule"
        )
    except ClientError as exc:
        sdk_error = exc.response.get("Error", {})
        sdk_pair = (sdk_error.get("Code"), sdk_error.get("Message"))
        assert sdk_pair == ("ValidationException", _EXPECTED_MESSAGE), (
            f"Converse against {_PROFILE_ONLY_MODEL!r} through the SDK was refused with "
            f"{sdk_pair!r}; expected ('ValidationException', {_EXPECTED_MESSAGE!r}) before testing "
            "the same refusal over raw ConverseStream"
        )

    rejected_body, rejected_meta = _send_converse_stream(ctx, rt, _PROFILE_ONLY_MODEL)
    assert rejected_meta["error"] is None, (
        f"ConverseStream for {_PROFILE_ONLY_MODEL!r} over hand-signed HTTP/2 failed at the "
        f"transport: {rejected_meta['error']!r}"
    )
    assert rejected_meta["status"] == "400", (
        f"ConverseStream for {_PROFILE_ONLY_MODEL!r} over hand-signed HTTP/2 returned :status "
        f"{rejected_meta['status']!r}; expected '400'"
    )
    rejected_content_type = rejected_meta["headers"].get("content-type")
    assert rejected_content_type == "application/json", (
        f"the refusal's content-type was {rejected_content_type!r}; expected 'application/json' "
        "— an error must never be delivered as an event stream"
    )
    error_type_header = rejected_meta["headers"].get("x-amzn-errortype", "")
    code = error_type_header.split(":", 1)[0]
    parsed = json.loads(rejected_body)
    assert (code, parsed) == ("ValidationException", {"message": _EXPECTED_MESSAGE}), (
        f"the refusal carried x-amzn-errortype {error_type_header!r} and body {parsed!r}; "
        f"expected code 'ValidationException' and body {{'message': {_EXPECTED_MESSAGE!r}}}"
    )

    control_body, control_meta = _send_converse_stream(ctx, rt, _ON_DEMAND_MODEL)
    assert control_meta["error"] is None, (
        f"the positive control (ConverseStream for {_ON_DEMAND_MODEL!r}) failed at the "
        f"transport: {control_meta['error']!r}"
    )
    assert control_meta["status"] == "200", (
        f"the positive control returned :status {control_meta['status']!r}; expected '200' — "
        f"without this the refusal above cannot be told from a blanket outage"
    )
    control_content_type = control_meta["headers"].get("content-type")
    assert control_content_type == _EVENTSTREAM_CONTENT_TYPE, (
        f"the positive control's content-type was {control_content_type!r}; expected "
        f"{_EVENTSTREAM_CONTENT_TYPE!r}"
    )
    messages = _parse_eventstream(control_body)
    event_types = [headers.get(":event-type") for headers, _ in messages]
    expected_types = [
        "messageStart", "contentBlockDelta", "contentBlockStop", "messageStop", "metadata",
    ]
    assert event_types == expected_types, (
        f"the positive control's event stream carried event types {event_types!r}; expected "
        f"exactly {expected_types!r} for a {_MAX_TOKENS}-token answer"
    )


def _send_converse_stream(ctx, rt, model_id: str):
    """Serialize, SigV4-sign and send one ConverseStream request over hand-signed HTTP/2."""
    params = {
        "modelId": model_id,
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

    h2_headers = dict(signed)
    h2_headers[":method"] = "POST"
    h2_headers[":path"] = request_dict["url_path"]
    h2_headers[":authority"] = parts.netloc

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
                "headers": h2_headers,
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
