"""subscribe-to-shard-event-stream-framing-over-a-hand-signed-http2-request."""
from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import tempfile
import time
import zlib
from urllib.parse import urlsplit

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "subscribe-to-shard-event-stream-framing-over-a-hand-signed-http2-request"
GROUP = "data-plane"
SERVICES = ["kinesis"]

# Confirmed against real AWS (us-west-2), two consecutive green replays, ~27.5s wall clock each:
#   - The event-stream framing IS [total_length:4][headers_length:4][prelude_crc:4][headers]
#     [payload][message_crc:4], both CRCs CRC-32 (zlib) over the preceding bytes, header value
#     type 7 (UTF-8 string) throughout — the hand-signed HTTP/2 request and byte-level parser below
#     work as written.
#   - SigV4 signing `host` = the endpoint netloc while sending only `:authority` (no literal `host`
#     header) over HTTP/2 IS accepted by AWS — this is the signing shape real SDKs use.
#   - An `initial-response` message DOES precede the first SubscribeToShardEvent.
#   - A SubscribeToShardEvent's embedded JSON payload carries :content-type
#     'application/x-amz-json-1.1' (the AWS JSON 1.1 protocol content type), NOT generic
#     'application/json' as first hypothesized.
#   - `ContinuationSequenceNumber` does NOT equal the last delivered record's SequenceNumber —
#     Kinesis sequence numbers are not dense integers, so the two are never equal or adjacent. What
#     IS true, confirmed twice: it is strictly greater than the SequenceNumber of the last record in
#     the batch that carries it, and it is non-decreasing across every event in the subscription
#     (including record-less heartbeats sent while idle).

_N_RECORDS = 5
_PAYLOADS = tuple(f"h2-frame-probe-{i}".encode() for i in range(_N_RECORDS))
_PARTITION_KEY = "h2-pk"
#: How long the Node client holds the HTTP/2 stream open collecting raw frames.
_SUBSCRIBE_MS = 15000
_TARGET = "Kinesis_20131202.SubscribeToShard"
_EVENTSTREAM_CONTENT_TYPE = "application/vnd.amazon.eventstream"

#: A minimal HTTP/2 client. node:http2 is in the standard library, so there is nothing to install.
_NODE_SOURCE = r"""
const http2 = require("node:http2");
const fs = require("node:fs");

const conf = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const out = fs.createWriteStream(conf.out);
const result = { status: null, headers: {}, error: null, bytes: 0 };
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
req.on("data", (c) => { result.bytes += c.length; out.write(c); });
req.on("error", (e) => { result.error = "stream: " + e.message; done(); });
req.on("end", () => done());
req.write(Buffer.from(conf.body, "base64"));
req.end();

setTimeout(() => {
  req.close(http2.constants.NGHTTP2_NO_ERROR);
  session.close();
  done();
}, conf.maxMs);
"""


@tags(
    "axis:happy-path",
    "cap:c6",
    "concern:data-plane",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """SubscribeToShard's enhanced fan-out response is a real HTTP/2 vnd.amazon.eventstream: every
    frame's prelude and message CRC-32 recompute correctly over the bytes on the wire, and the
    records inside carry exactly the sequence numbers PutRecord returned, in order."""
    require_tools("node")
    kinesis = ctx.client("kinesis")
    stream = _create_active_stream(ctx)
    shard_id = _single_shard_id(ctx, stream["name"])

    put_seqs = [
        kinesis.put_record(
            StreamName=stream["name"], Data=payload, PartitionKey=_PARTITION_KEY
        )["SequenceNumber"]
        for payload in _PAYLOADS
    ]

    consumer_name = ctx.unique_name("sim2real-efo-")
    consumer_arn = kinesis.register_stream_consumer(
        StreamARN=stream["arn"], ConsumerName=consumer_name
    )["Consumer"]["ConsumerARN"]
    ctx.on_cleanup(lambda: kinesis.deregister_stream_consumer(ConsumerARN=consumer_arn))
    _poll_until(
        lambda: kinesis.describe_stream_consumer(ConsumerARN=consumer_arn)[
            "ConsumerDescription"
        ]["ConsumerStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=180.0,
        interval_s=3.0,
        description=f"enhanced fan-out consumer {consumer_name} to reach ACTIVE",
    )

    # ---- Hand-sign the SubscribeToShard request against the endpoint ctx configured ----
    endpoint = kinesis.meta.endpoint_url
    body = json.dumps(
        {
            "ConsumerARN": consumer_arn,
            "ShardId": shard_id,
            "StartingPosition": {"Type": "TRIM_HORIZON"},
        }
    ).encode()
    signed = _sign(ctx, endpoint, body)

    raw, meta = _stream_over_http2(ctx, endpoint, signed, body)

    assert meta["error"] is None, (
        f"the HTTP/2 client failed talking to {endpoint}: {meta['error']}. SubscribeToShard is only "
        "offered over HTTP/2, so a target that cannot serve h2 has no enhanced fan-out data plane"
    )
    assert meta["status"] == "200", (
        f"SubscribeToShard over hand-signed HTTP/2 returned :status {meta['status']!r}; expected "
        f"'200'. Response headers: {meta['headers']!r}"
    )
    content_type = meta["headers"].get("content-type")
    assert content_type == _EVENTSTREAM_CONTENT_TYPE, (
        f"SubscribeToShard responded with content-type {content_type!r}; expected "
        f"{_EVENTSTREAM_CONTENT_TYPE!r} — the response must be event-stream framed, not plain JSON"
    )
    assert raw, (
        f"the HTTP/2 response body was empty after {_SUBSCRIBE_MS}ms; expected at least one "
        f"event-stream frame carrying the {_N_RECORDS} records already on {shard_id}"
    )

    # ---- Recompute the framing byte-for-byte. No recording can carry this ----
    messages = _parse_eventstream(raw)
    assert messages, (
        f"parsed zero complete event-stream messages out of {len(raw)} response bytes; the first "
        f"32 bytes were {raw[:32]!r}"
    )

    events = []
    for headers, payload in messages:
        assert headers.get(":message-type") == "event", (
            f"an event-stream message carried :message-type {headers.get(':message-type')!r}; "
            f"expected 'event'. Full headers: {headers!r}"
        )
        if headers.get(":event-type") == "SubscribeToShardEvent":
            assert headers.get(":content-type") == "application/x-amz-json-1.1", (
                f"a SubscribeToShardEvent carried :content-type "
                f"{headers.get(':content-type')!r}; expected 'application/x-amz-json-1.1' — the "
                "embedded payload follows the same AWS JSON 1.1 protocol as the API itself, not "
                "generic 'application/json'"
            )
            events.append(json.loads(payload))
    assert events, (
        "no message had :event-type == 'SubscribeToShardEvent'; the event types seen were "
        f"{[h.get(':event-type') for h, _ in messages]!r}"
    )

    delivered_seqs: list[str] = []
    delivered_data: list[bytes] = []
    for event in events:
        for record in event["Records"]:
            delivered_seqs.append(record["SequenceNumber"])
            delivered_data.append(base64.b64decode(record["Data"]))

    assert delivered_seqs == put_seqs, (
        f"the raw HTTP/2 event stream delivered sequence numbers {delivered_seqs}; expected exactly "
        f"the {_N_RECORDS} PutRecord returned, in order: {put_seqs}"
    )
    assert delivered_data == list(_PAYLOADS), (
        f"the raw HTTP/2 event stream delivered payloads {delivered_data!r}; expected "
        f"{list(_PAYLOADS)!r} — the JSON payload's Data field is base64 over the exact bytes put"
    )
    seqs_int = [int(s) for s in put_seqs]
    continuations = [int(event["ContinuationSequenceNumber"]) for event in events]
    assert continuations == sorted(continuations), (
        "ContinuationSequenceNumber must be non-decreasing across the SubscribeToShardEvents of "
        "one subscription — Kinesis advances it on every event, including record-less heartbeats "
        f"sent while the subscription is idle; saw {continuations!r}"
    )
    last_record_event = max(i for i, event in enumerate(events) if event["Records"])
    last_record_continuation = continuations[last_record_event]
    assert last_record_continuation > seqs_int[-1], (
        f"the SubscribeToShardEvent that delivered the last PutRecord'd record reported "
        f"ContinuationSequenceNumber {last_record_continuation}; expected it strictly greater than "
        f"that record's own SequenceNumber {seqs_int[-1]} — Kinesis sequence numbers are not dense, "
        "so the continuation token is a distinct forward-pointing checkpoint, never equal to a "
        "delivered record's own number"
    )
    assert all(event["MillisBehindLatest"] >= 0 for event in events), (
        "a SubscribeToShardEvent reported a negative MillisBehindLatest: "
        f"{[e['MillisBehindLatest'] for e in events]!r}"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    """Bounded retry that RAISES on timeout — never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"timed out after {timeout_s}s waiting for {description}; last observation: {last!r}"
    )


def _sign(ctx, endpoint: str, body: bytes) -> dict[str, str]:
    """SigV4-sign a SubscribeToShard request for whatever endpoint ctx pointed the client at.

    The credentials come off the ctx-built client, so this follows the same principal (and the same
    OU-account guard) as every other call in the check — it never resolves the ambient chain.
    """
    kinesis = ctx.client("kinesis")
    raw_creds = kinesis._request_signer._credentials
    frozen = (
        raw_creds.get_frozen_credentials()
        if hasattr(raw_creds, "get_frozen_credentials")
        else raw_creds
    )
    netloc = urlsplit(endpoint).netloc
    request = AWSRequest(
        method="POST",
        url=endpoint,
        data=body,
        headers={
            "host": netloc,
            "content-type": "application/x-amz-json-1.1",
            "x-amz-target": _TARGET,
        },
    )
    SigV4Auth(frozen, "kinesis", ctx.region).add_auth(request)
    return {k.lower(): v for k, v in request.headers.items()}


def _stream_over_http2(ctx, endpoint: str, signed: dict[str, str], body: bytes):
    """Drive one HTTP/2 SubscribeToShard request through node:http2 and return (raw_bytes, meta)."""
    parts = urlsplit(endpoint)
    origin = f"{parts.scheme}://{parts.netloc}"
    path = parts.path or "/"
    # :authority carries the authority in HTTP/2; `host` was signed but must not be sent. See
    # hypothesis 5.
    headers = {k: v for k, v in signed.items() if k != "host"}
    headers[":method"] = "POST"
    headers[":path"] = path
    headers[":authority"] = parts.netloc

    workdir = tempfile.mkdtemp(prefix="sim2real-kinesis-h2-")
    ctx.on_cleanup(lambda: shutil.rmtree(workdir, ignore_errors=True))
    script = os.path.join(workdir, "h2.js")
    conf_path = os.path.join(workdir, "conf.json")
    out_path = os.path.join(workdir, "body.bin")
    with open(script, "w", encoding="utf-8") as handle:
        handle.write(_NODE_SOURCE)
    with open(conf_path, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "origin": origin,
                "headers": headers,
                "body": base64.b64encode(body).decode(),
                "out": out_path,
                "maxMs": _SUBSCRIBE_MS,
            },
            handle,
        )

    completed = subprocess.run(
        ["node", script, conf_path],
        env=ctx.subprocess_env(),
        capture_output=True,
        timeout=(_SUBSCRIBE_MS / 1000.0) + 60.0,
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
    A trailing partial message (the stream was cut at _SUBSCRIBE_MS) is dropped, but a message whose
    CRC does not recompute RAISES — that is the assertion this whole check exists for.
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
    """Decode an event-stream header block. Kinesis uses value type 7 (UTF-8 string) throughout."""
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
                "string), the only type Kinesis is expected to emit (see hypothesis 3)"
            )
        value_length = int.from_bytes(buf[index : index + 2], "big")
        index += 2
        headers[name] = buf[index : index + value_length].decode("utf-8")
        index += value_length
    return headers


def _create_active_stream(ctx, *, shard_count: int = 1) -> dict[str, str]:
    """Create-or-adopt a provisioned stream, tagged, and wait until it is ACTIVE."""
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-kds-")
    try:
        kinesis.create_stream(
            StreamName=name,
            ShardCount=shard_count,
            StreamModeDetails={"StreamMode": "PROVISIONED"},
            Tags={"sim2real": "behavioral", "sim2real-check": CHECK},
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceInUseException":
            raise
    ctx.on_cleanup(
        lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    )
    summary = _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"],
        lambda s: s["StreamStatus"] == "ACTIVE",
        timeout_s=240.0,
        interval_s=3.0,
        description=f"stream {name} to reach ACTIVE",
    )
    return {"name": name, "arn": summary["StreamARN"]}


def _single_shard_id(ctx, stream_name: str) -> str:
    """ListShards can lag ACTIVE briefly; poll until exactly one shard is addressable."""
    kinesis = ctx.client("kinesis")

    def probe() -> list:
        try:
            return kinesis.list_shards(StreamName=stream_name)["Shards"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("ResourceInUseException", "ResourceNotFoundException"):
                return []
            raise

    shards = _poll_until(
        probe,
        lambda s: len(s) == 1,
        timeout_s=90.0,
        interval_s=3.0,
        description=f"exactly one shard to be addressable on {stream_name}",
    )
    return shards[0]["ShardId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
