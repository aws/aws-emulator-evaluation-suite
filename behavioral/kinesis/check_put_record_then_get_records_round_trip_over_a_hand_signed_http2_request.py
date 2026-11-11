"""put-record-then-get-records-round-trip-over-a-hand-signed-http2-request."""
from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import tempfile
import time
from urllib.parse import urlsplit

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "put-record-then-get-records-round-trip-over-a-hand-signed-http2-request"
GROUP = "data-plane"
SERVICES = ["kinesis"]

_PAYLOAD = b"h2-unary-roundtrip-probe"
_PARTITION_KEY = "h2-unary-pk"
_RESPONSE_MS = 10000
_GET_RECORDS_DEADLINE_S = 30.0

#: A minimal HTTP/2 unary request/response client. node:http2 is stdlib, nothing to install.
_NODE_SOURCE = r"""
const http2 = require("node:http2");
const fs = require("node:fs");
const conf = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const result = { status: null, headers: {}, error: null, body: "" };
let finished = false;
function done() {
  if (finished) return;
  finished = true;
  process.stdout.write(JSON.stringify(result) + "\n");
  process.exit(0);
}
const session = http2.connect(conf.origin);
session.on("error", (e) => { result.error = "session: " + e.message; done(); });
const req = session.request(conf.headers);
req.on("response", (h) => {
  result.status = String(h[":status"]);
  for (const k of Object.keys(h)) { result.headers[k] = String(h[k]); }
});
req.setEncoding("utf8");
req.on("data", (c) => { result.body += c; });
req.on("error", (e) => { result.error = "stream: " + e.message; done(); });
req.on("end", () => { session.close(); done(); });
req.write(Buffer.from(conf.body, "base64"));
req.end();
setTimeout(() => { result.error = result.error || "timeout"; try { session.close(); } catch (e) {} done(); }, conf.maxMs);
"""


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """PutRecord then GetRecords, both sent as hand-signed unary requests over a raw HTTP/2
    connection, return :status 200 and the record round-trips byte-exact."""
    require_tools("node")
    kinesis = ctx.client("kinesis")
    stream = _create_active_stream(ctx)
    shard_id = _single_shard_id(ctx, stream["name"])
    endpoint = kinesis.meta.endpoint_url

    put_body = json.dumps(
        {
            "StreamName": stream["name"],
            "Data": base64.b64encode(_PAYLOAD).decode(),
            "PartitionKey": _PARTITION_KEY,
        }
    ).encode()
    put_resp, put_meta = _send_over_http2(
        ctx, endpoint, "Kinesis_20131202.PutRecord", put_body, endpoint_netloc=urlsplit(endpoint).netloc
    )
    assert put_meta["error"] is None, (
        f"PutRecord over hand-signed HTTP/2 to {endpoint} failed: {put_meta['error']!r}"
    )
    assert put_meta["status"] == "200", (
        f"PutRecord over hand-signed HTTP/2 returned :status {put_meta['status']!r}, expected "
        f"'200'. Response body: {put_resp!r}"
    )
    put_json = json.loads(put_resp)
    sequence_number = put_json["SequenceNumber"]
    assert put_json["ShardId"] == shard_id, (
        f"PutRecord over HTTP/2 reported ShardId {put_json['ShardId']!r}; expected the stream's "
        f"only shard {shard_id!r}"
    )

    iterator = kinesis.get_shard_iterator(
        StreamName=stream["name"], ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]

    records: list = []
    deadline = time.monotonic() + _GET_RECORDS_DEADLINE_S
    while True:
        get_body = json.dumps({"ShardIterator": iterator, "Limit": 10}).encode()
        get_resp, get_meta = _send_over_http2(
            ctx, endpoint, "Kinesis_20131202.GetRecords", get_body,
            endpoint_netloc=urlsplit(endpoint).netloc,
        )
        assert get_meta["error"] is None, (
            f"GetRecords over hand-signed HTTP/2 to {endpoint} failed: {get_meta['error']!r}"
        )
        assert get_meta["status"] == "200", (
            f"GetRecords over hand-signed HTTP/2 returned :status {get_meta['status']!r}, expected "
            f"'200'. Response body: {get_resp!r}"
        )
        get_json = json.loads(get_resp)
        records.extend(get_json["Records"])
        iterator = get_json.get("NextShardIterator")
        if records or not iterator:
            break
        if time.monotonic() > deadline:
            raise AssertionError(
                f"GetRecords over HTTP/2 returned no record within {_GET_RECORDS_DEADLINE_S}s "
                f"of following NextShardIterator; last response: {get_json!r}"
            )
        time.sleep(1.0)
    assert len(records) == 1, (
        f"GetRecords over HTTP/2 returned {len(records)} record(s); expected exactly 1. Records: "
        f"{records!r}"
    )
    record = records[0]
    assert record["SequenceNumber"] == sequence_number, (
        f"GetRecords over HTTP/2 delivered SequenceNumber {record['SequenceNumber']!r}; expected "
        f"the one PutRecord returned over the same transport: {sequence_number!r}"
    )
    assert record["PartitionKey"] == _PARTITION_KEY, (
        f"GetRecords over HTTP/2 delivered PartitionKey {record['PartitionKey']!r}; expected "
        f"{_PARTITION_KEY!r}"
    )
    delivered_data = base64.b64decode(record["Data"])
    assert delivered_data == _PAYLOAD, (
        f"GetRecords over HTTP/2 delivered data {delivered_data!r}; expected the exact bytes put "
        f"{_PAYLOAD!r}"
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


def _sign(ctx, endpoint: str, target: str, body: bytes, *, sign_netloc: str) -> dict[str, str]:
    """SigV4-sign a Kinesis request for ``sign_netloc``, the host the signature covers."""
    kinesis = ctx.client("kinesis")
    raw_creds = kinesis._request_signer._credentials
    frozen = (
        raw_creds.get_frozen_credentials()
        if hasattr(raw_creds, "get_frozen_credentials")
        else raw_creds
    )
    request = AWSRequest(
        method="POST",
        url=endpoint,
        data=body,
        headers={
            "host": sign_netloc,
            "content-type": "application/x-amz-json-1.1",
            "x-amz-target": target,
        },
    )
    SigV4Auth(frozen, "kinesis", ctx.region).add_auth(request)
    return {k.lower(): v for k, v in request.headers.items()}


def _send_over_http2(
    ctx, endpoint: str, target: str, body: bytes, *, endpoint_netloc: str, authority: str | None = None
):
    """Hand-sign ``target`` for ``endpoint_netloc`` and send it as one HTTP/2 request.

    ``authority`` overrides the wire ``:authority``; defaults to the host the signature covers.
    Returns ``(response_body_str, meta)`` where ``meta`` carries ``status``, ``headers``, ``error``.
    """
    signed = _sign(ctx, endpoint, target, body, sign_netloc=endpoint_netloc)
    parts = urlsplit(endpoint)
    origin = f"{parts.scheme}://{parts.netloc}"
    headers = {k: v for k, v in signed.items() if k != "host"}
    headers[":method"] = "POST"
    headers[":path"] = parts.path or "/"
    headers[":authority"] = authority or endpoint_netloc

    workdir = tempfile.mkdtemp(prefix="sim2real-kinesis-h2-")
    ctx.on_cleanup(lambda: shutil.rmtree(workdir, ignore_errors=True))
    script = os.path.join(workdir, "h2.js")
    conf_path = os.path.join(workdir, "conf.json")
    with open(script, "w", encoding="utf-8") as handle:
        handle.write(_NODE_SOURCE)
    with open(conf_path, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "origin": origin,
                "headers": headers,
                "body": base64.b64encode(body).decode(),
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
    return meta.pop("body"), meta


def _create_active_stream(ctx, *, shard_count: int = 1) -> dict[str, str]:
    """Create-or-adopt a provisioned stream, tagged, and wait until it is ACTIVE."""
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-kds-h2u-")
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
