"""put-record-signed-for-a-different-authority-host-rejected."""
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

CHECK = "put-record-signed-for-a-different-authority-host-rejected"
GROUP = "data-plane"
SERVICES = ["kinesis"]

_PAYLOAD = b"h2-mismatched-authority-probe"
_PARTITION_KEY = "h2-mismatch-pk"
_RESPONSE_MS = 10000
_OTHER_HOST = "attacker-controlled.example.com"

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
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A PutRecord signed for the real endpoint host but sent with a different :authority is
    refused with InvalidSignatureException, stores nothing, and a correctly signed retry succeeds."""
    require_tools("node")
    kinesis = ctx.client("kinesis")
    stream = _create_active_stream(ctx)
    shard_id = _single_shard_id(ctx, stream["name"])
    endpoint = kinesis.meta.endpoint_url
    endpoint_netloc = urlsplit(endpoint).netloc

    before_iterator = kinesis.get_shard_iterator(
        StreamName=stream["name"], ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]

    bad_body = json.dumps(
        {
            "StreamName": stream["name"],
            "Data": base64.b64encode(_PAYLOAD).decode(),
            "PartitionKey": _PARTITION_KEY,
        }
    ).encode()
    bad_resp, bad_meta = _send_over_http2(
        ctx,
        endpoint,
        "Kinesis_20131202.PutRecord",
        bad_body,
        endpoint_netloc=endpoint_netloc,
        authority=_OTHER_HOST,
    )
    assert bad_meta["error"] is None, (
        f"PutRecord signed for {endpoint_netloc!r} but sent with :authority {_OTHER_HOST!r} failed "
        f"at the transport instead of reaching the service: {bad_meta['error']!r}"
    )
    assert bad_meta["status"] == "400", (
        f"PutRecord signed for {endpoint_netloc!r} but sent with :authority {_OTHER_HOST!r} "
        f"returned :status {bad_meta['status']!r}; expected '400'. Response body: {bad_resp!r}"
    )
    bad_json = json.loads(bad_resp)
    assert bad_json["__type"] == "InvalidSignatureException", (
        f"a PutRecord with mismatched :authority returned __type {bad_json.get('__type')!r}; "
        "expected 'InvalidSignatureException'"
    )
    assert bad_json["message"] == (
        "The request signature we calculated does not match the signature you provided. "
        "Check your AWS Secret Access Key and signing method. Consult the service documentation "
        "for details."
    ), f"the InvalidSignatureException message was {bad_json['message']!r}"

    records = kinesis.get_records(ShardIterator=before_iterator, Limit=10)["Records"]
    assert records == [], (
        "GetRecords returned records after the mismatched-:authority PutRecord was refused; "
        f"expected none to have been stored: {records!r}"
    )

    good_body = json.dumps(
        {
            "StreamName": stream["name"],
            "Data": base64.b64encode(_PAYLOAD).decode(),
            "PartitionKey": _PARTITION_KEY,
        }
    ).encode()
    good_resp, good_meta = _send_over_http2(
        ctx,
        endpoint,
        "Kinesis_20131202.PutRecord",
        good_body,
        endpoint_netloc=endpoint_netloc,
        authority=endpoint_netloc,
    )
    assert good_meta["error"] is None, (
        f"the positive control (correctly signed PutRecord) failed: {good_meta['error']!r}"
    )
    assert good_meta["status"] == "200", (
        f"the positive control (correctly signed PutRecord) returned :status "
        f"{good_meta['status']!r}; expected '200'. Response body: {good_resp!r}"
    )
    good_json = json.loads(good_resp)

    after_records = _poll_until(
        lambda: kinesis.get_records(ShardIterator=before_iterator, Limit=10)["Records"],
        lambda records: len(records) >= 1,
        timeout_s=30.0,
        interval_s=2.0,
        description="the correctly signed record to become readable",
    )
    assert len(after_records) == 1, (
        f"GetRecords returned {len(after_records)} record(s) after the positive control; expected "
        f"exactly 1: {after_records!r}"
    )
    assert after_records[0]["SequenceNumber"] == good_json["SequenceNumber"], (
        f"GetRecords returned SequenceNumber {after_records[0]['SequenceNumber']!r}; expected the "
        f"positive control's own {good_json['SequenceNumber']!r}"
    )
    assert after_records[0]["Data"] == _PAYLOAD, (
        f"GetRecords returned data {after_records[0]['Data']!r} for the positive control's "
        f"record; expected {_PAYLOAD!r}"
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
    ctx, endpoint: str, target: str, body: bytes, *, endpoint_netloc: str, authority: str
):
    """Hand-sign ``target`` for ``endpoint_netloc`` and send it with the wire ``:authority`` set to
    ``authority``, which may differ from the host the signature covers.

    Returns ``(response_body_str, meta)`` where ``meta`` carries ``status``, ``headers``, ``error``.
    """
    signed = _sign(ctx, endpoint, target, body, sign_netloc=endpoint_netloc)
    parts = urlsplit(endpoint)
    origin = f"{parts.scheme}://{parts.netloc}"
    headers = {k: v for k, v in signed.items() if k != "host"}
    headers[":method"] = "POST"
    headers[":path"] = parts.path or "/"
    headers[":authority"] = authority

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
    name = ctx.unique_name("sim2real-kds-h2m-")
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
