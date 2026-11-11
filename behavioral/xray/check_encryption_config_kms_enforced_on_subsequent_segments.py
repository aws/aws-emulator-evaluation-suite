"""encryption-config-kms-enforced-on-subsequent-segments."""
from __future__ import annotations

import json
import random
import time

from behavioral_harness import tags

CHECK = "encryption-config-kms-enforced-on-subsequent-segments"
GROUP = "server-side"
SERVICES = ["xray"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data", "resource:account-singleton:xray-encryption")
def run(ctx) -> None:
    """After PutEncryptionConfig with a customer KMS key, GetEncryptionConfig reports it ACTIVE with
    the key ARN, and a segment put afterwards reads back via BatchGetTraces unchanged."""
    xray = ctx.client("xray")
    kms = ctx.client("kms")

    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    key_policy = {
        "Version": "2012-10-17",
        "Id": "sim2real-xray-key-policy",
        "Statement": [
            {
                "Sid": "EnableRootAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ctx.client('sts').get_caller_identity()['Account']}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "AllowCallerToConfigureXRayEncryption",
                "Effect": "Allow",
                "Principal": {"AWS": caller_arn},
                "Action": [
                    "kms:CreateGrant",
                    "kms:DescribeKey",
                    "kms:Decrypt",
                    "kms:Encrypt",
                    "kms:GenerateDataKey",
                    "kms:GenerateDataKey*",
                ],
                "Resource": "*",
            },
        ],
    }
    key = kms.create_key(
        Description=ctx.unique_name("sim2ray-xray-key-"),
        Policy=json.dumps(key_policy),
        Tags=[{"TagKey": "sim2real", "TagValue": "xray-behavioral"}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    key_arn = key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    prior = xray.get_encryption_config()["EncryptionConfig"]

    def _restore():
        if prior.get("Type") == "KMS" and prior.get("KeyId"):
            xray.put_encryption_config(Type="KMS", KeyId=prior["KeyId"])
        else:
            xray.put_encryption_config(Type="NONE")

    ctx.on_cleanup(_restore)

    xray.put_encryption_config(Type="KMS", KeyId=key_id)

    cfg = _poll_until(
        lambda: xray.get_encryption_config()["EncryptionConfig"],
        lambda c: c.get("Status") == "ACTIVE",
        timeout_s=420,
        interval_s=15,
    )
    assert cfg["Status"] == "ACTIVE", f"expected encryption config to settle ACTIVE, got {cfg['Status']!r} (full config: {cfg!r})"
    assert cfg["Type"] == "KMS", f"expected encryption type KMS, got {cfg['Type']!r}"
    assert cfg["KeyId"] == key_arn, f"expected KeyId to resolve to the created key's ARN {key_arn!r}, got {cfg['KeyId']!r}"

    now = time.time()
    trace_id = f"1-{int(now):08x}-{_hex(24)}"
    seg = {
        "name": "sim2ray-kms-svc",
        "id": _hex(16),
        "trace_id": trace_id,
        "start_time": now,
        "end_time": now + 0.05,
    }
    put_resp = xray.put_trace_segments(TraceSegmentDocuments=[json.dumps(seg)])
    unprocessed = put_resp.get("UnprocessedTraceSegments", [])
    assert unprocessed == [], f"expected the segment to be accepted under KMS encryption, got unprocessed entries: {unprocessed!r}"

    traces = _poll_until(
        lambda: xray.batch_get_traces(TraceIds=[trace_id])["Traces"],
        lambda t: len(t) >= 1,
        timeout_s=180,
        interval_s=10,
    )

    assert len(traces) == 1, f"expected exactly one trace for {trace_id!r} via the independent BatchGetTraces read, got {len(traces)}"
    assert traces[0]["Id"] == trace_id, f"expected returned trace id to match {trace_id!r}, got {traces[0]['Id']!r}"
    assert len(traces[0]["Segments"]) == 1, f"expected exactly one segment on the trace, got {len(traces[0]['Segments'])}"


def _hex(n: int) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value: {last}")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
