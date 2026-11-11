"""deep-logs-2-logcmk-encrypted-group-put-get-roundtrip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deep-logs-2-logcmk-encrypted-group-put-get-roundtrip"
GROUP = "kms-data-plane"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """In a log group encrypted with a customer-managed KMS key, GetLogEvents returns the written messages and
    timestamps in order, the last two from the tail, and FilterLogEvents returns exactly the ERROR subset.
    """
    from botocore.exceptions import ClientError

    logs = ctx.client("logs")
    kms = ctx.client("kms")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    key_arn = kms.create_key(
        Description=ctx.unique_name("sim2real-logcmk-rt-"),
        Policy=_key_policy(account_id, ctx.region, grant_logs=True),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7))

    group = ctx.unique_name("sim2real-logcmk-rt-")
    stream = "s1"
    logs.create_log_group(logGroupName=group, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    logs.create_log_stream(logGroupName=group, logStreamName=stream)

    _associate_with_retry(logs, ClientError, logGroupName=group, kmsKeyId=key_arn)
    described = _poll(
        lambda: _describe_group(logs, group),
        lambda g: g.get("kmsKeyId") == key_arn,
        timeout_s=60, what="kmsKeyId to reflect the associated CMK",
    )
    assert described["kmsKeyId"] == key_arn, (
        f"kmsKeyId after AssociateKmsKey is {described.get('kmsKeyId')!r}, expected {key_arn!r}"
    )

    base = int(time.time() * 1000) - 5000
    messages = [
        "INFO boot sequence started",
        "ERROR disk quota exceeded on /var",
        json.dumps({"level": "WARN", "msg": "latency", "p99_ms": 812}),
        "INFO café ☃ unicode payload survives encryption",
        "ERROR upstream returned 503",
    ]
    events = [{"timestamp": base + i * 10, "message": m} for i, m in enumerate(messages)]
    put = logs.put_log_events(logGroupName=group, logStreamName=stream, logEvents=events)
    assert "rejectedLogEventsInfo" not in put, (
        f"PutLogEvents rejected part of a valid batch: {put.get('rejectedLogEventsInfo')!r}"
    )

    read = _poll(
        lambda: _read_events(logs, group, stream),
        lambda evs: len(evs) >= len(messages),
        timeout_s=60, what="all 5 events to become readable through the CMK",
    )
    assert [e["message"] for e in read] == messages, (
        f"decrypted messages {[e['message'] for e in read]!r} differ from written {messages!r}"
    )
    assert [e["timestamp"] for e in read] == [e["timestamp"] for e in events], (
        f"timestamps {[e['timestamp'] for e in read]!r} differ from written "
        f"{[e['timestamp'] for e in events]!r}"
    )

    tail = logs.get_log_events(
        logGroupName=group, logStreamName=stream, startFromHead=False, limit=2
    )["events"]
    assert [e["message"] for e in tail] == messages[-2:], (
        f"startFromHead=False limit=2 returned {[e['message'] for e in tail]!r}, "
        f"expected the last two {messages[-2:]!r}"
    )

    filtered = _filter_messages(logs, group, '"ERROR"')
    expected_err = [m for m in messages if "ERROR" in m]
    assert filtered == expected_err, (
        f"FilterLogEvents over the encrypted group returned {filtered!r}, expected {expected_err!r}"
    )


def _key_policy(account_id: str, region: str, *, grant_logs: bool) -> str:
    statements = [
        {
            "Sid": "RootFullAccess",
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "kms:*",
            "Resource": "*",
        }
    ]
    if grant_logs:
        statements.append(
            {
                "Sid": "AllowCloudWatchLogs",
                "Effect": "Allow",
                "Principal": {"Service": f"logs.{region}.amazonaws.com"},
                "Action": [
                    "kms:Encrypt*",
                    "kms:Decrypt*",
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKey*",
                    "kms:Describe*",
                ],
                "Resource": "*",
            }
        )
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


def _associate_with_retry(logs, client_error, *, timeout_s: float = 60.0, **kwargs) -> None:
    # A key created a moment ago can still be propagating to CloudWatch Logs; that surfaces as
    # InvalidParameterException. Retry only that code, bounded.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            logs.associate_kms_key(**kwargs)
            return
        except client_error as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException":
                raise
            if time.monotonic() > deadline:
                raise
            time.sleep(3)


def _describe_group(logs, group: str) -> dict:
    for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=group):
        for g in page["logGroups"]:
            if g["logGroupName"] == group:
                return g
    raise AssertionError(f"log group {group!r} not found by DescribeLogGroups")


def _read_events(logs, group: str, stream: str) -> list:
    out, token = [], None
    for _ in range(50):
        kw = {"logGroupName": group, "logStreamName": stream, "startFromHead": True}
        if token:
            kw["nextToken"] = token
        resp = logs.get_log_events(**kw)
        out.extend(resp["events"])
        nxt = resp.get("nextForwardToken")
        if nxt == token:
            break
        token = nxt
    return out


def _filter_messages(logs, group: str, pattern: str) -> list:
    out = []
    for page in logs.get_paginator("filter_log_events").paginate(
        logGroupName=group, filterPattern=pattern
    ):
        out.extend(page["events"])
    return [e["message"] for e in sorted(out, key=lambda e: e["timestamp"])]


def _poll(probe, predicate, *, timeout_s: float, what: str, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {what}; last={last!r}")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
