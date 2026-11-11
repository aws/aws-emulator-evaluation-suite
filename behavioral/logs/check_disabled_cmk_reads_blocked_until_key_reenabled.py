"""disabled-cmk-reads-blocked-until-key-reenabled."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disabled-cmk-reads-blocked-until-key-reenabled"
GROUP = "kms-key-state"
SERVICES = ["logs"]


@tags(
    "cap:c2",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "axis:rejection",
)
def run(ctx) -> None:
    """Events in a CMK-encrypted log group stop being served when the key is disabled, and are
    served again, unchanged, once the key is re-enabled.
    """
    logs = ctx.client("logs")
    kms = ctx.client("kms")
    account = ctx.client("sts").get_caller_identity()["Account"]

    group = ctx.unique_name("sim2real-behav-logs-kmsoff-")
    stream = ctx.unique_name("sim2real-behav-logs-kmsoff-s-")

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "AccountRootAdmin", "Effect": "Allow",
             "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
             "Action": "kms:*", "Resource": "*"},
            {"Sid": "LogsForThisGroup", "Effect": "Allow",
             "Principal": {"Service": f"logs.{ctx.region}.amazonaws.com"},
             "Action": ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*",
                        "kms:GenerateDataKey*", "kms:Describe*"],
             "Resource": "*",
             "Condition": {"ArnEquals": {"kms:EncryptionContext:aws:logs:arn":
                 f"arn:aws:logs:{ctx.region}:{account}:log-group:{group}"}}},
        ],
    }
    key_arn = kms.create_key(
        Policy=json.dumps(policy),
        Description=f"sim2real {CHECK}",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7))

    ctx.on_cleanup(lambda: _delete_group_if_present(logs, group))
    _create_with_retry(logs, group, key_arn)
    logs.create_log_stream(logGroupName=group, logStreamName=stream)

    ts = int(time.time() * 1000)
    sent = [(ts, "written while the CMK is enabled"), (ts + 1, "second line, same key")]
    logs.put_log_events(logGroupName=group, logStreamName=stream,
                        logEvents=[{"timestamp": t, "message": m} for t, m in sent])
    before = _poll(lambda: _events(logs, group, stream), lambda got: len(got) >= 2, 60)
    assert before == sent, f"enabled-key read returned {before!r}, expected {sent!r}"

    # Re-enable is registered as cleanup so the key is usable again even if an assertion fails.
    kms.disable_key(KeyId=key_arn)
    ctx.on_cleanup(lambda: _enable_if_disabled(kms, key_arn))
    state = kms.describe_key(KeyId=key_arn)["KeyMetadata"]["KeyState"]
    assert state == "Disabled", f"key state after DisableKey is {state!r}"

    # AWS does not raise: GetLogEvents stays a 200 with an empty events list while disabled.
    hidden = _poll(lambda: _events(logs, group, stream), lambda got: got == [], 300)
    assert hidden == [], (
        f"GetLogEvents still served {hidden!r} 300s after the group's CMK was disabled"
    )
    g = _describe_group(logs, group)
    assert g is not None and g.get("kmsKeyId") == key_arn, (
        f"disabling the key must not disassociate it from the group; described {g!r}"
    )

    # After EnableKey the very same events come back.
    kms.enable_key(KeyId=key_arn)
    restored = _poll(lambda: _events(logs, group, stream), lambda got: len(got) >= 2, 300)
    assert restored == sent, (
        f"after EnableKey the group served {restored!r}, expected the original {sent!r}"
    )


def _events(logs: Any, group: str, stream: str) -> list[tuple[int, str]]:
    resp = logs.get_log_events(logGroupName=group, logStreamName=stream, startFromHead=True)
    return [(e["timestamp"], e["message"]) for e in resp["events"]]


def _poll(fn, cond, timeout_s: float, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last = fn()
    while not cond(last) and time.monotonic() < deadline:
        time.sleep(interval_s)
        last = fn()
    return last


def _create_with_retry(logs: Any, name: str, key_arn: str, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            logs.create_log_group(logGroupName=name, kmsKeyId=key_arn, tags={"sim2real": CHECK})
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in {"AccessDeniedException",
                                                     "InvalidParameterException"}:
                raise
            last = exc
            time.sleep(5)
    raise AssertionError(f"CreateLogGroup with the CMK never succeeded within {timeout_s}s: {last!r}")


def _describe_group(logs: Any, name: str) -> dict | None:
    for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=name):
        for g in page["logGroups"]:
            if g["logGroupName"] == name:
                return g
    return None


def _delete_group_if_present(logs: Any, name: str) -> None:
    try:
        logs.delete_log_group(logGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _enable_if_disabled(kms: Any, key_arn: str) -> None:
    if kms.describe_key(KeyId=key_arn)["KeyMetadata"]["KeyState"] == "Disabled":
        kms.enable_key(KeyId=key_arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
