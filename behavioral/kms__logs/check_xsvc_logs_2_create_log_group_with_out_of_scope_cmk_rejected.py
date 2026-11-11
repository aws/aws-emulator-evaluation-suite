"""xsvc-logs-2-create-log-group-with-out-of-scope-cmk-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-logs-2-create-log-group-with-out-of-scope-cmk-rejected"
GROUP = "kms-key-policy-scope"
SERVICES = ["kms", "logs"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:data-plane", "dp:api",
      "plane:control", "plane:data")
def run(ctx) -> None:
    """CreateLogGroup with a CMK whose policy admits only group A's ARN succeeds for A, which then
    serves events, but is refused for group B with AccessDeniedException and B is not created.
    """
    logs = ctx.client("logs")
    kms = ctx.client("kms")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    group_a = ctx.unique_name("sim2real-xsvc-lg-create-a-")
    group_b = ctx.unique_name("sim2real-xsvc-lg-create-b-")
    arn_a = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{group_a}"

    key_arn = _create_logs_key(ctx, kms, account_id, arn_a)

    # Policy propagation is retried on the code a not-yet-usable key produces.
    _register_group_teardown(ctx, logs, group_a)
    _retry_code(
        lambda: logs.create_log_group(logGroupName=group_a, kmsKeyId=key_arn,
                                      tags={"sim2real-check": CHECK}),
        "InvalidParameterException", timeout_s=120.0,
        description=f"CreateLogGroup {group_a!r} with its in-scope CMK",
    )
    assert _groups_named(logs, group_a) == [key_arn], (
        f"group A must exist exactly once with kmsKeyId {key_arn!r}; got {_groups_named(logs, group_a)!r}"
    )

    # Teardown is registered before the call so a wrongly created B does not leak.
    _register_group_teardown(ctx, logs, group_b)
    code, message = _error(lambda: logs.create_log_group(
        logGroupName=group_b, kmsKeyId=key_arn, tags={"sim2real-check": CHECK}))
    assert code == "AccessDeniedException", (
        f"CreateLogGroup with an out-of-scope CMK must be rejected with AccessDeniedException; "
        f"got {code!r} ({message!r})"
    )
    arn_b = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{group_b}"
    expected_message = (
        f"The specified KMS key does not exist or is not allowed to be used with Arn '{arn_b}'"
    )
    assert message == expected_message, (
        f"CreateLogGroup refusal message: expected {expected_message!r}, got {message!r}"
    )
    leaked = _groups_named(logs, group_b)
    assert leaked == [], f"a rejected CreateLogGroup must not create group B; found {leaked!r}"

    logs.create_log_stream(logGroupName=group_a, logStreamName="app")
    marker = ctx.unique_name("evt-")
    messages = [f"{marker} {i} é中" for i in range(3)]
    base = int(time.time() * 1000)
    resp = logs.put_log_events(
        logGroupName=group_a, logStreamName="app",
        logEvents=[{"timestamp": base + i, "message": m} for i, m in enumerate(messages)],
    )
    assert "rejectedLogEventsInfo" not in resp, f"PutLogEvents partially rejected: {resp!r}"
    got = _poll_until(
        lambda: [e["message"] for e in logs.get_log_events(
            logGroupName=group_a, logStreamName="app", startFromHead=True)["events"]],
        lambda m: len(m) >= len(messages), timeout_s=60.0,
        description="the events on the CMK-encrypted group to be readable")
    assert got == messages, f"GetLogEvents returned {got!r}, expected exactly {messages!r}"


def _error(fn):
    """Return (code, message) of the ClientError fn raises; raise if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("the call was expected to be rejected but SUCCEEDED")


def _retry_code(fn, transient_code, *, timeout_s, description):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != transient_code or time.monotonic() >= deadline:
                raise AssertionError(f"{description} failed: {exc.response['Error']!r}") from exc
            time.sleep(5.0)


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description}; last: {last!r}")


def _groups_named(logs, group):
    """kmsKeyId of every group whose name is exactly ``group`` (a prefix query, paginated)."""
    out = []
    for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=group):
        out.extend(g.get("kmsKeyId") for g in page["logGroups"] if g["logGroupName"] == group)
    return out


def _quiet(fn, *ok_codes):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ok_codes:
            raise


def _create_logs_key(ctx, kms, account_id, group_arn):
    """Create a CMK usable by CloudWatch Logs only for ``group_arn``.

    Its cleanup is registered first, so LIFO runs it after every log group is gone.
    """
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "AccountAdmin", "Effect": "Allow",
             "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
             "Action": "kms:*", "Resource": "*"},
            {"Sid": "CloudWatchLogsForOneGroup", "Effect": "Allow",
             "Principal": {"Service": f"logs.{ctx.region}.amazonaws.com"},
             "Action": ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*",
                        "kms:GenerateDataKey*", "kms:Describe*"],
             "Resource": "*",
             "Condition": {"ArnEquals": {"kms:EncryptionContext:aws:logs:arn": group_arn}}},
        ],
    }
    key_arn = kms.create_key(
        Policy=json.dumps(policy),
        Description=ctx.unique_name("sim2real-xsvc-logs-key-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7))
    return key_arn


def _register_group_teardown(ctx, logs, group):
    def _teardown():
        # DisassociateKmsKey BEFORE the group goes, and both before the key is scheduled.
        _quiet(lambda: logs.disassociate_kms_key(logGroupName=group), "ResourceNotFoundException")
        _quiet(lambda: logs.delete_log_group(logGroupName=group), "ResourceNotFoundException")

    ctx.on_cleanup(_teardown)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
