"""xsvc-logs-2-cmk-scoped-to-group-a-rejects-associate-on-group-b."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-logs-2-cmk-scoped-to-group-a-rejects-associate-on-group-b"
GROUP = "kms-key-policy-scope"
SERVICES = ["kms", "logs"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:data-plane", "dp:api",
      "plane:control", "plane:data")
def run(ctx) -> None:
    """A CMK whose policy admits CloudWatch Logs only for log group A's encryption context
    associates with A but is refused on group B with AccessDeniedException, leaving B unencrypted;
    A then serves events under the key while B still ingests unencrypted.
    """
    logs = ctx.client("logs")
    kms = ctx.client("kms")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    group_a = ctx.unique_name("sim2real-xsvc-lg-scope-a-")
    group_b = ctx.unique_name("sim2real-xsvc-lg-scope-b-")
    arn_a = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{group_a}"

    key_arn = _create_logs_key(ctx, kms, account_id, arn_a)

    _create_log_group(ctx, logs, group_a)
    _create_log_group(ctx, logs, group_b)

    # Key-policy propagation is retried, bounded.
    _retry_code(
        lambda: logs.associate_kms_key(logGroupName=group_a, kmsKeyId=key_arn),
        "InvalidParameterException", timeout_s=120.0,
        description=f"AssociateKmsKey on in-scope group {group_a!r}",
    )
    assert _kms_key_of(logs, group_a) == key_arn, (
        f"group A kmsKeyId is {_kms_key_of(logs, group_a)!r}, expected {key_arn!r}"
    )

    code, message = _error(lambda: logs.associate_kms_key(logGroupName=group_b, kmsKeyId=key_arn))
    assert code == "AccessDeniedException", (
        f"AssociateKmsKey on out-of-scope group B must be rejected with AccessDeniedException; "
        f"got {code!r} ({message!r})"
    )
    arn_b = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{group_b}"
    assert message == (
        f"The specified KMS key does not exist or is not allowed to be used with Arn '{arn_b}'"
    ), message
    b_key = _kms_key_of(logs, group_b)
    assert b_key is None, f"a rejected association must leave group B unencrypted; kmsKeyId={b_key!r}"

    marker = ctx.unique_name("evt-")
    for group in (group_a, group_b):
        logs.create_log_stream(logGroupName=group, logStreamName="app")
        resp = logs.put_log_events(
            logGroupName=group, logStreamName="app",
            logEvents=[{"timestamp": int(time.time() * 1000), "message": f"{marker} {group}"}],
        )
        assert "rejectedLogEventsInfo" not in resp, f"PutLogEvents on {group!r} partially rejected: {resp!r}"
    for group in (group_a, group_b):
        got = _poll_until(
            lambda g=group: [e["message"] for e in logs.get_log_events(
                logGroupName=g, logStreamName="app", startFromHead=True)["events"]],
            lambda m: len(m) >= 1, timeout_s=60.0, description=f"the event on {group!r} to be readable")
        assert got == [f"{marker} {group}"], f"GetLogEvents on {group!r} returned {got!r}"
    assert _kms_key_of(logs, group_a) == key_arn and _kms_key_of(logs, group_b) is None, (
        "the association state must be unchanged by data-plane traffic: "
        f"A={_kms_key_of(logs, group_a)!r} B={_kms_key_of(logs, group_b)!r}"
    )


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


def _kms_key_of(logs, group):
    found = [g for g in logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
             if g["logGroupName"] == group]
    assert len(found) == 1, f"expected exactly one log group named {group!r}, found {len(found)}"
    return found[0].get("kmsKeyId")


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


def _create_log_group(ctx, logs, group, **kwargs):
    logs.create_log_group(logGroupName=group, tags={"sim2real-check": CHECK}, **kwargs)

    def _teardown():
        # DisassociateKmsKey BEFORE the group goes, and both before the key is scheduled.
        _quiet(lambda: logs.disassociate_kms_key(logGroupName=group), "ResourceNotFoundException")
        _quiet(lambda: logs.delete_log_group(logGroupName=group), "ResourceNotFoundException")

    ctx.on_cleanup(_teardown)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
