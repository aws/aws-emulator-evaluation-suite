"""kms-grant-scoped-to-another-log-group-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "kms-grant-scoped-to-another-log-group-rejected"
GROUP = "kms-encryption-context"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A CMK whose logs grant is conditioned on one group's ARN (kms:EncryptionContext:aws:logs:arn)
    encrypts and serves that group, but CreateLogGroup for another name is AccessDenied and absent.
    """
    logs = ctx.client("logs")
    kms = ctx.client("kms")
    account = ctx.client("sts").get_caller_identity()["Account"]

    allowed = ctx.unique_name("sim2real-behav-logs-kmsscope-ok-")
    other = ctx.unique_name("sim2real-behav-logs-kmsscope-no-")
    stream = ctx.unique_name("sim2real-behav-logs-kmsscope-s-")

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AccountRootAdmin",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "LogsForOneGroupOnly",
                "Effect": "Allow",
                "Principal": {"Service": f"logs.{ctx.region}.amazonaws.com"},
                "Action": ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*",
                           "kms:GenerateDataKey*", "kms:Describe*"],
                "Resource": "*",
                "Condition": {"ArnEquals": {
                    "kms:EncryptionContext:aws:logs:arn":
                        f"arn:aws:logs:{ctx.region}:{account}:log-group:{allowed}"}},
            },
        ],
    }
    key_arn = kms.create_key(
        Policy=json.dumps(policy),
        Description=f"sim2real {CHECK}",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7))

    # Positive control first: it also serves as the key-policy propagation barrier, so the
    # negative below is evaluated against a policy that is demonstrably live.
    ctx.on_cleanup(lambda: _delete_group_if_present(logs, allowed))
    _create_with_retry(logs, allowed, key_arn)
    g = _describe_group(logs, allowed)
    assert g is not None and g.get("kmsKeyId") == key_arn, (
        f"permitted group should carry kmsKeyId {key_arn!r}, described {g!r}"
    )
    logs.create_log_stream(logGroupName=allowed, logStreamName=stream)
    ts = int(time.time() * 1000)
    sent = [(ts, "scoped-cmk alpha"), (ts + 1, "scoped-cmk beta")]
    logs.put_log_events(logGroupName=allowed, logStreamName=stream,
                        logEvents=[{"timestamp": t, "message": m} for t, m in sent])
    got = _read_events(logs, allowed, stream, expected=len(sent))
    assert got == sent, f"permitted encrypted group returned {got!r}, expected {sent!r}"

    # Same key, a log group whose ARN the grant does not name.
    ctx.on_cleanup(lambda: _delete_group_if_present(logs, other))
    code, message = _error(lambda: logs.create_log_group(logGroupName=other, kmsKeyId=key_arn))
    assert code == "AccessDeniedException", (
        f"CreateLogGroup with a CMK scoped to another group's ARN returned {code!r}, "
        f"expected AccessDeniedException"
    )
    expected = (
        "The specified KMS key does not exist or is not allowed to be used with Arn "
        f"'arn:aws:logs:{ctx.region}:{account}:log-group:{other}'"
    )
    assert message == expected, f"CreateLogGroup refusal message {message!r}, expected {expected!r}"
    assert _describe_group(logs, other) is None, (
        f"log group {other!r} exists although its CreateLogGroup was refused"
    )
    # The key is untouched by the refusal: the permitted group is still readable.
    assert _read_events(logs, allowed, stream, expected=len(sent)) == sent, (
        "the permitted group stopped serving its events after the refused create"
    )


def _create_with_retry(logs: Any, name: str, key_arn: str, timeout_s: float = 60.0) -> None:
    # A freshly created key policy can briefly read as not-yet-effective to the logs principal.
    deadline = time.monotonic() + timeout_s
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            logs.create_log_group(logGroupName=name, kmsKeyId=key_arn,
                                  tags={"sim2real": CHECK})
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in {"AccessDeniedException",
                                                     "InvalidParameterException"}:
                raise
            last = exc
            time.sleep(5)
    raise AssertionError(f"permitted CreateLogGroup never succeeded within {timeout_s}s: {last!r}")


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


def _read_events(logs: Any, group: str, stream: str, expected: int,
                 timeout_s: float = 60.0) -> list[tuple[int, str]]:
    deadline = time.monotonic() + timeout_s
    got: list[tuple[int, str]] = []
    while time.monotonic() < deadline:
        resp = logs.get_log_events(logGroupName=group, logStreamName=stream, startFromHead=True)
        got = [(e["timestamp"], e["message"]) for e in resp["events"]]
        if len(got) >= expected:
            return got
        time.sleep(2)
    raise AssertionError(f"{group}/{stream} held {len(got)} of {expected} events: {got!r}")


def _error(fn: Any) -> tuple[str, str | None]:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
