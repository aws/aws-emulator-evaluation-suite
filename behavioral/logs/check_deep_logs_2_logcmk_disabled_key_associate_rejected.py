"""deep-logs-2-logcmk-disabled-key-associate-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deep-logs-2-logcmk-disabled-key-associate-rejected"
GROUP = "kms-data-plane"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:control", "plane:data")
def run(ctx) -> None:
    """AssociateKmsKey with a disabled CMK fails with InvalidParameterException and leaves the group
    unencrypted; after EnableKey the identical call succeeds and events round-trip through the key.
    """
    from botocore.exceptions import ClientError

    logs = ctx.client("logs")
    kms = ctx.client("kms")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    key_arn = kms.create_key(
        Description=ctx.unique_name("sim2real-logcmk-dis-"),
        Policy=_key_policy(account_id, ctx.region, grant_logs=True),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7))

    group = ctx.unique_name("sim2real-logcmk-dis-")
    stream = "s1"
    logs.create_log_group(logGroupName=group, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    logs.create_log_stream(logGroupName=group, logStreamName=stream)

    kms.disable_key(KeyId=key_arn)
    state = kms.describe_key(KeyId=key_arn)["KeyMetadata"]["KeyState"]
    assert state == "Disabled", f"key state after DisableKey is {state!r}, expected 'Disabled'"

    code, message = _error(
        lambda: logs.associate_kms_key(logGroupName=group, kmsKeyId=key_arn), ClientError
    )
    assert code == "InvalidParameterException", (
        f"AssociateKmsKey with a disabled key returned {code!r}, expected InvalidParameterException"
    )
    assert message == "The specified KMS key is marked as disabled.", (
        f"AssociateKmsKey with a disabled key returned message {message!r}"
    )
    after_reject = _describe_group(logs, group)
    assert "kmsKeyId" not in after_reject, (
        f"a rejected AssociateKmsKey left kmsKeyId={after_reject.get('kmsKeyId')!r} on the group"
    )

    # Positive control: same key, same group, same call -- now enabled.
    kms.enable_key(KeyId=key_arn)
    state = kms.describe_key(KeyId=key_arn)["KeyMetadata"]["KeyState"]
    assert state == "Enabled", f"key state after EnableKey is {state!r}, expected 'Enabled'"
    _associate_with_retry(logs, ClientError, logGroupName=group, kmsKeyId=key_arn)
    associated = _poll(lambda: _describe_group(logs, group),
                       lambda g: g.get("kmsKeyId") == key_arn,
                       timeout_s=60, what="kmsKeyId to reflect the re-enabled key")
    assert associated["kmsKeyId"] == key_arn, (
        f"kmsKeyId is {associated.get('kmsKeyId')!r} after associating the re-enabled key"
    )

    msg = f"after-enable {group}"
    logs.put_log_events(logGroupName=group, logStreamName=stream,
                        logEvents=[{"timestamp": int(time.time() * 1000), "message": msg}])
    read = _poll(lambda: _read_messages(logs, group, stream), lambda m: m == [msg],
                 timeout_s=60, what="the event to be readable through the re-enabled key")
    assert read == [msg], f"GetLogEvents through the re-enabled CMK returned {read!r}"


def _error(fn, client_error) -> tuple[str, str]:
    """Return the (code, message) fn() raised; fail if the call succeeds."""
    try:
        fn()
    except client_error as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("call unexpectedly SUCCEEDED; real AWS rejects it")


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
    # A key enabled a moment ago can still read as disabled to CloudWatch Logs; that surfaces as
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


def _read_messages(logs, group: str, stream: str) -> list:
    out, token = [], None
    for _ in range(50):
        kw = {"logGroupName": group, "logStreamName": stream, "startFromHead": True}
        if token:
            kw["nextToken"] = token
        resp = logs.get_log_events(**kw)
        out.extend(e["message"] for e in resp["events"])
        nxt = resp.get("nextForwardToken")
        if nxt == token:
            break
        token = nxt
    return out


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
