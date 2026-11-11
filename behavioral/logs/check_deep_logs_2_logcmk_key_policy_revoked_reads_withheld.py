"""deep-logs-2-logcmk-key-policy-revoked-reads-withheld."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deep-logs-2-logcmk-key-policy-revoked-reads-withheld"
GROUP = "kms-data-plane"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Dropping the Logs statement from a CMK's key policy silently empties GetLogEvents for the
    encrypted group (no error) while an unencrypted twin keeps reading; restoring it brings it back.
    """
    from botocore.exceptions import ClientError

    logs = ctx.client("logs")
    kms = ctx.client("kms")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    full_policy = _key_policy(account_id, ctx.region, grant_logs=True)
    revoked_policy = _key_policy(account_id, ctx.region, grant_logs=False)

    key_arn = kms.create_key(
        Description=ctx.unique_name("sim2real-logcmk-rv-"),
        Policy=full_policy,
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7))

    enc_group = ctx.unique_name("sim2real-logcmk-rv-enc-")
    logs.create_log_group(logGroupName=enc_group, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=enc_group))
    twin_group = ctx.unique_name("sim2real-logcmk-rv-twin-")
    logs.create_log_group(logGroupName=twin_group, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=twin_group))
    stream = "s1"
    for g in (enc_group, twin_group):
        logs.create_log_stream(logGroupName=g, logStreamName=stream)

    _associate_with_retry(logs, ClientError, logGroupName=enc_group, kmsKeyId=key_arn)
    _poll(lambda: _describe_group(logs, enc_group), lambda g: g.get("kmsKeyId") == key_arn,
          timeout_s=60, what="kmsKeyId to reflect the associated CMK")

    now = int(time.time() * 1000)
    enc_msg = f"encrypted-payload {enc_group}"
    twin_msg = f"plaintext-payload {twin_group}"
    logs.put_log_events(logGroupName=enc_group, logStreamName=stream,
                        logEvents=[{"timestamp": now, "message": enc_msg}])
    logs.put_log_events(logGroupName=twin_group, logStreamName=stream,
                        logEvents=[{"timestamp": now, "message": twin_msg}])

    # Positive control BEFORE the break: both groups read their event.
    before = _poll(lambda: _read_messages(logs, enc_group, stream), lambda m: m == [enc_msg],
                   timeout_s=60, what="the encrypted event to be readable before revocation")
    assert before == [enc_msg], f"encrypted group read {before!r} before revocation"
    twin_before = _poll(lambda: _read_messages(logs, twin_group, stream),
                        lambda m: m == [twin_msg], timeout_s=60,
                        what="the twin event to be readable")
    assert twin_before == [twin_msg], f"twin group read {twin_before!r}"

    # Drop the CloudWatch Logs statement. AWS does not raise here: GetLogEvents stays a 200 and
    # its events list goes empty within ~10s.
    kms.put_key_policy(KeyId=key_arn, PolicyName="default", Policy=revoked_policy)
    withheld = _poll(lambda: _read_messages(logs, enc_group, stream), lambda m: m == [],
                     timeout_s=180, interval_s=5,
                     what="GetLogEvents to stop returning the event encrypted under the revoked key")
    assert withheld == [], f"encrypted event still readable after revocation: {withheld!r}"

    # The effect is caused by the policy change: the unencrypted twin, read at the same moment,
    # is unaffected, and the association itself is still in place.
    twin_during = _read_messages(logs, twin_group, stream)
    assert twin_during == [twin_msg], (
        f"twin group (no CMK) read {twin_during!r} while the CMK was revoked; expected [{twin_msg!r}]"
    )
    assert _describe_group(logs, enc_group).get("kmsKeyId") == key_arn, (
        "revoking the key policy must not silently disassociate the key from the log group"
    )

    # Recovery: restore the statement and demand the identical call succeeds again.
    kms.put_key_policy(KeyId=key_arn, PolicyName="default", Policy=full_policy)
    restored = _poll(lambda: _read_messages(logs, enc_group, stream), lambda m: m == [enc_msg],
                     timeout_s=180, interval_s=5,
                     what="the encrypted event to be readable again after the policy is restored")
    assert restored == [enc_msg], f"after restoring the key policy the group read {restored!r}"


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
