"""deep-logs-2-logcmk-events-bound-to-ingest-key."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deep-logs-2-logcmk-events-bound-to-ingest-key"
GROUP = "kms-data-plane"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Each event stays bound to the key associated when it was ingested: after A -> B -> none,
    revoking one key's Logs grant withholds exactly that key's events while the others still read.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_AssociateKmsKey.html
    """
    from botocore.exceptions import ClientError

    logs = ctx.client("logs")
    kms = ctx.client("kms")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    full_policy = _key_policy(account_id, ctx.region, grant_logs=True)
    revoked_policy = _key_policy(account_id, ctx.region, grant_logs=False)

    key_a = kms.create_key(Description=ctx.unique_name("sim2real-logcmk-bind-a-"),
                           Policy=full_policy,
                           Tags=[{"TagKey": "sim2real", "TagValue": CHECK}])["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_a, PendingWindowInDays=7))
    key_b = kms.create_key(Description=ctx.unique_name("sim2real-logcmk-bind-b-"),
                           Policy=full_policy,
                           Tags=[{"TagKey": "sim2real", "TagValue": CHECK}])["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_b, PendingWindowInDays=7))

    group = ctx.unique_name("sim2real-logcmk-bind-")
    stream = "s1"
    logs.create_log_group(logGroupName=group, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    logs.create_log_stream(logGroupName=group, logStreamName=stream)

    def read():
        return _read_messages(logs, group, stream)

    def put(msg):
        logs.put_log_events(logGroupName=group, logStreamName=stream,
                            logEvents=[{"timestamp": int(time.time() * 1000), "message": msg}])

    m_a, m_b, m_plain = "gen-1 under key A", "gen-2 under key B", "gen-3 plaintext"

    _associate_with_retry(logs, ClientError, logGroupName=group, kmsKeyId=key_a)
    _poll(lambda: _describe_group(logs, group), lambda g: g.get("kmsKeyId") == key_a,
          timeout_s=60, what="kmsKeyId to become key A")
    put(m_a)
    _poll(read, lambda m: m == [m_a], timeout_s=60, what="the key-A event to be readable")

    _associate_with_retry(logs, ClientError, logGroupName=group, kmsKeyId=key_b)
    _poll(lambda: _describe_group(logs, group), lambda g: g.get("kmsKeyId") == key_b,
          timeout_s=60, what="kmsKeyId to become key B (re-association overrides)")
    put(m_b)
    both = _poll(read, lambda m: m == [m_a, m_b], timeout_s=60,
                 what="both generations to be readable after re-association")
    assert both == [m_a, m_b], f"after re-association the stream read {both!r}"

    # Revoke key A: only the event ingested under A disappears (on AWS within ~10s).
    kms.put_key_policy(KeyId=key_a, PolicyName="default", Policy=revoked_policy)
    only_b = _poll(read, lambda m: m != [m_a, m_b], timeout_s=180, interval_s=5,
                   what="revoking key A to change what the stream returns")
    assert only_b == [m_b], (
        f"with key A revoked the stream read {only_b!r}; expected only the key-B event [{m_b!r}]"
    )
    kms.put_key_policy(KeyId=key_a, PolicyName="default", Policy=full_policy)
    back = _poll(read, lambda m: m == [m_a, m_b], timeout_s=180, interval_s=5,
                 what="the key-A event to return once key A's grant is restored")
    assert back == [m_a, m_b], f"after restoring key A the stream read {back!r}"

    # Disassociate: new events are plaintext, but key-B events still depend on key B: the
    # association is kept while data encrypted with the key remains in CloudWatch Logs.
    logs.disassociate_kms_key(logGroupName=group)
    _poll(lambda: _describe_group(logs, group), lambda g: "kmsKeyId" not in g,
          timeout_s=60, what="kmsKeyId to clear after DisassociateKmsKey")
    put(m_plain)
    three = _poll(read, lambda m: m == [m_a, m_b, m_plain], timeout_s=60,
                  what="all three generations to be readable after disassociation")
    assert three == [m_a, m_b, m_plain], f"after disassociation the stream read {three!r}"

    kms.put_key_policy(KeyId=key_b, PolicyName="default", Policy=revoked_policy)
    no_b = _poll(read, lambda m: m != [m_a, m_b, m_plain], timeout_s=180, interval_s=5,
                 what="revoking key B to hide the key-B event even after disassociation")
    assert no_b == [m_a, m_plain], (
        f"with key B revoked after disassociation the stream read {no_b!r}; expected the key-A "
        f"and plaintext events [{m_a!r}, {m_plain!r}]"
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
