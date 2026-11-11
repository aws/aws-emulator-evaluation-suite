"""deep-logs-2-logcmk-malformed-entity-rejected-events-kept."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deep-logs-2-logcmk-malformed-entity-rejected-events-kept"
GROUP = "kms-data-plane"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """PutLogEvents with a malformed entity reports rejectedEntityInfo.errorType but still ingests
    the batch: on a CMK-encrypted group every event is readable afterwards, in order.
    """
    from botocore.exceptions import ClientError

    logs = ctx.client("logs")
    kms = ctx.client("kms")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    key_arn = kms.create_key(
        Description=ctx.unique_name("sim2real-logcmk-ent-"),
        Policy=_key_policy(account_id, ctx.region, grant_logs=True),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_arn, PendingWindowInDays=7))

    group = ctx.unique_name("sim2real-logcmk-ent-")
    stream = "s1"
    logs.create_log_group(logGroupName=group, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    logs.create_log_stream(logGroupName=group, logStreamName=stream)
    _associate_with_retry(logs, ClientError, logGroupName=group, kmsKeyId=key_arn)
    _poll(lambda: _describe_group(logs, group), lambda g: g.get("kmsKeyId") == key_arn,
          timeout_s=60, what="kmsKeyId to reflect the associated CMK")

    svc_name = group.rsplit("-", 1)[-1]
    # AWS returns PascalCase errorType values, not the UPPER_SNAKE names in the model enum.
    cases = [
        ("valid", {"keyAttributes": {"Type": "Service", "Name": svc_name,
                                     "Environment": "sim2real"}}, None),
        ("bad-type", {"keyAttributes": {"Type": "Bogus", "Name": svc_name}},
         "InvalidTypeValue"),
        ("no-required-keys", {"keyAttributes": {"Foo": "a", "Bar": "b"}},
         "MissingRequiredFields"),
        ("bad-attribute", {"keyAttributes": {"Type": "Service", "Name": svc_name,
                                             "Environment": "sim2real"},
                           "attributes": {"PlatformType": "NotAPlatform"}},
         "InvalidAttributes"),
    ]

    base = int(time.time() * 1000) - 10000
    written = []
    for i, (label, entity, want) in enumerate(cases):
        batch = [{"timestamp": base + i * 100 + j, "message": f"{label} event {j}"}
                 for j in range(2)]
        resp = logs.put_log_events(logGroupName=group, logStreamName=stream,
                                   logEvents=batch, entity=entity)
        written.extend(e["message"] for e in batch)
        got = (resp.get("rejectedEntityInfo") or {}).get("errorType")
        assert got == want, (
            f"{label}: rejectedEntityInfo.errorType={got!r}, expected {want!r} "
            f"(full rejectedEntityInfo={resp.get('rejectedEntityInfo')!r})"
        )
        assert "rejectedLogEventsInfo" not in resp, (
            f"{label}: an entity rejection must not reject the events, got "
            f"rejectedLogEventsInfo={resp.get('rejectedLogEventsInfo')!r}"
        )

    read = _poll(lambda: _read_messages(logs, group, stream),
                 lambda m: len(m) >= len(written), timeout_s=60,
                 what="all events (including those sent with rejected entities) to be readable")
    assert read == written, (
        f"events read back {read!r} differ from all events written {written!r}; a rejected "
        "entity must not drop its batch"
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
