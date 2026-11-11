"""export-task-objects-carry-the-destination-buckets-own-encryption."""
from __future__ import annotations

# Expected AWS behavior:
#  1. CreateExportTask succeeds against a bucket whose default encryption is SSE-KMS with a
#     customer-managed key, given a key policy that allows logs.<region>.amazonaws.com to
#     GenerateDataKey/Decrypt.
#  2. HeadObject on every exported object reports ServerSideEncryption "aws:kms" and an
#     SSEKMSKeyId equal to the CMK ARN this check created.
#  3. The AES-256 twin control bucket's exported objects report ServerSideEncryption
#     "AES256" and carry NO SSEKMSKeyId -- so the encryption reported is the bucket's, not a
#     constant.
#  4. The exact set of objects CloudWatch Logs writes. The check asserts only that at least
#     one .gz object exists and that every object under the prefix is encrypted; the internal
#     key LAYOUT is deliberately not pinned because it is undocumented.
#  5. Only one export task per account may be RUNNING or PENDING, so the two exports run
#     sequentially; the second is not rejected after the first reaches COMPLETED.
#  6. A COMPLETED export task is not proof its data object was written.
#     CreateExportTask against the SSE-KMS bucket can report COMPLETED after writing only the
#     logs.<region>.amazonaws.com permission-check object ("<prefix>/aws-logs-write-test"), with
#     zero .gz objects, because CloudWatch Logs' export-eligible-event index can lag behind what
#     get_log_events already reports as readable. Retrying with a fresh task/prefix resolves it; see
#     _run_export_until_content.

import gzip
import json
import time

from behavioral_harness import tags

CHECK = "export-task-objects-carry-the-destination-buckets-own-encryption"
GROUP = "e2e"
SERVICES = ["logs", "s3"]

_MESSAGES = [
    "sim2real-export-encryption-alpha",
    "sim2real-export-encryption-beta",
    "sim2real-export-encryption-gamma",
]
_TERMINAL_EXPORT_STATES = {"COMPLETED", "FAILED", "CANCELLED"}


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
    "resource:account-singleton:logs-export-task",
)
def run(ctx) -> None:
    """A CloudWatch Logs export task writes its objects under the destination bucket's own
    default encryption -- SSE-KMS with the caller's customer-managed key, or SSE-S3 for an
    AES-256 bucket -- and the objects still decompress to the exact log messages."""
    logs = ctx.client("logs")
    s3 = ctx.client("s3")
    kms = ctx.client("kms")
    account = ctx.client("sts").get_caller_identity()["Account"]

    group, stream = _make_group_and_stream(ctx, logs, "sim2real-behav-logsexp-")
    from_ms, to_ms = _write_and_wait(logs, group, stream, _MESSAGES)

    key_arn = _make_export_key(ctx, kms, account)
    kms_bucket = _make_export_bucket(ctx, s3, account, "sim2real-behav-logsexp-kms-")
    s3.put_bucket_encryption(
        Bucket=kms_bucket,
        ServerSideEncryptionConfiguration={
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "aws:kms",
                        "KMSMasterKeyID": key_arn,
                    },
                    # AWS's CloudWatch Logs -> S3 SSE-KMS setup doc sets BucketKeyEnabled
                    # true; match the documented setup.
                    "BucketKeyEnabled": True,
                }
            ]
        },
    )
    aes_bucket = _make_export_bucket(ctx, s3, account, "sim2real-behav-logsexp-aes-")
    s3.put_bucket_encryption(
        Bucket=aes_bucket,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )

    # --- 1. Export to the SSE-KMS bucket. Only one export task per account may be active,
    # so the two exports are strictly sequential.
    _, kms_objects = _run_export_until_content(
        ctx, logs, s3, group, kms_bucket, "exp-kms-", from_ms, to_ms
    )
    for key in kms_objects:
        head = s3.head_object(Bucket=kms_bucket, Key=key)
        assert head["ServerSideEncryption"] == "aws:kms", (
            f"expected s3://{kms_bucket}/{key} to be written under the bucket's SSE-KMS "
            f"default encryption ('aws:kms'), got "
            f"{head.get('ServerSideEncryption')!r}"
        )
        assert head["SSEKMSKeyId"] == key_arn, (
            f"expected s3://{kms_bucket}/{key} to name the customer-managed key this check "
            f"created ({key_arn}), got {head.get('SSEKMSKeyId')!r}"
        )

    exported = _decompress_gz(s3, kms_bucket, kms_objects)
    for message in _MESSAGES:
        assert message in exported, (
            f"expected the SSE-KMS export to contain {message!r} after decompression -- "
            f"encryption must not cost content; got {len(exported)} characters not "
            f"containing it"
        )

    # --- 2. Twin control: the AES-256 bucket, same log group, same events, same export
    # path. A target that reports a constant encryption header fails exactly one of these
    # two legs, so neither can pass by accident.
    _, aes_objects = _run_export_until_content(
        ctx, logs, s3, group, aes_bucket, "exp-aes-", from_ms, to_ms
    )
    for key in aes_objects:
        head = s3.head_object(Bucket=aes_bucket, Key=key)
        assert head["ServerSideEncryption"] == "AES256", (
            f"expected s3://{aes_bucket}/{key} to be written under the bucket's SSE-S3 "
            f"default encryption ('AES256'), got {head.get('ServerSideEncryption')!r}"
        )
        assert "SSEKMSKeyId" not in head, (
            f"expected NO SSEKMSKeyId on an SSE-S3 object -- the SSE-KMS bucket's key must "
            f"not leak into this one -- got {head.get('SSEKMSKeyId')!r} for "
            f"s3://{aes_bucket}/{key}"
        )

    aes_exported = _decompress_gz(s3, aes_bucket, aes_objects)
    for message in _MESSAGES:
        assert message in aes_exported, (
            f"expected the AES-256 export to contain {message!r} after decompression, got "
            f"{len(aes_exported)} characters not containing it"
        )


def _now_ms() -> int:
    return int(time.time() * 1000)


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate() holds; RAISE on the deadline (never return last)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _make_group_and_stream(ctx, logs, prefix: str) -> tuple[str, str]:
    group = ctx.unique_name(prefix)
    logs.create_log_group(logGroupName=group, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    stream = f"{group}-stream"
    logs.create_log_stream(logGroupName=group, logStreamName=stream)
    return group, stream


def _write_and_wait(logs, group: str, stream: str, messages: list[str]) -> tuple[int, int]:
    base = _now_ms()
    resp = logs.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": base + i, "message": m} for i, m in enumerate(messages)],
    )
    rejected = resp.get("rejectedLogEventsInfo")
    assert not rejected, (
        f"expected {len(messages)} in-window events accepted for {group}, got "
        f"rejectedLogEventsInfo {rejected!r}"
    )
    # An export can only contain events the service has already ingested, so wait for the
    # read path to agree before exporting. Bounded retry; raises on the deadline.
    _poll_until(
        lambda: [
            e["message"]
            for e in logs.get_log_events(
                logGroupName=group, logStreamName=stream, startFromHead=True
            )["events"]
        ],
        lambda msgs: sorted(msgs) == sorted(messages),
        timeout_s=180.0,
        interval_s=5.0,
        description=f"all {len(messages)} events readable from {group}/{stream} before export",
    )
    return base - 1, base + len(messages) + 60_000


def _make_export_key(ctx, kms, account: str) -> str:
    """A customer-managed key whose policy lets the CloudWatch Logs export principal use it.
    The account-root statement is mandatory: KMS refuses a policy that locks the account out.
    """
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowAccountRoot",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "AllowCloudWatchLogsExport",
                "Effect": "Allow",
                "Principal": {"Service": f"logs.{ctx.region}.amazonaws.com"},
                "Action": [
                    "kms:Encrypt",
                    "kms:Decrypt",
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKey*",
                    "kms:DescribeKey",
                ],
                "Resource": "*",
            },
        ],
    }
    created = kms.create_key(
        Description=f"sim2real {CHECK}",
        Policy=json.dumps(policy),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_id = created["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return created["Arn"]


def _make_export_bucket(ctx, s3, account: str, prefix: str) -> str:
    bucket = ctx.unique_name(prefix)
    if ctx.region == "us-east-1":
        # us-east-1 is the only region for which CreateBucket must omit LocationConstraint.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )
    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": f"logs.{ctx.region}.amazonaws.com"},
                        "Action": "s3:GetBucketAcl",
                        "Resource": f"arn:aws:s3:::{bucket}",
                        "Condition": {"StringEquals": {"aws:SourceAccount": account}},
                    },
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": f"logs.{ctx.region}.amazonaws.com"},
                        "Action": "s3:PutObject",
                        "Resource": f"arn:aws:s3:::{bucket}/*",
                        "Condition": {
                            "StringEquals": {
                                "s3:x-amz-acl": "bucket-owner-full-control",
                                "aws:SourceAccount": account,
                            }
                        },
                    },
                ],
            }
        ),
    )
    return bucket


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})
    s3.delete_bucket(Bucket=bucket)


def _run_export_until_content(
    ctx,
    logs,
    s3,
    group: str,
    bucket: str,
    prefix_base: str,
    from_ms: int,
    to_ms: int,
    *,
    settle_s: float = 120.0,
) -> tuple[str, list[str]]:
    """CreateExportTask can report COMPLETED after writing only the
    ``logs.<region>.amazonaws.com`` permission-check object (``aws-logs-write-test``), with
    ZERO data objects: the export's eligible-event index can lag behind what
    ``get_log_events`` already reports as readable. So retry with a fresh task/prefix until the
    index catches up; every attempt still demands a COMPLETED export, and the final attempt
    demands actual .gz content.
    """
    last_keys: list[str] = []
    # The settle window opens at the first COMPLETED export without data, so a slow export
    # never eats into the time the index gets to catch up.
    deadline = None
    attempt = 0
    while True:
        attempt += 1
        prefix = ctx.unique_name(f"{prefix_base}{attempt}-")
        # Widen ``to`` to the live clock each attempt: since the constraint is CWL's
        # eligible-event index catching up in real time, not the requested window.
        widened_to = max(to_ms, _now_ms() + 5_000)
        task_id = logs.create_export_task(
            taskName=ctx.unique_name("sim2real-behav-logsexp-task-"),
            logGroupName=group,
            to=widened_to,
            destination=bucket,
            destinationPrefix=prefix,
            **{"from": from_ms},
        )["taskId"]
        status = _poll_until(
            lambda: logs.describe_export_tasks(taskId=task_id)["exportTasks"][0]["status"]["code"],
            lambda code: code in _TERMINAL_EXPORT_STATES,
            timeout_s=600.0,
            interval_s=10.0,
            description=f"export task {task_id} reaches a terminal state",
        )
        assert status == "COMPLETED", (
            f"expected export task {task_id} to reach COMPLETED writing to "
            f"s3://{bucket}/{prefix}/, got {status}"
        )
        keys = _list_keys(s3, bucket, prefix)
        gz_keys = [k for k in keys if k.endswith(".gz")]
        if gz_keys:
            return prefix, gz_keys
        last_keys = keys
        if deadline is None:
            left = ctx.time_left()
            deadline = time.monotonic() + (settle_s if left is None else min(settle_s, left))
        if time.monotonic() >= deadline:
            break
        time.sleep(2.0)
    raise AssertionError(
        f"export task(s) to s3://{bucket}/{prefix_base}* reported COMPLETED in every one of "
        f"{attempt} attempts but never produced a .gz object -- last attempt's keys under "
        f"its prefix: {last_keys!r}"
    )


def _list_keys(s3, bucket: str, prefix: str) -> list[str]:
    # ListObjectsV2 omits Contents entirely for an empty prefix, so the [] default is the
    # only correct reading. Its POLARITY is safe: every caller requires a NON-empty result
    # (the poll's predicate and _decompress_gz both fail on []), so the default can never
    # supply the value this check exists to detect.
    resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
    return [o["Key"] for o in resp.get("Contents", [])]


def _decompress_gz(s3, bucket: str, keys: list[str]) -> str:
    chunks = []
    gz_keys = [k for k in keys if k.endswith(".gz")]
    assert gz_keys, (
        f"expected at least one .gz object under s3://{bucket}/, got keys {keys}"
    )
    for key in gz_keys:
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        chunks.append(gzip.decompress(body).decode("utf-8"))
    return "\n".join(chunks)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
