"""e2e-export-task-produces-s3-object-with-log-content."""
from __future__ import annotations

import gzip
import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-export-task-produces-s3-object-with-log-content"
GROUP = "e2e"
SERVICES = ["logs"]
#: Export tasks are a long-running class: real AWS needed up to 600 s to reach COMPLETED.
POLL_BUDGET_S = 600.0


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data", "resource:account-singleton:logs-export-task")
def run(ctx) -> None:
    """CreateExportTask against a populated log group actually lands the exact log content
    (not just a SUCCEEDED status) in the destination S3 bucket."""
    logs = ctx.client("logs")
    ctx.client("s3")

    bucket = _create_export_bucket(ctx)
    log_group = ctx.unique_name("sim2real-behav-lg-")
    log_stream = ctx.unique_name("sim2real-behav-ls-")
    marker = f"sim2real-marker-{uuid.uuid4().hex}"

    logs.create_log_group(logGroupName=log_group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: _delete_group_if_present(logs, log_group))
    logs.create_log_stream(logGroupName=log_group, logStreamName=log_stream)

    start_ms = int(time.time() * 1000)
    logs.put_log_events(
        logGroupName=log_group,
        logStreamName=log_stream,
        logEvents=[{"timestamp": start_ms, "message": marker}],
    )

    # A just-written event can lag slightly behind CloudWatch Logs' export-eligible index: an
    # export task can legitimately report COMPLETED without yet including the newest event.
    # Retry with a fresh task/prefix (widening the "to" bound each time) to a 120 s deadline.
    content = ""
    left = ctx.time_left()
    deadline = time.monotonic() + (120.0 if left is None else max(1.0, min(120.0, left - 5.0)))
    attempt = 0
    while True:
        attempt += 1
        prefix = ctx.unique_name(f"sim2real-behav-export-{attempt}-")
        end_ms = int(time.time() * 1000) + 5000
        task_id = logs.create_export_task(
            logGroupName=log_group,
            to=end_ms,
            destination=bucket,
            destinationPrefix=prefix,
            **{"from": start_ms - 5000},
        )["taskId"]

        status = _poll_export_task(ctx, task_id)
        assert status == "COMPLETED", f"export task ended in status {status}, expected COMPLETED"

        content = _download_prefix_text(ctx, bucket, prefix)
        if marker in content or time.monotonic() >= deadline:
            break
        time.sleep(2.0)

    assert marker in content, "exported S3 content does not contain the written log message"

    # The log group is deleted and gone: unreadable, unlisted, and unwritable.
    logs.delete_log_group(logGroupName=log_group)
    refused = _expect_error(lambda: logs.get_log_events(logGroupName=log_group, logStreamName=log_stream,
                                                        startFromHead=True),
                            ("ResourceNotFoundException",))
    expected_message = "The specified log group does not exist."
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'
    groups = [
        g["logGroupName"]
        for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=log_group)
        for g in page.get("logGroups", [])
    ]
    assert log_group not in groups, f"deleted log group {log_group} still listed"
    refused = _expect_error(lambda: logs.put_log_events(
                  logGroupName=log_group, logStreamName=log_stream,
                  logEvents=[{"timestamp": int(time.time() * 1000), "message": "after delete"}],
    ), ("ResourceNotFoundException",))
    expected_message = "The specified log group does not exist."
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'

    # The exported objects and the bucket are deleted: the exported key no longer answers.
    s3 = ctx.client("s3")
    exported = [o["Key"] for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix)
                for o in page.get("Contents", [])]
    assert exported, f"no exported objects under s3://{bucket}/{prefix} to delete"
    _empty_and_delete_bucket(s3, bucket)
    try:
        s3.head_object(Bucket=bucket, Key=exported[0])
    except ClientError as exc:
        got = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        assert got == 404, f"expected HeadObject on the deleted export to answer 404, got {got!r}"
    else:
        raise AssertionError(f"exported object s3://{bucket}/{exported[0]} still answers after deletion")



# ===== helpers =====
def _create_export_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    account_id = ctx.account
    bucket = ctx.unique_name("sim2real-behav-export-").lower().replace("_", "-")

    # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint;
    # this branches on the S3 API's own quirk, not a region pin on the check (ctx.region is
    # used for the actual bucket location in every other region).
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})

    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowGetBucketAcl",
                "Effect": "Allow",
                "Principal": {"Service": f"logs.{ctx.region}.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket}",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            },
            {
                "Sid": "AllowPutObject",
                "Effect": "Allow",
                "Principal": {"Service": f"logs.{ctx.region}.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control",
                        "aws:SourceAccount": account_id,
                    }
                },
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    return bucket


def _assert_error(exc, codes, *, status=400, contains=()) -> None:
    """Grade a ClientError on code, HTTP status, the exact message and the ids it must name."""
    err = exc.response.get('Error', {})
    code, msg = err.get('Code'), err.get('Message') or ''
    got_status = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
    assert code in codes, f"expected error code in {codes!r}, got {code!r}: {msg!r}"
    assert got_status == status, f"expected HTTP {status} with {code}, got {got_status!r}"
    assert msg.strip(), f"expected the exact message with {code}"
    for want in contains:
        assert want in msg, f"expected the {code} message to name {want!r}, got {msg!r}"


def _expect_error(fn, codes, *, status=400, contains=()):
    """Call fn() and grade the ClientError it raises; an accepted call is itself a failure."""
    try:
        result = fn()
    except ClientError as exc:
        _assert_error(exc, codes, status=status, contains=contains)
        return exc
    raise AssertionError(f'expected {codes!r}, but the call succeeded: {result!r}')


def _delete_group_if_present(logs, name):
    try:
        logs.delete_log_group(logGroupName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _empty_and_delete_bucket(s3, bucket):
    """Delete every object, then the bucket; a bucket already gone is fine."""
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchBucket":
            raise


def _poll_export_task(ctx, task_id: str, timeout_s: float = POLL_BUDGET_S) -> str:
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    terminal = {"COMPLETED", "FAILED", "CANCELLED"}
    code = "PENDING"
    while time.monotonic() < deadline:
        tasks = logs.describe_export_tasks(taskId=task_id)["exportTasks"]
        if tasks:
            code = tasks[0]["status"]["code"]
            if code in terminal:
                return code
        time.sleep(5.0)
    raise AssertionError(f"export task {task_id} did not reach a terminal state within {timeout_s}s; last status {code}")


def _download_prefix_text(ctx, bucket: str, prefix: str) -> str:
    s3 = ctx.client("s3")
    deadline = time.monotonic() + 60.0
    keys: list[str] = []
    while time.monotonic() < deadline:
        resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
        keys = [o["Key"] for o in resp.get("Contents", [])]
        if keys:
            break
        time.sleep(3.0)
    assert keys, f"no objects found under s3://{bucket}/{prefix}"

    chunks = []
    for key in keys:
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        if key.endswith(".gz"):
            body = gzip.decompress(body)
        chunks.append(body.decode("utf-8", errors="replace"))
    return "\n".join(chunks)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
