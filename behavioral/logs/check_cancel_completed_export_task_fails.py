"""cancel-completed-export-task-fails."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cancel-completed-export-task-fails"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:logs-export-task")
def run(ctx) -> None:
    """CancelExportTask on an already-terminal task returns InvalidOperationException, not success."""
    logs = ctx.client("logs")
    log_group = _create_log_group(ctx)
    bucket = _create_export_bucket(ctx)

    now_ms = int(time.time() * 1000)
    from_ms = now_ms - 60_000
    to_ms = now_ms + 60_000

    task_id = logs.create_export_task(
        logGroupName=log_group,
        destination=bucket,
        destinationPrefix=ctx.unique_name("export-"),
        fromTime=from_ms,
        to=to_ms,
    )["taskId"]

    status = _poll_export_status(
        ctx, task_id, {"COMPLETED", "FAILED", "CANCELLED"}, timeout_s=120.0
    )
    if status not in ("COMPLETED", "FAILED"):
        raise AssertionError(f"export task did not reach a settled terminal state: {status}")

    code, message = _error(lambda: logs.cancel_export_task(taskId=task_id))
    assert code == "InvalidOperationException", (
        f"expected InvalidOperationException cancelling a {status} task, got {code!r}"
    )
    expected_message = "The specified export task has already finished"
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )

    # The task's status must remain untouched by the rejected cancel attempt.
    resp = logs.describe_export_tasks(taskId=task_id)
    final_status = resp["exportTasks"][0]["status"]["code"]
    assert final_status == status, (
        f"rejected CancelExportTask must not mutate task status: was {status}, now {final_status}"
    )


def _error(fn):
    """Call fn() expecting a ClientError; return its (Code, Message). A success raises, so a
    target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _create_log_group(ctx) -> str:
    logs = ctx.client("logs")
    name = ctx.unique_name("sim2real-behav-cwl-export-")
    logs.create_log_group(logGroupName=name, tags={"simparity-check": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
    return name


def _create_export_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region
    bucket = ctx.unique_name("sim2real-behav-cwlexp-").lower().replace("_", "-")
    # CreateBucket rejects a LocationConstraint of us-east-1 -- the constraint must be omitted
    # only for that region. This is the standard S3 idiom, not a region pin on the check itself.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]}
    )

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowGetBucketAcl",
                "Effect": "Allow",
                "Principal": {"Service": f"logs.{region}.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket}",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            },
            {
                "Sid": "AllowPutObject",
                "Effect": "Allow",
                "Principal": {"Service": f"logs.{region}.amazonaws.com"},
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
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        try:
            s3.get_bucket_policy(Bucket=bucket)
            break
        except Exception:
            time.sleep(1.0)
    return bucket


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            keys = [{"Key": obj["Key"]} for obj in page.get("Contents", [])]
            if keys:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _poll_export_status(
    ctx, task_id: str, target_statuses: set[str], timeout_s: float = 90.0
) -> str:
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    last_status = "UNKNOWN"
    while time.monotonic() < deadline:
        resp = logs.describe_export_tasks(taskId=task_id)
        tasks: list[dict[str, Any]] = resp.get("exportTasks", [])
        if tasks:
            last_status = tasks[0]["status"]["code"]
            if last_status in target_statuses:
                return last_status
        time.sleep(2.0)
    return last_status


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
