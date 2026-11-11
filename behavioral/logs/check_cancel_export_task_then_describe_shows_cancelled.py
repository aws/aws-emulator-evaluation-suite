"""cancel-export-task-then-describe-shows-cancelled."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-export-task-then-describe-shows-cancelled"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:logs-export-task")
def run(ctx) -> None:
    """CancelExportTask moves a non-terminal export task to CANCELLED and DescribeExportTasks reflects it."""
    logs = ctx.client("logs")
    log_group = _create_log_group(ctx)
    bucket = _create_export_bucket(ctx)

    now_ms = int(time.time() * 1000)
    from_ms = now_ms - 3_600_000
    to_ms = now_ms + 60_000

    # An export task on a fresh/near-empty log group can reach a terminal state very
    # quickly, so we race the cancel immediately after creation and retry with a fresh
    # task if we lose the race (task already terminal by the time cancel lands).
    for _attempt in range(4):
        task_id = logs.create_export_task(
            logGroupName=log_group,
            destination=bucket,
            destinationPrefix=ctx.unique_name("export-"),
            fromTime=from_ms,
            to=to_ms,
        )["taskId"]

        try:
            logs.cancel_export_task(taskId=task_id)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "InvalidOperationException":
                raise
            # Lost the race: task had already reached a terminal state. Drain it and retry.
            drained = _poll_export_status(
                ctx, task_id, {"COMPLETED", "FAILED", "CANCELLED"}, timeout_s=_budget_s(ctx, 90.0)
            )
            if drained not in {"COMPLETED", "FAILED", "CANCELLED"} and _budget_spent(ctx):
                raise TimeoutError(
                    f"export task {task_id} to reach a terminal state: the run budget ended first; not graded"
                )
            continue
        status = _poll_export_status(ctx, task_id, {"CANCELLED"}, timeout_s=_budget_s(ctx, 90.0))
        if status != "CANCELLED" and _budget_spent(ctx):
            raise TimeoutError(f"export task {task_id} to show CANCELLED: the run budget ended first; not graded")
        assert status == "CANCELLED", f"expected CANCELLED, got {status!r}"
        return

    raise AssertionError(
        "could not observe a cancellable (non-terminal) export task after 4 attempts"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _create_log_group(ctx) -> str:
    logs = ctx.client("logs")
    name = ctx.unique_name("sim2real-behav-cwl-export-")
    logs.create_log_group(logGroupName=name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
    return name


def _create_export_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region
    bucket = ctx.unique_name("sim2real-behav-cwlexp-").lower().replace("_", "-")
    # CreateBucket rejects an explicit LocationConstraint of us-east-1 itself; the bucket still
    # lands in ctx.region either way, so this is an S3 API quirk, not a hardcoded region.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))

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
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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
        time.sleep(1.0)
    return last_status


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
