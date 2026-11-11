"""create-export-task-bucket-missing-permission-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-export-task-bucket-missing-permission-rejected"
GROUP = "export-tasks"
SERVICES = ["logs", "s3", "sts"]


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "plane:control",
    "resource:account-singleton:logs-export-task",
)
def run(ctx) -> None:
    """CreateExportTask against a bucket whose policy does not grant the Logs service principal
    creates no task, naming the missing permission; granting only s3:GetBucketAcl still fails,
    now naming s3:PutObject, and granting both lets the same group export (positive control)."""
    logs = ctx.client("logs")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    bucket = _create_bucket(ctx)
    group_name = ctx.unique_name("sim2real-behav-cetbmp-group-")
    logs.create_log_group(logGroupName=group_name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))
    now_ms = int(time.time() * 1000)

    # No bucket policy at all: the Logs principal has no grant on the bucket.
    code, message = _error(
        lambda: logs.create_export_task(
            logGroupName=group_name,
            destination=bucket,
            **{"from": now_ms - 60000, "to": now_ms},
        )
    )
    assert code == "AccessDeniedException", (
        f"CreateExportTask against an unpermissioned bucket returned {code!r}, expected "
        "AccessDeniedException"
    )
    assert message == (
        "GetBucketAcl call on the given bucket failed. Please check if CloudWatch Logs has "
        "been granted permission to perform this operation."
    ), f"unexpected message for a bucket with no policy: {message!r}"
    tasks = logs.describe_export_tasks()["exportTasks"]
    assert not any(t.get("logGroupName") == group_name for t in tasks), (
        f"no export task should exist after the unpermissioned-bucket rejection, found {tasks!r}"
    )

    # A policy granting only s3:GetBucketAcl (no s3:PutObject) is rejected for the PutObject grant.
    s3.put_bucket_policy(
        Bucket=bucket, Policy=json.dumps(_acl_only_policy(ctx.region, account_id, bucket))
    )
    code2, message2 = _error(
        lambda: logs.create_export_task(
            logGroupName=group_name,
            destination=bucket,
            **{"from": now_ms - 60000, "to": now_ms},
        )
    )
    assert code2 == "AccessDeniedException", (
        f"CreateExportTask against a GetBucketAcl-only bucket returned {code2!r}, expected "
        "AccessDeniedException"
    )
    assert message2 == (
        "PutObject call on the given bucket failed. Please check if CloudWatch Logs has "
        "been granted permission to perform this operation."
    ), f"unexpected message for a GetBucketAcl-only bucket: {message2!r}"
    tasks2 = logs.describe_export_tasks()["exportTasks"]
    assert not any(t.get("logGroupName") == group_name for t in tasks2), (
        f"no export task should exist after the GetBucketAcl-only rejection, found {tasks2!r}"
    )

    # Positive control: granting both permissions lets the same group export.
    s3.put_bucket_policy(
        Bucket=bucket, Policy=json.dumps(_full_policy(ctx.region, account_id, bucket))
    )
    task_id = logs.create_export_task(
        logGroupName=group_name,
        destination=bucket,
        **{"from": now_ms - 60000, "to": now_ms},
    )["taskId"]
    ctx.on_cleanup(lambda: _cancel_unless_terminal(logs, task_id))
    final_status = _poll_until(
        lambda: logs.describe_export_tasks(taskId=task_id)["exportTasks"][0]["status"]["code"],
        lambda s: s in ("COMPLETED", "FAILED", "CANCELLED"),
        timeout_s=240,
        description="the positive-control export task reaches a terminal status",
    )
    assert final_status == "COMPLETED", (
        f"expected the fully-permissioned positive-control export task to complete, got "
        f"{final_status!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _cancel_unless_terminal(logs, task_id):
    """Cancel the task unless it is gone or already terminal (nothing to undo)."""
    tasks = logs.describe_export_tasks(taskId=task_id)["exportTasks"]
    if not tasks or tasks[0]["status"]["code"] in ("COMPLETED", "FAILED", "CANCELLED"):
        return
    try:
        logs.cancel_export_task(taskId=task_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _acl_only_policy(region, account_id, bucket):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowGetBucketAcl",
                "Effect": "Allow",
                "Principal": {"Service": f"logs.{region}.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket}",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            }
        ],
    }


def _full_policy(region, account_id, bucket):
    policy = _acl_only_policy(region, account_id, bucket)
    policy["Statement"].append(
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
        }
    )
    return policy


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-cetbmp-").lower().replace("_", "-")

    # CreateBucket rejects an explicit LocationConstraint of us-east-1.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )

    def _empty_and_delete():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_empty_and_delete)
    return bucket


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
