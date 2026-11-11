"""export-task-server-managed-completion."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "export-task-server-managed-completion"
GROUP = "server-side"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:logs-export-task")
def run(ctx) -> None:
    """A CreateExportTask job is driven to COMPLETED entirely by the managed
    service; the client only ever polls DescribeExportTasks, never performs the
    actual copy itself."""
    logs = ctx.client("logs")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    bucket = ctx.unique_name("sim2real-behav-export").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)
    _set_export_bucket_policy(ctx, s3, bucket, account_id)

    group = ctx.unique_name("sim2real-behav-export-lg-")
    stream = "sim2real-stream"
    logs.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    logs.create_log_stream(logGroupName=group, logStreamName=stream)

    now_ms = int(time.time() * 1000)
    logs.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": now_ms, "message": "export-task-server-managed-completion probe event"}],
    )

    task_id = logs.create_export_task(
        logGroupName=group,
        destination=bucket,
        destinationPrefix="sim2real-export",
        **{"from": now_ms - 5 * 60 * 1000},
        to=now_ms + 60 * 1000,
    )["taskId"]
    ctx.on_cleanup(lambda: _cleanup_bucket_objects(s3, bucket))

    task = _poll_until(
        lambda: _describe_task(logs, task_id),
        lambda t: t["status"]["code"] in ("COMPLETED", "FAILED", "CANCELLED"),
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert task["status"]["code"] == "COMPLETED", f"export task ended in unexpected state: {task['status']}"

    # DescribeExportTasks is the producer's own self-report; the managed copy is only
    # proven by an independent read at the destination it was supposed to land in.
    _poll_until(
        lambda: s3.list_objects_v2(Bucket=bucket, Prefix="sim2real-export").get("Contents", []),
        lambda objs: len(objs) > 0,
        timeout_s=60.0,
        interval_s=5.0,
    )


def _create_bucket(ctx: Any, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))


def _set_export_bucket_policy(ctx: Any, s3, bucket: str, account_id: str) -> None:
    service_principal = f"logs.{ctx.region}.amazonaws.com"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowGetBucketAcl",
                "Action": "s3:GetBucketAcl",
                "Effect": "Allow",
                "Resource": f"arn:aws:s3:::{bucket}",
                "Principal": {"Service": service_principal},
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": [account_id]},
                    "ArnLike": {"aws:SourceArn": [f"arn:aws:logs:{ctx.region}:{account_id}:log-group:*"]},
                },
            },
            {
                "Sid": "AllowPutObject",
                "Action": "s3:PutObject",
                "Effect": "Allow",
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Principal": {"Service": service_principal},
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control",
                        "aws:SourceAccount": [account_id],
                    },
                    "ArnLike": {"aws:SourceArn": [f"arn:aws:logs:{ctx.region}:{account_id}:log-group:*"]},
                },
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))


def _cleanup_bucket_objects(s3, bucket: str) -> None:
    try:
        objects = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objects:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _describe_task(logs, task_id: str) -> dict:
    tasks = logs.describe_export_tasks(taskId=task_id)["exportTasks"]
    assert tasks, f"export task {task_id!r} disappeared"
    return tasks[0]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last result={result!r}")
        time.sleep(interval_s)
        result = probe()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
