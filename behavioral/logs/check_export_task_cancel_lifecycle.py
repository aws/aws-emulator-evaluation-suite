"""export-task-cancel-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "export-task-cancel-lifecycle"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:logs-export-task")
def run(ctx) -> None:
    """CreateExportTask produces a task visible via DescribeExportTasks whose status
    transitions to CANCELLED after CancelExportTask."""
    logs = ctx.client("logs")
    s3 = ctx.client("s3")

    bucket_name = ctx.unique_name("sim2real-export-bkt-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )

    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowCwlAcl",
                "Effect": "Allow",
                "Principal": {"Service": f"logs.{ctx.region}.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket_name}",
            },
            {
                "Sid": "AllowCwlWrite",
                "Effect": "Allow",
                "Principal": {"Service": f"logs.{ctx.region}.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
                "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(bucket_policy))

    group_name = ctx.unique_name("sim2real-export-lg-")
    stream_name = ctx.unique_name("sim2real-export-ls-")
    logs.create_log_group(logGroupName=group_name, tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))
    logs.create_log_stream(logGroupName=group_name, logStreamName=stream_name)
    now_ms = int(time.time() * 1000)
    logs.put_log_events(
        logGroupName=group_name,
        logStreamName=stream_name,
        logEvents=[{"timestamp": now_ms, "message": f"export-cancel-test-{i}"} for i in range(5)],
    )

    def _create_task():
        return logs.create_export_task(
            logGroupName=group_name,
            fromTime=0,
            to=now_ms + 60_000,
            destination=bucket_name,
        )

    # A fresh/near-empty log group's export can reach a terminal state within a second or two,
    # faster than CancelExportTask can land -- an inherent scheduling race, not a fidelity signal.
    # Retry with a fresh task rather than scoring the race itself as a failure.
    for _attempt in range(5):
        create_resp = _retry_on_code(_create_task, "LimitExceededException", attempts=10, delay_s=5)
        task_id = create_resp["taskId"]
        ctx.on_cleanup(lambda _tid=task_id: _safe_cancel(logs, _tid))

        if _cancel_accepted(logs, task_id):
            final = _poll_until(
                lambda: _describe_task(logs, task_id)["status"]["code"],
                lambda c: c in ("CANCELLED", "COMPLETED", "FAILED"),
                timeout_s=90,
                interval_s=2,
            )
            assert final == "CANCELLED", f"expected CANCELLED, task ended in {final}"
            return
        # Lost the race: task was already terminal. Drain it and retry with a fresh one.
        _poll_until(
            lambda: _describe_task(logs, task_id)["status"]["code"],
            lambda c: c in ("CANCELLED", "COMPLETED", "FAILED"),
            timeout_s=90,
            interval_s=2,
        )

    raise AssertionError(
        "could not observe a cancellable (non-terminal) export task after 5 attempts"
    )


def _describe_task(logs, task_id: str) -> dict:
    tasks = logs.describe_export_tasks(taskId=task_id).get("exportTasks", [])
    assert tasks, f"export task {task_id} not visible via DescribeExportTasks"
    return tasks[0]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _retry_on_code(fn, code: str, *, attempts: int = 5, delay_s: float = 2.0):
    from botocore.exceptions import ClientError

    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != code:
                raise
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


def _empty_and_delete_bucket(s3, name: str, timeout_s: float = 120.0) -> None:
    """Teardown: delete every object version and delete marker, then the bucket.

    The export writes its own objects (a write-test marker at least), so the bucket is never empty;
    a write landing after the sweep is swept again, bounded.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=name):
            objs = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objs:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs, "Quiet": True}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        try:
            s3.delete_bucket(Bucket=name)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "BucketNotEmpty" or time.monotonic() >= deadline:
                raise
        time.sleep(5.0)


def _safe_cancel(logs, task_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        logs.cancel_export_task(taskId=task_id)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "InvalidOperationException":
            return  # the task already left PENDING/RUNNING (terminal)
        if code != "ResourceNotFoundException":
            raise


def _cancel_accepted(logs, task_id: str) -> bool:
    """True when CancelExportTask is accepted; False only on InvalidOperationException (task already terminal)."""
    from botocore.exceptions import ClientError

    try:
        logs.cancel_export_task(taskId=task_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidOperationException":
            raise
        return False
    return True


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
