"""cancel-export-task-terminal-state-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cancel-export-task-terminal-state-rejected"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:logs-export-task")
def run(ctx) -> None:
    """CancelExportTask on a task that has already reached a terminal state (COMPLETED) is
    rejected with InvalidOperationException, not silently accepted."""
    logs = ctx.client("logs")
    s3 = ctx.client("s3")

    bucket_name = ctx.unique_name("sim2real-export-term-bkt-").lower().replace("_", "-")
    # CreateBucket rejects an explicit LocationConstraint of "us-east-1" (legacy S3 API quirk) --
    # the constraint must be omitted in that region, not set to it.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )
    # DeleteBucket refuses a non-empty bucket, and CreateExportTask always writes at least
    # its `aws-logs-write-test` permission probe object into the destination (plus any
    # exported log objects), so deleting the bucket directly leaks it -- a billable
    # residual left behind by a check that reports success. Empty it first, and only the
    # objects in the bucket THIS check created.
    ctx.on_cleanup(lambda: _delete_bucket_recursive(s3, bucket_name))

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

    group_name = ctx.unique_name("sim2real-export-term-lg-")
    logs.create_log_group(logGroupName=group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))
    now_ms = int(time.time() * 1000)

    def _create_task():
        return logs.create_export_task(
            logGroupName=group_name, fromTime=0, to=now_ms, destination=bucket_name
        )

    create_resp = _retry_on_code(_create_task, "LimitExceededException", attempts=10, delay_s=5)
    task_id = create_resp["taskId"]
    ctx.on_cleanup(lambda: _safe_cancel(logs, task_id))

    # An empty log group's export task reaches a terminal state quickly.
    terminal_status = _poll_until(
        lambda: logs.describe_export_tasks(taskId=task_id)["exportTasks"][0]["status"]["code"],
        lambda code: code in ("COMPLETED", "FAILED", "CANCELLED"),
        timeout_s=120,
        interval_s=3,
    )
    assert terminal_status == "COMPLETED", f"expected COMPLETED for cancel-after-terminal test, got {terminal_status}"

    code, message = _error(lambda: logs.cancel_export_task(taskId=task_id))
    assert code == "InvalidOperationException", f"expected InvalidOperationException, got {code}"
    expected_message = "The specified export task has already finished"
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )

    # Independent read at the destination: the rejected cancel must not have mutated the task.
    status_after_rejected_cancel = logs.describe_export_tasks(taskId=task_id)["exportTasks"][0][
        "status"
    ]["code"]
    assert status_after_rejected_cancel == "COMPLETED", (
        "a rejected CancelExportTask must not mutate task status: was COMPLETED, now "
        f"{status_after_rejected_cancel}"
    )


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


def _delete_bucket_recursive(s3, bucket: str) -> None:
    """Delete every object in `bucket` (all versions, if versioning is on) then the bucket."""
    for paginator_name, key in (
        ("list_object_versions", "Versions"),
        ("list_object_versions", "DeleteMarkers"),
    ):
        try:
            for page in s3.get_paginator(paginator_name).paginate(Bucket=bucket):
                objects = [
                    {"Key": o["Key"], "VersionId": o["VersionId"]} for o in page.get(key, [])
                ]
                if objects:
                    failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
                    if failed:
                        raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objects:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket)


def _safe_cancel(logs, task_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        logs.cancel_export_task(taskId=task_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
