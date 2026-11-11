"""cancel-export-task-already-completed-fails."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "cancel-export-task-already-completed-fails"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:logs-export-task")
def run(ctx) -> None:
    """CancelExportTask on a COMPLETED task raises InvalidOperationException with its exact message and the task
    stays COMPLETED, while cancelling a fresh task drives it to CANCELLED."""
    logs = ctx.client("logs")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    region = ctx.region

    log_group = ctx.unique_name("sim2real-behav-explg-")
    logs.create_log_group(logGroupName=log_group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    stream = ctx.unique_name("stream-")
    logs.create_log_stream(logGroupName=log_group, logStreamName=stream)

    now_ms = int(time.time() * 1000)
    logs.put_log_events(
        logGroupName=log_group,
        logStreamName=stream,
        logEvents=[
            {"timestamp": now_ms - 10000, "message": "export-fidelity-1"},
            {"timestamp": now_ms - 5000, "message": "export-fidelity-2"},
        ],
    )

    bucket = ctx.unique_name("sim2real-behav-export-").lower()
    _create_bucket(s3, bucket, region)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowGetBucketAcl",
                "Effect": "Allow",
                "Principal": {"Service": f"logs.{region}.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket}",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account},
                    "ArnLike": {"aws:SourceArn": f"arn:aws:logs:{region}:{account}:log-group:*"},
                },
            },
            {
                "Sid": "AllowPutObject",
                "Effect": "Allow",
                "Principal": {"Service": f"logs.{region}.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Condition": {
                    "StringEquals": {
                        "aws:SourceAccount": account,
                        "s3:x-amz-acl": "bucket-owner-full-control",
                    },
                    "ArnLike": {"aws:SourceArn": f"arn:aws:logs:{region}:{account}:log-group:*"},
                },
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))

    from_ms = now_ms - 3600 * 1000
    to_ms = now_ms

    # Positive control: cancelling a freshly created, still-live task must succeed and
    # drive it to CANCELLED. Without this, "rejects cancelling a COMPLETED task" would be
    # indistinguishable from "rejects every CancelExportTask".
    control_id = logs.create_export_task(
        logGroupName=log_group,
        destination=bucket,
        destinationPrefix="export-control",
        **{"from": from_ms, "to": to_ms},
    )["taskId"]

    logs.cancel_export_task(taskId=control_id)

    def probe_control() -> str:
        tasks = logs.describe_export_tasks(taskId=control_id)["exportTasks"]
        return tasks[0]["status"]["code"] if tasks else "UNKNOWN"

    control_status = _poll_until(
        probe_control, lambda s: s == "CANCELLED", timeout_s=120, interval_s=3
    )
    assert control_status == "CANCELLED", (
        f"positive control: expected the cancelled task to settle at CANCELLED, "
        f"got {control_status}"
    )

    # Subject: a second task, left to complete naturally, must refuse a cancel once it
    # has reached COMPLETED.
    resp = logs.create_export_task(
        logGroupName=log_group,
        destination=bucket,
        destinationPrefix="export-subject",
        **{"from": from_ms, "to": to_ms},
    )
    task_id = resp["taskId"]

    def probe() -> str:
        tasks = logs.describe_export_tasks(taskId=task_id)["exportTasks"]
        return tasks[0]["status"]["code"] if tasks else "UNKNOWN"

    status = _poll_until(probe, lambda s: s == "COMPLETED", timeout_s=120, interval_s=3)
    assert status == "COMPLETED", f"expected the export task to reach COMPLETED, got {status}"

    code, message = _error(lambda: logs.cancel_export_task(taskId=task_id))
    assert code == "InvalidOperationException", (
        f"expected InvalidOperationException cancelling a COMPLETED export task, got {code}"
    )
    expected_message = "The specified export task has already finished"
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )

    # The rejected cancel must not re-mutate the task: an independent read still reports
    # the same COMPLETED status it had before the rejected call.
    after_status = probe()
    assert after_status == "COMPLETED", (
        f"rejected CancelExportTask must not change task status: was COMPLETED, "
        f"now {after_status}"
    )


def _create_bucket(s3: Any, bucket: str, region: str) -> None:
    if region == "us-east-1":
        # us-east-1 is the one region that rejects a CreateBucketConfiguration.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})


def _empty_and_delete_bucket(s3: Any, bucket: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            failed = s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _poll_until(
    probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
