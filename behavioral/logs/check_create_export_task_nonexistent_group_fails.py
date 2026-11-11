"""create-export-task-nonexistent-group-fails."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-export-task-nonexistent-group-fails"
GROUP = 'export-tasks'
SERVICES = ['logs']

_TERMINAL = {"COMPLETED", "FAILED", "CANCELLED"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:logs-export-task")
def run(ctx) -> None:
    """CreateExportTask on a nonexistent log group raises ResourceNotFoundException and creates no
    task, while the same destination bucket with a real log group is accepted and completes."""
    svc = ctx.client("logs")
    s3 = ctx.client("s3")

    bucket = _create_export_bucket(ctx, s3)

    group = ctx.unique_name("sim2real-behav-lg-export-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    svc.create_log_group(logGroupName=group, tags={"simparity-check": CHECK})
    ctx.on_cleanup(lambda: svc.delete_log_group(logGroupName=group))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)
    svc.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": int(time.time() * 1000), "message": "sim2real export probe"}],
    )
    creation_time = svc.describe_log_groups(logGroupNamePrefix=group)["logGroups"][0][
        "creationTime"
    ]

    missing_group = ctx.unique_name("sim2real-behav-lg-export-missing-")
    now_ms = int(time.time() * 1000)
    code, msg = _error(
        lambda: svc.create_export_task(
            logGroupName=missing_group,
            destination=bucket,
            **{"from": now_ms - 3_600_000},
            to=now_ms,
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r} {msg!r}"
    assert msg == "The specified log group does not exist.", f"unexpected message: {msg!r}"

    all_tasks = svc.describe_export_tasks()["exportTasks"]
    missing_group_tasks = [t for t in all_tasks if t.get("logGroupName") == missing_group]
    assert missing_group_tasks == [], (
        f"expected no export tasks to exist after the rejected call, found {missing_group_tasks}"
    )

    # Positive control: the same destination bucket with a real log group is accepted.
    task_id = svc.create_export_task(
        logGroupName=group,
        destination=bucket,
        **{"from": creation_time},
        to=int(time.time() * 1000),
    )["taskId"]

    final_task = _poll_until(
        lambda: svc.describe_export_tasks(taskId=task_id)["exportTasks"][0],
        lambda t: t["status"]["code"] in _TERMINAL,
        timeout_s=300.0,
        interval_s=5.0,
    )
    assert final_task["status"]["code"] == "COMPLETED", (
        f"expected the valid-group export task to complete, got {final_task['status']}"
    )


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last result={result!r}")


def _create_export_bucket(ctx, s3):
    bucket = ctx.unique_name("sim2real-behav-export-")
    # CreateBucket rejects a LocationConstraint for us-east-1, so it is omitted only there.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]}
    )

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "CwlAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": f"logs.{ctx.region}.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket}",
            },
            {
                "Sid": "CwlWrite",
                "Effect": "Allow",
                "Principal": {"Service": f"logs.{ctx.region}.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    return bucket


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
