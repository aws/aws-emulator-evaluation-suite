"""create-export-task-overlapping-window-conflict-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-export-task-overlapping-window-conflict-rejected"
GROUP = "error-semantics"
SERVICES = ["logs"]

_TERMINAL = {"COMPLETED", "FAILED", "CANCELLED"}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:logs-export-task")
def run(ctx) -> None:
    """CreateExportTask with `to` earlier than `from` raises InvalidParameterException with its exact message
    and creates no task, while the same log group with a forward window exports to COMPLETED."""

    logs = ctx.client("logs")
    s3 = ctx.client("s3")

    bucket = _create_export_bucket(ctx, s3)
    group_name = ctx.unique_name("sim2real-logs-export-")
    stream_name = ctx.unique_name("stream-")
    logs.create_log_group(logGroupName=group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))
    logs.create_log_stream(logGroupName=group_name, logStreamName=stream_name)

    creation_time = logs.describe_log_groups(logGroupNamePrefix=group_name)["logGroups"][0][
        "creationTime"
    ]

    now_ms = int(time.time() * 1000)
    logs.put_log_events(
        logGroupName=group_name,
        logStreamName=stream_name,
        logEvents=[{"timestamp": now_ms, "message": "sim2real export test event"}],
    )

    # A reversed window (`to` before `from`) is an internally inconsistent, malformed time
    # range -- CreateExportTask must reject it outright, regardless of the log group's
    # lifecycle.
    now_ms2 = int(time.time() * 1000)
    conflicting_task_name = ctx.unique_name("task-conflict-")
    reversed_from, reversed_to = now_ms2, now_ms2 - 3_600_000
    code = _error(
        lambda: logs.create_export_task(
            taskName=conflicting_task_name,
            logGroupName=group_name,
            destination=bucket,
            **{"from": reversed_from},
            to=reversed_to,
        )
    )
    expected = (
        "InvalidParameterException",
        f"Specified time range of '{reversed_from}' and '{reversed_to}' is not valid. Please make sure "
        "the values are within the retention period of the log groups and from value is lesser than "
        "the to value",
    )
    assert code == expected, f"expected {expected!r}, got {code!r}"

    # Effect absent: no export task was ever created for the conflicting window. (Describe
    # ExportTasks has no logGroupName filter -- filter client-side by taskId/logGroupName.)
    all_tasks = logs.describe_export_tasks()["exportTasks"]
    group_tasks = [t for t in all_tasks if t.get("logGroupName") == group_name]
    assert group_tasks == [], (
        f"expected no export tasks to exist after the rejected call, found {group_tasks}"
    )

    # Positive control: the exact same log group, but with a window that legitimately starts
    # at-or-after creationTime and covers the ingested event, is accepted and completes.
    task_id = logs.create_export_task(
        taskName=ctx.unique_name("task-valid-"),
        logGroupName=group_name,
        destination=bucket,
        **{"from": creation_time},
        to=int(time.time() * 1000),
    )["taskId"]

    final_task = _poll_until(
        lambda: logs.describe_export_tasks(taskId=task_id)["exportTasks"][0],
        lambda t: t["status"]["code"] in _TERMINAL,
        timeout_s=300.0,
        interval_s=5.0,
    )
    assert final_task["status"] == {"code": "COMPLETED", "message": "Completed successfully"}, (
        f"expected the valid-window export task to complete, got {final_task['status']}"
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
    bucket = ctx.unique_name("sim2real-logs-export-")
    # us-east-1 rejects an explicit LocationConstraint on CreateBucket; every other region
    # requires one. ctx.region drives the branch, nothing is pinned.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "Sim2RealOwner", "Value": "behavioral-suite"}]}
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

