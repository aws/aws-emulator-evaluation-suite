"""create-export-task-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _make_events(messages, step_ms=1000):
    base = int(time.time() * 1000)
    return [{"timestamp": base + i * step_ms, "message": m} for i, m in enumerate(messages)]


def _export_bucket_policy(region, account, bucket_name, log_group_arn_with_star):
    principal = {"Service": f"logs.{region}.amazonaws.com"}
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowGetBucketAcl",
                    "Action": "s3:GetBucketAcl",
                    "Effect": "Allow",
                    "Resource": f"arn:aws:s3:::{bucket_name}",
                    "Principal": principal,
                    "Condition": {
                        "StringEquals": {"aws:SourceAccount": [account]},
                        "ArnLike": {"aws:SourceArn": [log_group_arn_with_star]},
                    },
                },
                {
                    "Sid": "AllowPutObject",
                    "Action": "s3:PutObject",
                    "Effect": "Allow",
                    "Resource": f"arn:aws:s3:::{bucket_name}/*",
                    "Principal": principal,
                    "Condition": {
                        "StringEquals": {
                            "s3:x-amz-acl": "bucket-owner-full-control",
                            "aws:SourceAccount": [account],
                        },
                        "ArnLike": {"aws:SourceArn": [log_group_arn_with_star]},
                    },
                },
            ],
        }
    )


CHECK = "create-export-task-lifecycle"
GROUP = 'export-tasks'
SERVICES = ['logs']


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:logs-export-task")
def run(ctx) -> None:
    """CreateExportTask creates a task visible in DescribeExportTasks that can be cancelled
    before completion; the task settles in the terminal state the cancel outcome implies."""
    svc = ctx.client("logs")
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]

    group = ctx.unique_name("sim2real-behav-lg-export-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    ctx.on_cleanup(lambda _n=group: svc.put_log_group_deletion_protection(logGroupIdentifier=_n, deletionProtectionEnabled=False))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)
    svc.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=_make_events(["export-probe-message"]),
    )
    group_arn_star = svc.describe_log_groups(logGroupNamePrefix=group)["logGroups"][0]["arn"]

    bucket_name = ctx.unique_name("sim2real-behav-export-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )

    def _teardown_bucket(_b=bucket_name, _s3=s3):
        try:
            for o in _s3.list_objects_v2(Bucket=_b).get("Contents", []):
                _s3.delete_object(Bucket=_b, Key=o["Key"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise
        _s3.delete_bucket(Bucket=_b)

    ctx.on_cleanup(_teardown_bucket)
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "Sim2RealOwner", "Value": "behavioral-suite"}]}
    )
    s3.put_bucket_policy(
        Bucket=bucket_name, Policy=_export_bucket_policy(ctx.region, account, bucket_name, group_arn_star)
    )

    now_ms = int(time.time() * 1000)
    task_resp = svc.create_export_task(
        logGroupName=group, **{"from": 0}, to=now_ms, destination=bucket_name
    )
    task_id = task_resp["taskId"]

    desc = svc.describe_export_tasks(taskId=task_id)
    tasks = desc.get("exportTasks", [])
    assert len(tasks) == 1 and tasks[0]["taskId"] == task_id, (
        f"expected DescribeExportTasks(taskId={task_id!r}) to return exactly that task, got {tasks!r}"
    )

    try:
        svc.cancel_export_task(taskId=task_id)
        cancel_err = None
    except ClientError as exc:
        err = exc.response.get("Error", {})
        cancel_err = (err.get("Code"), err.get("Message"))
    final = _poll_until(
        lambda: svc.describe_export_tasks(taskId=task_id)["exportTasks"][0],
        lambda t: t["status"]["code"] in ("CANCELLED", "COMPLETED", "FAILED"),
        timeout_s=60,
        interval_s=2.0,
        description="export task reaches a terminal status",
    )
    if cancel_err is None:
        # CancelExportTask accepted the request -> the task must end CANCELLED.
        assert final["status"] == {"code": "CANCELLED", "message": "Export task cancelled by user"}, (
            f"CancelExportTask succeeded but task ended as {final['status']!r}"
        )
    else:
        # Lost the race to completion: cancel is only rejected once the task
        # already reached a terminal state.
        assert cancel_err == ("InvalidOperationException", "The specified export task has already finished"), (
            f"expected InvalidOperationException for a too-late cancel, got {cancel_err!r}"
        )
        assert final["status"] == {"code": "COMPLETED", "message": "Completed successfully"}, (
            f"cancel was rejected as 'already terminal' but status is {final['status']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
