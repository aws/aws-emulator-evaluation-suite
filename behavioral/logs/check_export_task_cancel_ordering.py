"""export-task-cancel-ordering."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "export-task-cancel-ordering"
GROUP = 'export-tasks'
SERVICES = ['logs']


def _make_events(messages, start_ts_ms=None, step_ms=1000):
    base = start_ts_ms if start_ts_ms is not None else int(time.time() * 1000)
    return [{"timestamp": base + i * step_ms, "message": m} for i, m in enumerate(messages)]


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition", ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _describe_log_group(svc, name):
    desc = svc.describe_log_groups(logGroupNamePrefix=name)
    for g in desc.get("logGroups", []):
        if g["logGroupName"] == name:
            return g
    raise AssertionError(f"log group {name!r} not found via DescribeLogGroups")


def _export_bucket_policy(bucket_name, region, account, log_group_arn_with_star):
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


def _delete_bucket(s3, bucket):
    try:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    s3.delete_bucket(Bucket=bucket)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:logs-export-task")
def run(ctx) -> None:
    """CancelExportTask halts an in-flight export task, driving it to CANCELLED; cancelling the now
    terminal task is rejected and leaves its status unchanged."""
    svc = ctx.client("logs")
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]

    group = ctx.unique_name("sim2real-behav-lg-exportcancel-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)
    svc.put_log_events(
        logGroupName=group, logStreamName=stream, logEvents=_make_events(["export-cancel-probe"])
    )
    group_arn_star = _describe_log_group(svc, group)["arn"]

    bucket_name = ctx.unique_name("sim2real-behav-export-cancel-")[:63].rstrip("-")
    create_kwargs = {"Bucket": bucket_name}
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda _b=bucket_name: _delete_bucket(s3, _b))
    s3.put_bucket_policy(
        Bucket=bucket_name,
        Policy=_export_bucket_policy(bucket_name, ctx.region, account, group_arn_star),
    )

    def _status(tid):
        return svc.describe_export_tasks(taskId=tid)["exportTasks"][0]["status"]["code"]

    # A tiny export can finish before the cancel lands; such an attempt is drained and retried
    # with a fresh task, up to 4 attempts.
    lost = []
    for _attempt in range(4):
        now_ms = int(time.time() * 1000)
        created = svc.create_export_task(
            logGroupName=group, **{"from": 0}, to=now_ms, destination=bucket_name
        )
        task_id = created["taskId"]
        status = _status(task_id)
        if status in ("PENDING", "RUNNING"):
            try:
                svc.cancel_export_task(taskId=task_id)
                break
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "InvalidOperationException":
                    raise
        lost.append((task_id, status))
        _poll_until(
            lambda tid=task_id: _status(tid),
            lambda s: s in ("CANCELLED", "COMPLETED", "FAILED"),
            timeout_s=_budget_s(ctx, 60),
            interval_s=1.0,
            ctx=ctx,
            description=f"export task {task_id} that finished before its cancel reaches a terminal status",
        )
    else:
        raise AssertionError(
            f"lost the race on every attempt: each export task reached a terminal status "
            f"before CancelExportTask could be issued: {lost!r}"
        )

    final = _poll_until(
        lambda: _status(task_id),
        lambda s: s in ("CANCELLED", "COMPLETED", "FAILED"),
        timeout_s=_budget_s(ctx, 60),
        interval_s=1.0,
        ctx=ctx,
        description="cancelled export task reaches a terminal status",
    )
    assert final in ("CANCELLED", "COMPLETED"), (
        f"expected the cancelled export task to end CANCELLED (or race to COMPLETED), got {final!r}"
    )

    # A task that settles CANCELLED here is refused with either of two exact messages,
    # depending on where the export was when the first cancel landed.
    code, message = _error(lambda: svc.cancel_export_task(taskId=task_id))
    assert code == "InvalidOperationException", (
        f"expected cancelling an already-terminal export task to be rejected with "
        f"InvalidOperationException, got {code!r}"
    )
    assert message in (
        "The specified export task has been already cancelled",
        "The specified export task has already finished",
    ), f"unexpected CancelExportTask message for an already-terminal task: {message!r}"
    unmutated = svc.describe_export_tasks(taskId=task_id)["exportTasks"][0]["status"]["code"]
    assert unmutated == final, (
        f"rejected CancelExportTask must not mutate task status: was {final!r}, now {unmutated!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
