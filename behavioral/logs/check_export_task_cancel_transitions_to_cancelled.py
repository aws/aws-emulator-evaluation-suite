"""export-task-cancel-transitions-to-cancelled."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "export-task-cancel-transitions-to-cancelled"
GROUP = "state-machine"
SERVICES = ["logs"]


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=2.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"export task status (last={last!r}): the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _create_export_bucket(ctx):
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-logs-exp-").lower().replace("_", "-")

    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)

    principal = {"Service": f"logs.{ctx.region}.amazonaws.com"}
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowLogsAcl",
                "Effect": "Allow",
                "Principal": principal,
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket}",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            },
            {
                "Sid": "AllowLogsPutObject",
                "Effect": "Allow",
                "Principal": principal,
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Condition": {
                    "StringEquals": {
                        "aws:SourceAccount": account_id,
                        "s3:x-amz-acl": "bucket-owner-full-control",
                    }
                },
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "export-task-cancel-transitions-to-cancelled"}]},
    )
    return bucket


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:logs-export-task")
def run(ctx) -> None:
    """CancelExportTask transitions a PENDING/RUNNING export task to CANCELLED."""
    logs = ctx.client("logs")
    bucket = _create_export_bucket(ctx)

    log_group_name = ctx.unique_name("sim2real-logs-exporttask-")
    logs.create_log_group(logGroupName=log_group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))

    def _status(tid):
        return logs.describe_export_tasks(taskId=tid)["exportTasks"][0]["status"]["code"]

    def _try_export_and_cancel():
        now_ms = int(time.time() * 1000)
        task_id = logs.create_export_task(
            logGroupName=log_group_name,
            **{"from": 0},
            to=now_ms,
            destination=bucket,
        )["taskId"]
        try:
            logs.cancel_export_task(taskId=task_id)
        except logs.exceptions.InvalidOperationException:
            return task_id, "raced"  # already reached a terminal state before we could cancel
        return task_id, "cancel_requested"

    # A refused cancel means the export finished first; that attempt is drained and retried
    # with a fresh task, up to 4 attempts.
    raced = []
    for _attempt in range(4):
        task_id, outcome = _try_export_and_cancel()
        if outcome == "cancel_requested":
            break
        raced.append(task_id)
        _poll_until(
            lambda tid=task_id: _status(tid),
            lambda code: code in ("CANCELLED", "COMPLETED", "FAILED"),
            timeout_s=_budget_s(ctx, 60.0),
            interval_s=1.0,
            ctx=ctx,
        )
    else:
        raise AssertionError(
            "export task reached a terminal state before CancelExportTask could be issued, "
            f"on every attempt: {raced!r}"
        )

    final_status = _poll_until(
        lambda: _status(task_id),
        lambda code: code in ("CANCELLED", "COMPLETED", "FAILED"),
        timeout_s=_budget_s(ctx, 120.0),
        interval_s=1.0,
        ctx=ctx,
    )
    assert final_status == "CANCELLED", (
        f"expected export task {task_id} to settle at CANCELLED after CancelExportTask, "
        f"got {final_status}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
