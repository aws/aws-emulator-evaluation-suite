"""export-task-cancel-terminal-state-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "export-task-cancel-terminal-state-rejected"
GROUP = "state-machine"
SERVICES = ["logs"]


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _expect_rejection(fn):
    """Call fn(); return the ClientError (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_export_bucket(ctx):
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-logs-expterm-").lower().replace("_", "-")

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
    return bucket


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:logs-export-task")
def run(ctx) -> None:
    """CancelExportTask on an already-terminal (CANCELLED) task is rejected and does not re-mutate it."""
    logs = ctx.client("logs")
    bucket = _create_export_bucket(ctx)

    log_group_name = ctx.unique_name("sim2real-logs-expterm-lg-")
    logs.create_log_group(logGroupName=log_group_name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))

    now_ms = int(time.time() * 1000)
    task_id = logs.create_export_task(
        logGroupName=log_group_name, **{"from": 0}, to=now_ms, destination=bucket
    )["taskId"]

    # Positive control: cancelling a fresh, non-terminal task succeeds.
    try:
        logs.cancel_export_task(taskId=task_id)
    except ClientError as e:
        raise AssertionError(
            f"positive control failed: cancel_export_task raised "
            f"{e.response['Error']['Code']}"
        )
    status_after_first = _poll_until(
        lambda: logs.describe_export_tasks(taskId=task_id)["exportTasks"][0]["status"]["code"],
        lambda code: code in ("CANCELLED", "COMPLETED", "FAILED"),
        timeout_s=120.0,
        interval_s=2.0,
    )
    assert status_after_first == "CANCELLED", (
        f"positive control failed: expected task to settle at CANCELLED, "
        f"got {status_after_first}"
    )

    # Negative: break the one precondition CancelExportTask needs (task must not already be
    # terminal) by cancelling the same CANCELLED task again.
    second_cancel_code, second_cancel_message = _expect_rejection(
        lambda: logs.cancel_export_task(taskId=task_id)
    )
    assert second_cancel_code == "InvalidOperationException", (
        f"expected InvalidOperationException cancelling an already-terminal task, "
        f"got {second_cancel_code}"
    )
    # AWS answers a CANCELLED task with either of two exact messages; both name the task as
    # already terminal.
    assert second_cancel_message in (
        "The specified export task has been already cancelled",
        "The specified export task has already finished",
    ), (
        f"unexpected CancelExportTask message for an already-CANCELLED task: "
        f"{second_cancel_message!r}"
    )

    # The forbidden effect (re-mutating a terminal task) did not happen: status is unchanged.
    status_final = logs.describe_export_tasks(taskId=task_id)["exportTasks"][0]["status"]["code"]
    assert status_final == "CANCELLED", (
        f"expected the rejected cancel to leave status unchanged at CANCELLED, "
        f"got {status_final}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
