"""e2e-export-task-rejected-for-invalid-input."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-export-task-rejected-for-invalid-input"
GROUP = "e2e"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:logs-export-task")
def run(ctx) -> None:
    """CreateExportTask rejects a missing log group and an inverted time range without creating a
    task, while a valid window on the same group and bucket completes (positive control).
    """
    logs = ctx.client("logs")

    bucket = _create_export_bucket(ctx)
    missing_log_group = ctx.unique_name("sim2real-behav-lg-missing-")
    now_ms = int(time.time() * 1000)

    code, message = _error(
        lambda: logs.create_export_task(
            logGroupName=missing_log_group,
            destination=bucket,
            **{"from": now_ms - 60000, "to": now_ms},
        )
    )
    assert code == "ResourceNotFoundException", (
        f"CreateExportTask against a nonexistent log group returned {code!r}, expected "
        "ResourceNotFoundException"
    )
    assert message == "The specified log group does not exist.", (
        f"unexpected CreateExportTask message for a nonexistent log group: {message!r}"
    )

    real_log_group = ctx.unique_name("sim2real-behav-lg-real-")
    logs.create_log_group(logGroupName=real_log_group, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=real_log_group))

    code, message = _error(
        lambda: logs.create_export_task(
            logGroupName=real_log_group,
            destination=bucket,
            **{"from": now_ms, "to": now_ms - 60000},  # to < from: inverted range
        )
    )
    assert code == "InvalidParameterException", (
        f"CreateExportTask with to < from returned {code!r}, expected InvalidParameterException"
    )
    assert message == (
        f"Specified time range of '{now_ms}' and '{now_ms - 60000}' is not valid. Please make "
        "sure the values are within the retention period of the log groups and from value is "
        "lesser than the to value"
    ), (
        f"unexpected CreateExportTask message for an inverted time range: {message!r}"
    )

    # Positive control: the rejections are about the bad input, not the group or bucket.
    valid_task_id = logs.create_export_task(
        logGroupName=real_log_group,
        destination=bucket,
        **{"from": now_ms - 60000, "to": now_ms},
    )["taskId"]
    ctx.on_cleanup(lambda: _best_effort_cancel(logs, valid_task_id))
    final_status = _poll_until(
        lambda: logs.describe_export_tasks(taskId=valid_task_id)["exportTasks"][0]["status"]["code"],
        lambda s: s in ("COMPLETED", "FAILED", "CANCELLED"),
        timeout_s=240,
        description="the positive-control export task reaches a terminal status",
    )
    assert final_status == "COMPLETED", (
        f"expected the validly-ordered positive-control export task to complete, got "
        f"{final_status!r}"
    )

    all_tasks = logs.describe_export_tasks()["exportTasks"]
    rejected_leg_tasks = [
        t
        for t in all_tasks
        if t.get("logGroupName") == real_log_group and t["taskId"] != valid_task_id
    ]
    assert rejected_leg_tasks == [], (
        "no export task should have been created by either rejected call, found "
        f"{rejected_leg_tasks}"
    )


def _error(fn):
    """Call fn(); return the ClientError's (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _best_effort_cancel(logs, task_id):
    try:
        logs.cancel_export_task(taskId=task_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_export_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-behav-export-").lower().replace("_", "-")

    # CreateBucket rejects an explicit LocationConstraint of us-east-1.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )

    def _empty_and_delete():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_empty_and_delete)

    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowGetBucketAcl",
                "Effect": "Allow",
                "Principal": {"Service": f"logs.{ctx.region}.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket}",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            },
            {
                "Sid": "AllowPutObject",
                "Effect": "Allow",
                "Principal": {"Service": f"logs.{ctx.region}.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control",
                        "aws:SourceAccount": account_id,
                    }
                },
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    return bucket


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

