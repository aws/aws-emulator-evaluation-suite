"""export-task-unknown-id-semantics."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "export-task-unknown-id-semantics"
GROUP = 'export-task'
SERVICES = ['logs']

def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")

def _create_export_bucket(ctx):
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-behav-export-").lower().replace("_", "-")

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
        Tagging={
            "TagSet": [
                {"Key": "sim2real", "Value": "export-task-unknown-id-semantics"},
                {"Key": "sim2real:managed", "Value": "true"},
            ]
        },
    )
    return bucket

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:logs-export-task")
def run(ctx) -> None:
    """DescribeExportTasks for an unknown taskId returns an empty list and CancelExportTask on it
    errors, while both operations recognize a real task id (positive control)."""
    logs = ctx.client("logs")
    bogus = ctx.unique_name("sim2real-behav-task-ghost-")

    bucket = _create_export_bucket(ctx)
    group = ctx.unique_name("sim2real-behav-lg-export-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    logs.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    logs.create_log_stream(logGroupName=group, logStreamName=stream)
    now_ms = int(time.time() * 1000)
    logs.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": now_ms, "message": "export-probe-message"}],
    )

    real_task_id = logs.create_export_task(
        logGroupName=group, **{"from": 0}, to=now_ms, destination=bucket
    )["taskId"]

    real_tasks = logs.describe_export_tasks(taskId=real_task_id).get("exportTasks", [])
    assert len(real_tasks) == 1 and real_tasks[0]["taskId"] == real_task_id, (
        f"expected describe_export_tasks to find the real task {real_task_id}, got {real_tasks}"
    )

    # Cancel may still raise InvalidOperationException if the task is already terminal,
    # but never a not-found/invalid-id error.
    try:
        logs.cancel_export_task(taskId=real_task_id)
    except ClientError as exc:
        real_cancel_code = exc.response["Error"]["Code"]
        real_cancel_message = exc.response["Error"].get("Message")
        assert real_cancel_code == "InvalidOperationException", (
            f"expected cancelling the real task {real_task_id} to succeed or report it "
            f"is already terminal, got {real_cancel_code}"
        )
        real_status = logs.describe_export_tasks(taskId=real_task_id)["exportTasks"][0]["status"]["code"]
        assert real_status == "COMPLETED", (
            f"expected the real task {real_task_id} to be refused cancellation only once it "
            f"COMPLETED, got status {real_status!r}"
        )
        assert real_cancel_message == "The specified export task has already finished", (
            f"unexpected CancelExportTask message for an already-terminal task: "
            f"{real_cancel_message!r}"
        )

    tasks = logs.describe_export_tasks(taskId=bogus).get("exportTasks", [])
    assert tasks == [], f"expected no export tasks for an unknown id, got {tasks}"

    code, message = _error(lambda: logs.cancel_export_task(taskId=bogus))
    assert code == "ResourceNotFoundException", (
        f"expected a not-found error cancelling an unknown export task, got {code}"
    )
    assert message == "The specified export task does not exist.", (
        f"unexpected CancelExportTask message for an unknown task id: {message!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
