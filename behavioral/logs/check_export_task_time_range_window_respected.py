"""export-task-time-range-window-respected."""
from __future__ import annotations

import gzip
import time

from behavioral_harness import tags

CHECK = "export-task-time-range-window-respected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["logs"]


def _never_ready(msg: str):
    """A resource accepted but never ready; returned so a call site keeps ``from exc`` chaining."""
    return AssertionError(msg)


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:logs-export-task")
def run(ctx) -> None:
    """CreateExportTask only exports events whose timestamp falls within [from, to);
    events outside that window are excluded from the exported S3 objects, verified by
    downloading and inspecting the actual exported data (not just task metadata)."""
    logs = ctx.client("logs")
    s3 = ctx.client("s3")

    group = ctx.unique_name("sim2real-behav-lg-")
    stream = ctx.unique_name("sim2real-behav-ls-")
    logs.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    logs.create_log_stream(logGroupName=group, logStreamName=stream)

    now_ms = int(time.time() * 1000)
    hour_ms = 60 * 60 * 1000
    outside_before_ts = now_ms - 4 * hour_ms
    inside_one_ts = now_ms - 3 * hour_ms
    inside_two_ts = now_ms - 2 * hour_ms
    outside_after_ts = now_ms - 1 * hour_ms
    window_from = now_ms - int(3.5 * hour_ms)
    window_to = now_ms - int(1.5 * hour_ms)

    marker = ctx.unique_name("m")
    events = [
        {"timestamp": outside_before_ts, "message": f"OUTSIDE-BEFORE-{marker}"},
        {"timestamp": inside_one_ts, "message": f"INSIDE-ONE-{marker}"},
        {"timestamp": inside_two_ts, "message": f"INSIDE-TWO-{marker}"},
        {"timestamp": outside_after_ts, "message": f"OUTSIDE-AFTER-{marker}"},
    ]
    logs.put_log_events(logGroupName=group, logStreamName=stream, logEvents=events)
    # On real AWS, PutLogEvents for a batch of historical (multi-hour-old)
    # timestamps can take noticeably longer than "just-now" events to become
    # visible via GetLogEvents -- even 120s was not always a generous enough
    # bound; widen the poll budget further rather than the assertion itself.
    _wait_for_events(ctx, group, stream, expected_count=4, timeout_s=300)

    bucket = ctx.unique_name("sim2real-behav-export-")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    _create_bucket(s3, bucket, ctx.region)
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    _allow_acls(s3, bucket)
    _apply_export_bucket_policy(s3, bucket, ctx.region, account_id)

    prefix = ctx.unique_name("export")
    task_id = _create_export_task_with_retry(
        logs,
        log_group_name=group,
        from_ms=window_from,
        to_ms=window_to,
        bucket=bucket,
        prefix=prefix,
    )
    ctx.on_cleanup(lambda: _best_effort_cancel(logs, task_id))

    status = _wait_for_export_task(logs, task_id, timeout_s=240)
    if status != "COMPLETED":
        raise _never_ready(
            f"export task did not reach COMPLETED within the poll budget (status={status})",
        )

    blob = _download_and_decompress_all(s3, bucket, prefix)
    assert f"INSIDE-ONE-{marker}" in blob, "in-window event missing from exported data"
    assert f"INSIDE-TWO-{marker}" in blob, "in-window event missing from exported data"
    assert f"OUTSIDE-BEFORE-{marker}" not in blob, "event before the export window leaked into export"
    assert f"OUTSIDE-AFTER-{marker}" not in blob, "event after the export window leaked into export"


def _wait_for_events(ctx, group, stream, expected_count, timeout_s=120.0):
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = logs.get_log_events(logGroupName=group, logStreamName=stream, startFromHead=True)
        if len(resp["events"]) >= expected_count:
            return
        time.sleep(3.0)
    raise AssertionError(f"events never became visible via GetLogEvents within {timeout_s}s")


def _create_bucket(s3, bucket, region):
    # us-east-1 is the one region CreateBucket rejects a LocationConstraint for; not a region pin.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    waiter = s3.get_waiter("bucket_exists")
    waiter.wait(Bucket=bucket, WaiterConfig={"Delay": 2, "MaxAttempts": 50})


def _allow_acls(s3, bucket):
    # CloudWatch Logs' S3 export writes objects with x-amz-acl: bucket-owner-full-control;
    # buckets created after April 2023 default to ACLs disabled, which breaks that write.
    s3.put_bucket_ownership_controls(
        Bucket=bucket, OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]}
    )


def _apply_export_bucket_policy(s3, bucket, region, account_id):
    import json

    service_principal = f"logs.{region}.amazonaws.com"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowCloudWatchLogsGetBucketAcl",
                "Action": "s3:GetBucketAcl",
                "Effect": "Allow",
                "Resource": f"arn:aws:s3:::{bucket}",
                "Principal": {"Service": service_principal},
                "Condition": {"StringEquals": {"aws:SourceAccount": [account_id]}},
            },
            {
                "Sid": "AllowCloudWatchLogsPutObject",
                "Action": "s3:PutObject",
                "Effect": "Allow",
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Principal": {"Service": service_principal},
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control",
                        "aws:SourceAccount": [account_id],
                    }
                },
            },
        ],
    }
    last_err = None
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        try:
            s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
            return
        except ClientError as e:
            last_err = e
            time.sleep(2.0)
    raise AssertionError(f"could not set export bucket policy: {last_err}")


def _create_export_task_with_retry(logs, *, log_group_name, from_ms, to_ms, bucket, prefix, timeout_s=60.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = logs.create_export_task(
                logGroupName=log_group_name,
                fromTime=from_ms,
                to=to_ms,
                destination=bucket,
                destinationPrefix=prefix,
            )
            return resp["taskId"]
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("InvalidParameterException", "LimitExceededException"):
                last_err = e
                time.sleep(3.0)
                continue
            raise
    raise AssertionError(f"CreateExportTask never succeeded (likely bucket-policy propagation or a "
                         f"concurrent export task): {last_err}")


def _wait_for_export_task(logs, task_id, timeout_s=240.0):
    deadline = time.monotonic() + timeout_s
    status = "UNKNOWN"
    while time.monotonic() < deadline:
        resp = logs.describe_export_tasks(taskId=task_id)
        tasks = resp.get("exportTasks", [])
        if tasks:
            status = tasks[0]["status"]["code"]
            if status in ("COMPLETED", "FAILED", "CANCELLED"):
                return status
        time.sleep(5.0)
    return status


def _best_effort_cancel(logs, task_id):
    from botocore.exceptions import ClientError

    # By the time cleanup runs, the task has already reached COMPLETED (the body's own
    # precondition for proceeding), so CancelExportTask routinely answers with this -- it is
    # not a cleanup failure, just a task that finished before it could be cancelled.
    try:
        logs.cancel_export_task(taskId=task_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "InvalidOperationException"):
            raise


def _download_and_decompress_all(s3, bucket, prefix):
    blob_parts = []
    continuation = None
    while True:
        kwargs = {"Bucket": bucket, "Prefix": prefix}
        if continuation:
            kwargs["ContinuationToken"] = continuation
        resp = s3.list_objects_v2(**kwargs)
        for obj in resp.get("Contents", []):
            body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
            try:
                text = gzip.decompress(body).decode("utf-8", errors="replace")
            except OSError:
                text = body.decode("utf-8", errors="replace")
            blob_parts.append(text)
        if resp.get("IsTruncated"):
            continuation = resp.get("NextContinuationToken")
        else:
            break
    return "\n".join(blob_parts)


def _delete_bucket(s3, bucket):
    continuation = None
    while True:
        kwargs = {"Bucket": bucket}
        if continuation:
            kwargs["ContinuationToken"] = continuation
        resp = s3.list_objects_v2(**kwargs)
        objects = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
        if objects:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        if resp.get("IsTruncated"):
            continuation = resp.get("NextContinuationToken")
        else:
            break
    s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
