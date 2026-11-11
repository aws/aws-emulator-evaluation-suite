"""export-task-honors-time-window-boundaries."""
from __future__ import annotations

import gzip
import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "export-task-honors-time-window-boundaries"
GROUP = "visibility-timeout-ttl"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:logs-export-task")
def run(ctx) -> None:
    """CreateExportTask only includes events whose timestamp falls within [from, to)."""
    logs = ctx.client("logs")
    log_group = _create_log_group(ctx)
    log_stream = ctx.unique_name("stream-")
    logs.create_log_stream(logGroupName=log_group, logStreamName=log_stream)

    marker = ctx.unique_name("marker-")
    now_ms = int(time.time() * 1000)
    hour_ms = 60 * 60 * 1000
    # Events are backdated by hours: CreateExportTask may not export just-ingested events, and
    # can complete while delivering zero objects for them.
    t_before = now_ms - 3 * hour_ms
    t_in = now_ms - 2 * hour_ms
    t_after = now_ms - 1 * hour_ms

    before_msg = f"OUTSIDE-BEFORE-{marker}"
    in_msg = f"INSIDE-WINDOW-{marker}"
    after_msg = f"OUTSIDE-AFTER-{marker}"

    logs.put_log_events(
        logGroupName=log_group,
        logStreamName=log_stream,
        logEvents=[
            {"timestamp": t_before, "message": before_msg},
            {"timestamp": t_in, "message": in_msg},
            {"timestamp": t_after, "message": after_msg},
        ],
    )
    _wait_for_events(ctx, log_group, log_stream, expected_count=3, timeout_s=150.0)

    from_ms = t_in - 30 * 60 * 1000
    to_ms = t_in + 30 * 60 * 1000  # excludes t_before and t_after, includes only t_in

    bucket = _create_export_bucket(ctx)
    prefix = ctx.unique_name("export-")
    task_id = _create_export_task_with_retry(
        ctx, log_group=log_group, bucket=bucket, prefix=prefix, from_ms=from_ms, to_ms=to_ms
    )

    status = _poll_export_status(
        ctx, task_id, {"COMPLETED", "FAILED", "CANCELLED"}, timeout_s=60.0
    )
    if status != "COMPLETED":
        raise AssertionError(f"export task did not complete: final status {status!r}")

    body_text = _wait_for_exported_text(ctx, bucket, prefix, timeout_s=60.0)
    if body_text is None:
        raise AssertionError(
            "export task completed with no exported objects even for hours-old, "
            "confirmed-visible source events"
        )

    assert in_msg in body_text, "in-window event missing from export output"
    assert before_msg not in body_text, "event before the 'from' boundary was exported"
    assert after_msg not in body_text, "event at/after the 'to' boundary was exported"


def _create_log_group(ctx) -> str:
    logs = ctx.client("logs")
    name = ctx.unique_name("sim2real-behav-cwl-export-")
    logs.create_log_group(logGroupName=name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
    return name


def _wait_for_events(ctx, log_group: str, log_stream: str, expected_count: int, timeout_s: float) -> None:
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = logs.get_log_events(
            logGroupName=log_group, logStreamName=log_stream, startFromHead=True
        )
        if len(resp["events"]) >= expected_count:
            return
        time.sleep(3.0)
    raise AssertionError(f"events never became visible via GetLogEvents within {timeout_s}s")


def _create_export_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region
    bucket = ctx.unique_name("sim2real-behav-cwlexp-").lower().replace("_", "-")
    # Not a region pin: the bucket still lands in ctx.region. CreateBucket's own API quirk is
    # what needs the literal -- us-east-1 is the one region that rejects a LocationConstraint.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "Sim2RealOwner", "Value": "behavioral-suite"}]}
    )

    # Buckets created after April 2023 default to ACLs disabled (BucketOwnerEnforced), but
    # CloudWatch Logs' export writer PUTs objects with x-amz-acl: bucket-owner-full-control.
    # Without this, every export write is rejected and the task completes having delivered
    # nothing, which looks identical to (and was previously misdiagnosed as) ingestion lag.
    s3.put_bucket_ownership_controls(
        Bucket=bucket, OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]}
    )

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowGetBucketAcl",
                "Effect": "Allow",
                "Principal": {"Service": f"logs.{region}.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket}",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            },
            {
                "Sid": "AllowPutObject",
                "Effect": "Allow",
                "Principal": {"Service": f"logs.{region}.amazonaws.com"},
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
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        try:
            s3.get_bucket_policy(Bucket=bucket)
            break
        except Exception:
            time.sleep(1.0)
    return bucket


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            keys = [{"Key": obj["Key"]} for obj in page.get("Contents", [])]
            if keys:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_export_task_with_retry(
    ctx, *, log_group: str, bucket: str, prefix: str, from_ms: int, to_ms: int, timeout_s: float = 45.0
) -> str:
    from botocore.exceptions import ClientError

    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = logs.create_export_task(
                logGroupName=log_group,
                destination=bucket,
                destinationPrefix=prefix,
                fromTime=from_ms,
                to=to_ms,
            )
            return resp["taskId"]
        except ClientError as e:
            # The bucket policy this check just wrote can take a moment to be visible to
            # CreateExportTask's own permission check even after get_bucket_policy echoes it.
            if e.response["Error"]["Code"] == "InvalidParameterException":
                last_err = e
                time.sleep(2.0)
                continue
            raise
    raise AssertionError(f"CreateExportTask never accepted the request: {last_err}")


def _poll_export_status(
    ctx, task_id: str, target_statuses: set[str], timeout_s: float = 90.0
) -> str:
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    last_status = "UNKNOWN"
    while time.monotonic() < deadline:
        resp = logs.describe_export_tasks(taskId=task_id)
        tasks: list[dict[str, Any]] = resp.get("exportTasks", [])
        if tasks:
            last_status = tasks[0]["status"]["code"]
            if last_status in target_statuses:
                return last_status
        time.sleep(2.0)
    return last_status


def _wait_for_exported_text(ctx, bucket: str, prefix: str, timeout_s: float = 120.0):
    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
        contents = resp.get("Contents", [])
        data_keys = [o["Key"] for o in contents if not o["Key"].endswith("aws-logs-write-test")]
        if data_keys:
            chunks = []
            for key in data_keys:
                raw = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
                try:
                    text = gzip.decompress(raw).decode("utf-8", errors="replace")
                except OSError:
                    text = raw.decode("utf-8", errors="replace")
                chunks.append(text)
            return "\n".join(chunks)
        time.sleep(3.0)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
