"""concurrent-put-record-batch-no-false-conflict."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-put-record-batch-no-false-conflict"
GROUP = "concurrency"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Concurrent PutRecordBatch calls on one stream all return FailedPutCount 0 with a RecordId and no ErrorCode
    per record, and every record lands in S3 exactly once: ingestion has no optimistic-lock conflicts."""
    firehose = ctx.client("firehose")
    s3 = ctx.client("s3")
    bucket_name, bucket_arn = _create_bucket(ctx)
    _role_name, role_arn, _policy_name = _create_firehose_role(ctx, bucket_arn)
    stream_name = _create_extended_s3_stream(ctx, role_arn, bucket_arn)
    _wait_stream_active(ctx, stream_name)

    num_workers = 8
    records_per_worker = 5
    expected_markers = {
        f"race-{worker_id}-{i}" for worker_id in range(num_workers) for i in range(records_per_worker)
    }

    def send_batch(worker_id: int):
        records = [
            {"Data": f"race-{worker_id}-{i}\n".encode()} for i in range(records_per_worker)
        ]
        return firehose.put_record_batch(DeliveryStreamName=stream_name, Records=records)

    with ThreadPoolExecutor(max_workers=num_workers) as pool:
        futures = [pool.submit(send_batch, worker_id) for worker_id in range(num_workers)]
        responses = [f.result() for f in futures]

    assert len(responses) == num_workers
    for resp in responses:
        assert resp["FailedPutCount"] == 0, f"unexpected failed puts: {resp}"
        assert len(resp["RequestResponses"]) == records_per_worker
        for entry in resp["RequestResponses"]:
            assert "ErrorCode" not in entry, f"unexpected per-record error: {entry}"
            assert "RecordId" in entry

    delivered = _poll_until(
        lambda: _collect_s3_markers(s3, bucket_name),
        lambda markers: len(markers) >= len(expected_markers),
        timeout_s=150.0,
        interval_s=5.0,
    )
    assert delivered == expected_markers, (
        f"missing={expected_markers - delivered} extra={delivered - expected_markers}"
    )


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-fh-bkt-").lower().replace("_", "-")
    kwargs = {"Bucket": name}
    # us-east-1 is the only region where CreateBucket rejects an explicit LocationConstraint.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name, f"arn:aws:s3:::{name}"


def _empty_and_delete_bucket(ctx, name):
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=name):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_firehose_role(ctx, bucket_arn, extra_statements=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-fh-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "firehose.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    statements = [{
        "Effect": "Allow",
        "Action": [
            "s3:AbortMultipartUpload",
            "s3:GetBucketLocation",
            "s3:GetObject",
            "s3:ListBucket",
            "s3:ListBucketMultipartUploads",
            "s3:PutObject",
        ],
        "Resource": [bucket_arn, f"{bucket_arn}/*"],
    }]
    if extra_statements:
        statements.extend(extra_statements)

    policy_name = ctx.unique_name("sim2real-behav-fh-pol-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_name, role_arn, policy_name


def _create_extended_s3_stream(ctx, role_arn, bucket_arn, buffering_interval=60, buffering_size_mb=1):
    # IAM role trust propagation into Firehose is eventually consistent -- a freshly created
    # role can transiently be rejected with InvalidArgumentException ("unable to assume role")
    # even though the trust policy is correct, so retry through that window.
    firehose = ctx.client("firehose")
    name = ctx.unique_name("sim2real-behav-fh-stream-")
    dest_config = {
        "RoleARN": role_arn,
        "BucketARN": bucket_arn,
        "BufferingHints": {"IntervalInSeconds": buffering_interval, "SizeInMBs": buffering_size_mb},
    }
    deadline = time.monotonic() + 120.0
    while True:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=dest_config,
            )
            break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = err.response["Error"].get("Message", "")
            if code == "InvalidArgumentException" and "unable to assume role" in msg.lower() and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise
    ctx.on_cleanup(lambda: _delete_stream(ctx, name))
    return name


def _delete_stream(ctx, name):
    firehose = ctx.client("firehose")
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_stream_active(ctx, name, timeout_s: float = 180.0) -> str:
    firehose = ctx.client("firehose")

    def probe():
        return firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamStatus"]

    deadline = time.monotonic() + timeout_s
    status = probe()
    while status not in ("ACTIVE", "CREATING_FAILED") and time.monotonic() < deadline:
        time.sleep(5.0)
        status = probe()
    if status != "ACTIVE":
        raise AssertionError(f"stream did not reach ACTIVE within {timeout_s}s: {status}")
    return status


def _collect_s3_markers(s3, bucket) -> set[str]:
    markers: set[str] = set()
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
            text = body.decode("utf-8", errors="replace")
            markers.update(line for line in text.split("\n") if line)
    return markers


def _poll_until(probe, predicate, timeout_s: float = 120.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value) and time.monotonic() < deadline:
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
