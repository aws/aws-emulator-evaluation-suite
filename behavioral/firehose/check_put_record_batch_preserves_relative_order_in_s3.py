"""put-record-batch-preserves-relative-order-in-s3."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-record-batch-preserves-relative-order-in-s3"
GROUP = "ordering"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Records submitted within a single PutRecordBatch call are delivered to S3 in
    the same relative order they were submitted."""
    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, f"arn:aws:s3:::{bucket}")
    stream_name = ctx.unique_name("sim2real-behav-fh-")
    _create_delivery_stream_s3(
        ctx, stream_name, role_arn, f"arn:aws:s3:::{bucket}",
        {"IntervalInSeconds": 60, "SizeInMBs": 128},
    )
    ctx.on_cleanup(lambda: _delete_stream(ctx, stream_name))
    _wait_stream_active(ctx, stream_name)

    fh = ctx.client("firehose")
    n = 25
    records = [{"Data": f"seq-{i:04d}\n".encode()} for i in range(n)]
    resp = fh.put_record_batch(DeliveryStreamName=stream_name, Records=records)
    assert resp["FailedPutCount"] == 0
    assert len(resp["RequestResponses"]) == n

    objects = _poll_until(
        lambda: _list_objects(ctx, bucket),
        lambda objs: len(objs) > 0,
        timeout_s=180.0,
        interval_s=10.0,
    )
    assert objects, "no object delivered to S3 within timeout"

    s3 = ctx.client("s3")
    lines: list[str] = []
    for obj in sorted(objects, key=lambda o: (o["LastModified"], o["Key"])):
        body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read().decode()
        lines.extend([line for line in body.split("\n") if line])

    expected = [f"seq-{i:04d}" for i in range(n)]
    assert lines == expected, f"relative order not preserved: got {lines}, expected {expected}"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-fh-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "purpose", "Value": "behavioral-check"}]})
    return bucket


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket,
                    Delete={"Objects": [{"Key": o["Key"]} for o in objs]},
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_firehose_role(ctx, bucket_arn: str) -> str:
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:GetObject",
                "s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:PutObject",
            ],
            "Resource": [bucket_arn, f"{bucket_arn}/*"],
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(policy_doc))
    return role["Arn"]


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_delivery_stream_s3(ctx, name: str, role_arn: str, bucket_arn: str, buffering_hints: dict) -> None:
    fh = ctx.client("firehose")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            fh.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration={
                    "RoleARN": role_arn,
                    "BucketARN": bucket_arn,
                    "BufferingHints": buffering_hints,
                },
                Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
            )
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidArgumentException" and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise


def _delete_stream(ctx, name: str) -> None:
    fh = ctx.client("firehose")
    try:
        fh.delete_delivery_stream(DeliveryStreamName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_stream_active(ctx, name: str, timeout: float = 180.0) -> dict:
    fh = ctx.client("firehose")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        desc = fh.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        if status == "CREATING_FAILED":
            raise AssertionError(f"delivery stream entered CREATING_FAILED: {desc.get('FailureDescription')}")
        time.sleep(3.0)
    raise AssertionError("delivery stream did not become ACTIVE in time")


def _list_objects(ctx, bucket: str) -> list:
    s3 = ctx.client("s3")
    return s3.list_objects_v2(Bucket=bucket).get("Contents", [])


def _poll_until(probe, predicate, timeout_s: float = 120.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    return result if predicate(result) else None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
