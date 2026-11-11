"""buffering-hint-interval-delays-delivery."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "buffering-hint-interval-delays-delivery"
GROUP = "visibility-timeout-ttl"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/APIReference/API_BufferingHints.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A record is not visible in S3 before the configured BufferingHints
    IntervalInSeconds elapses, and becomes visible shortly after -- validating
    buffering as a delivery-delay mechanism."""
    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, f"arn:aws:s3:::{bucket}")
    stream_name = ctx.unique_name("sim2real-behav-fh-")
    # BufferingHints.IntervalInSeconds is valid in [0, 900]
    # (https://docs.aws.amazon.com/firehose/latest/APIReference/API_BufferingHints.html);
    # SizeInMBs is pinned to its max so only the interval timer can trigger delivery.
    _create_delivery_stream_s3(
        ctx, stream_name, role_arn, f"arn:aws:s3:::{bucket}",
        {"IntervalInSeconds": 60, "SizeInMBs": 128},
    )
    ctx.on_cleanup(lambda: _delete_stream(ctx, stream_name))
    _wait_stream_active(ctx, stream_name)

    fh = ctx.client("firehose")
    payload = b"single-record\n"
    start = time.monotonic()
    fh.put_record(DeliveryStreamName=stream_name, Record={"Data": payload})

    # poll repeatedly for absence well inside the 60s buffer window
    early_deadline = start + 40.0
    while time.monotonic() < early_deadline:
        objs = _list_objects(ctx, bucket)
        assert not objs, f"record delivered before buffer interval elapsed: {objs}"
        time.sleep(5.0)

    objects = _poll_until(
        lambda: _list_objects(ctx, bucket),
        lambda objs: len(objs) > 0,
        timeout_s=180.0,
        interval_s=10.0,
    )
    elapsed = time.monotonic() - start
    assert objects, f"record never delivered to S3 after {elapsed:.0f}s"
    content = _concat_objects(ctx, bucket, objects)
    assert content == payload, f"delivered content mismatch: expected {payload!r}, got {content!r}"


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
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]})
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
                Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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


def _concat_objects(ctx, bucket: str, objects: list) -> bytes:
    s3 = ctx.client("s3")
    data = b""
    for obj in sorted(objects, key=lambda o: o["Key"]):
        data += s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
    return data


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
