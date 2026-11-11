"""put-record-binary-blob-round-trip."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-record-binary-blob-round-trip"
GROUP = "data-plane"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "concern:representation", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A PutRecord payload of raw non-UTF8 binary bytes is delivered to S3 byte-for-byte."""
    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, bucket)
    stream_name = _create_s3_delivery_stream(ctx, bucket, role_arn)
    _wait_stream_active(ctx, stream_name)

    firehose = ctx.client("firehose")
    # Non-UTF8 binary payload: invalid continuation bytes, NUL bytes, full byte range.
    data = bytes(range(256)) + b"\xc3\x28\x00\xff\xfe\x80\x81\x00\x00"
    resp = firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": data})
    assert resp.get("RecordId"), f"PutRecord must be accepted with a RecordId, got {resp!r}"

    keys, body = _wait_for_s3_object(ctx, bucket)
    assert len(keys) == 1, f"expected exactly 1 delivered object, got {len(keys)}: {keys!r}"
    assert body == data, f"delivered object {keys[0]!r} did not match binary payload byte-for-byte"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "purpose", "Value": "behavioral-check"}]}
    )
    return name


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    s3.delete_bucket(Bucket=bucket)


def _create_firehose_role(ctx, bucket_name: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-fh-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "firehose.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:AbortMultipartUpload",
                    "s3:GetBucketLocation",
                    "s3:GetObject",
                    "s3:ListBucket",
                    "s3:ListBucketMultipartUploads",
                    "s3:PutObject",
                ],
                "Resource": [
                    f"arn:aws:s3:::{bucket_name}",
                    f"arn:aws:s3:::{bucket_name}/*",
                ],
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="firehose-s3-access", PolicyDocument=json.dumps(policy)
    )
    return role_arn


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="firehose-s3-access")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_s3_delivery_stream(
    ctx,
    bucket_name: str,
    role_arn: str,
    *,
    prefix: str | None = None,
    error_output_prefix: str | None = None,
) -> str:
    firehose = ctx.client("firehose")
    name = ctx.unique_name("sim2real-fh-stream-")
    dest_config: dict[str, Any] = {
        "RoleARN": role_arn,
        "BucketARN": f"arn:aws:s3:::{bucket_name}",
        "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
        "CompressionFormat": "UNCOMPRESSED",
    }
    if prefix is not None:
        dest_config["Prefix"] = prefix
    if error_output_prefix is not None:
        dest_config["ErrorOutputPrefix"] = error_output_prefix

    # IAM role propagation into Firehose's control plane can lag a few seconds;
    # retry create while the role isn't yet assumable.
    deadline = time.monotonic() + 90
    while True:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=dest_config,
                Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
            )
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            exc.response["Error"].get("Message", "")
            if code == "InvalidArgumentException" and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
    ctx.on_cleanup(lambda: _delete_delivery_stream(ctx, name))
    return name


def _delete_delivery_stream(ctx, name: str) -> None:
    firehose = ctx.client("firehose")
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_stream_active(ctx, name: str, timeout_s: float = 180.0) -> None:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return
        if status in ("CREATING_FAILED",):
            raise AssertionError(f"delivery stream entered {status}")
        time.sleep(5)
    raise AssertionError(f"delivery stream {name} never became ACTIVE within {timeout_s}s")


def _wait_for_s3_object(
    ctx, bucket: str, timeout_s: float = 300.0, interval_s: float = 10.0, key_prefix: str | None = None
) -> tuple[list[str], bytes]:
    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        kwargs: dict[str, Any] = {"Bucket": bucket}
        if key_prefix:
            kwargs["Prefix"] = key_prefix
        resp = s3.list_objects_v2(**kwargs)
        contents = resp.get("Contents", [])
        if contents:
            keys = [obj["Key"] for obj in contents]
            body = s3.get_object(Bucket=bucket, Key=keys[0])["Body"].read()
            return keys, body
        time.sleep(interval_s)
    raise AssertionError(f"no object delivered to s3://{bucket}/{key_prefix or ''} within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
