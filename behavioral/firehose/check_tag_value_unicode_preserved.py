"""tag-value-unicode-preserved."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-value-unicode-preserved"
GROUP = "data-plane"
SERVICES = ["firehose"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag value containing unicode characters is returned byte-identical by ListTagsForDeliveryStream."""
    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, bucket)
    stream_name = _create_s3_delivery_stream(ctx, bucket, role_arn)
    _wait_stream_active(ctx, stream_name)

    firehose = ctx.client("firehose")
    tag_key = ctx.unique_name("sim2real-fh-tag-")
    # Firehose's server-side tag validation only allows Unicode letters, whitespace, and
    # '_ . : / = + - @' (empirically narrower than the shape-level regex, which also
    # accepts digits/%/'). Use only Unicode letters and allowed punctuation so this
    # exercises genuine multi-byte round-tripping without tripping either validation layer.
    tag_value = "café-日本語-Ñoño-value"
    firehose.tag_delivery_stream(DeliveryStreamName=stream_name, Tags=[{"Key": tag_key, "Value": tag_value}])

    resp = firehose.list_tags_for_delivery_stream(DeliveryStreamName=stream_name)
    tags_by_key = {t["Key"]: t["Value"] for t in resp["Tags"]}
    assert tag_key in tags_by_key, f"tag {tag_key!r} not found in {tags_by_key!r}"
    assert tags_by_key[tag_key] == tag_value, (
        f"tag value mangled: expected {tag_value!r}, got {tags_by_key[tag_key]!r}"
    )


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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
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

    deadline = time.monotonic() + 90
    while True:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=dest_config,
            )
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
