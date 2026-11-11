"""s3-prefix-timestamp-tokens-preserved."""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-prefix-timestamp-tokens-preserved"
GROUP = "data-plane"
SERVICES = ["firehose"]

_PREFIX_TEMPLATE = (
    "sim2real-fh-prefix-test/year=!{timestamp:yyyy}/month=!{timestamp:MM}/"
    "day=!{timestamp:dd}/hour=!{timestamp:HH}/"
)
_ERROR_OUTPUT_PREFIX_TEMPLATE = (
    "sim2real-fh-prefix-test-errors/!{firehose:error-output-type}/"
    "year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/hour=!{timestamp:HH}/"
)
_KEY_RE = re.compile(
    r"^sim2real-fh-prefix-test/year=(\d{4})/month=(\d{2})/day=(\d{2})/hour=(\d{2})/"
)


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """An S3 Prefix with !{timestamp:...} expressions expands into real date/time digits."""
    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, bucket)
    stream_name = _create_s3_delivery_stream(
        ctx,
        bucket,
        role_arn,
        prefix=_PREFIX_TEMPLATE,
        error_output_prefix=_ERROR_OUTPUT_PREFIX_TEMPLATE,
    )
    _wait_stream_active(ctx, stream_name)

    firehose = ctx.client("firehose")
    before = datetime.now(timezone.utc)
    firehose.put_record(
        DeliveryStreamName=stream_name, Record={"Data": b"prefix-token-expansion-test"}
    )

    key, _body = _wait_for_s3_object(ctx, bucket)
    after = datetime.now(timezone.utc)

    assert "!{" not in key, f"prefix tokens were not expanded, literal token leaked into key: {key!r}"
    match = _KEY_RE.match(key)
    assert match is not None, f"delivered key {key!r} did not match the expanded prefix format"
    year, month, day, hour = (int(g) for g in match.groups())
    delivered_ts = datetime(year, month, day, hour, tzinfo=timezone.utc)
    # The timestamp namespace evaluates against the approximate arrival time of the oldest
    # record in the object; allow a generous window around our put() to absorb buffering
    # delay and hour-boundary rounding without weakening what we assert (real digits, not
    # a stale/garbage value).
    assert before - timedelta(hours=1) <= delivered_ts <= after + timedelta(hours=1), (
        f"expanded prefix timestamp {delivered_ts} is not near the put_record window "
        f"[{before}, {after}]"
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
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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

    deadline = time.monotonic() + 90
    while True:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=dest_config,
                Tags=[{"Key": "sim2real", "Value": CHECK}],
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


def _wait_for_s3_object(
    ctx, bucket: str, timeout_s: float = 300.0, interval_s: float = 10.0, key_prefix: str | None = None
) -> tuple[str, bytes]:
    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        kwargs: dict[str, Any] = {"Bucket": bucket}
        if key_prefix:
            kwargs["Prefix"] = key_prefix
        resp = s3.list_objects_v2(**kwargs)
        contents = resp.get("Contents", [])
        if contents:
            key = contents[0]["Key"]
            body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
            return key, body
        time.sleep(interval_s)
    raise AssertionError(f"no object delivered to s3://{bucket}/{key_prefix or ''} within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
