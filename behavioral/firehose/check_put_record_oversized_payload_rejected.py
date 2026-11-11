"""put-record-oversized-payload-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-record-oversized-payload-rejected"
GROUP = "data-plane"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutRecord rejects a Data payload over the 1000 KiB limit and delivers nothing for it,
    while a normal-sized record on the same stream still succeeds."""
    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, bucket)
    stream_name = _create_s3_delivery_stream(ctx, bucket, role_arn)
    _wait_stream_active(ctx, stream_name)

    firehose = ctx.client("firehose")
    oversized = b"x" * 1_100_000  # > 1000 KiB (1,024,000 bytes) limit

    code, message = _error_code(lambda: firehose.put_record(
        DeliveryStreamName=stream_name, Record={"Data": oversized}
    ))
    # Empirically AWS rejects an oversized record's Data at the request-validation layer
    # (ValidationException), not the semantic InvalidArgumentException.
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = (
        "1 validation error detected: Value at 'record.data' failed to satisfy constraint: "
        "Member must have length less than or equal to 1024000"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control ordered after the rejection: the stream still delivers a normal record.
    control_data = b"control-record-after-rejection"
    firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": control_data})
    key, body = _wait_for_s3_object(ctx, bucket)
    assert body == control_data, f"positive control record delivered incorrectly: {key!r}"

    # Effect absent, by contrast: once the later control has landed, the bucket holds only the
    # control's bytes, so nothing of the rejected record was delivered.
    s3 = ctx.client("s3")
    keys = [o["Key"] for o in s3.list_objects_v2(Bucket=bucket).get("Contents", [])]
    delivered = b"".join(s3.get_object(Bucket=bucket, Key=k)["Body"].read() for k in sorted(keys))
    assert delivered == control_data, (
        f"the bucket holds {len(delivered)} byte(s) across {keys!r}, expected only the control "
        f"record {control_data!r}; the rejected oversized record was nonetheless delivered"
    )


def _capped(ctx, budget_s: float) -> float:
    """The wait bound, capped by the run's remaining time so a wait fails with its own message."""
    left = ctx.time_left()
    return budget_s if left is None else min(budget_s, left)


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-")
    # us-east-1 is the one region where S3's CreateBucket rejects an explicit
    # LocationConstraint; this is the real API contract, not a region assumption.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
        "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 0},
        "CompressionFormat": "UNCOMPRESSED",
    }
    if prefix is not None:
        dest_config["Prefix"] = prefix
    if error_output_prefix is not None:
        dest_config["ErrorOutputPrefix"] = error_output_prefix

    deadline = time.monotonic() + _capped(ctx, 90.0)
    while True:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=dest_config,
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidArgumentException" and time.monotonic() < deadline:
                time.sleep(2)
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
    deadline = time.monotonic() + _capped(ctx, timeout_s)
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return
        if status in ("CREATING_FAILED",):
            raise AssertionError(f"delivery stream entered {status}")
        time.sleep(2)
    raise AssertionError(f"delivery stream {name} never became ACTIVE within {timeout_s}s")


def _wait_for_s3_object(
    ctx, bucket: str, timeout_s: float = 300.0, interval_s: float = 2.0, key_prefix: str | None = None
) -> tuple[str, bytes]:
    s3 = ctx.client("s3")
    deadline = time.monotonic() + _capped(ctx, timeout_s)
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
