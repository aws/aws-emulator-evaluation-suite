"""empty-record-data-preserved."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "empty-record-data-preserved"
GROUP = "data-plane"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "concern:representation", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A zero-byte record is accepted with a RecordId and contributes zero bytes to the delivered
    S3 object: batched with a marker record, the object is exactly the marker bytes.
    """
    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, bucket)
    stream_name = _create_s3_delivery_stream(ctx, bucket, role_arn)
    _wait_stream_active(ctx, stream_name)

    firehose = ctx.client("firehose")
    marker = f"MARKER-{uuid.uuid4().hex}-".encode("ascii")

    # A buffer holding only a zero-byte record does not flush promptly, so it rides with a marker.
    resp = firehose.put_record_batch(
        DeliveryStreamName=stream_name,
        Records=[{"Data": b""}, {"Data": marker}],
    )
    assert resp["FailedPutCount"] == 0, f"empty/marker batch had failures: {resp!r}"
    assert len(resp["RequestResponses"]) == 2, (
        f"expected 2 RequestResponses (one per submitted record), got {len(resp['RequestResponses'])}: {resp!r}"
    )
    empty_result, marker_result = resp["RequestResponses"]
    assert "RecordId" in empty_result and "ErrorCode" not in empty_result, (
        f"the zero-byte record was rejected instead of accepted: {empty_result!r}"
    )
    assert "RecordId" in marker_result and "ErrorCode" not in marker_result, (
        f"the marker record was rejected instead of accepted: {marker_result!r}"
    )

    objects = _wait_for_s3_objects(ctx, bucket)
    # The empty record writes no object of its own, and a raw S3 destination inserts no separators
    # between records, so the delivered bytes are exactly the marker.
    empty = [key for key, body in objects if not body]
    assert not empty, f"the zero-byte record was delivered as empty object(s) {empty!r}"
    delivered = b"".join(body for _, body in objects)
    assert delivered == marker, (
        f"delivered objects {[key for key, _ in objects]!r} were not exactly the marker bytes "
        f"(empty record was dropped/padded): expected {marker!r}, got {delivered!r}"
    )

    s3 = ctx.client("s3")
    lengths = [s3.head_object(Bucket=bucket, Key=key)["ContentLength"] for key, _ in objects]
    assert sum(lengths) == len(marker), (
        f"S3 reports ContentLength {lengths}, expected {len(marker)} in total (marker only)"
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

    deadline = time.monotonic() + 60
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
                time.sleep(3)
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
        time.sleep(3)
    raise AssertionError(f"delivery stream {name} never became ACTIVE within {timeout_s}s")


def _wait_for_s3_objects(
    ctx, bucket: str, timeout_s: float = 300.0, interval_s: float = 10.0
) -> list[tuple[str, bytes]]:
    """Every object in *bucket*, with its body, once two listings an interval apart agree."""
    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout_s
    seen: list[str] = []
    while time.monotonic() < deadline:
        keys = [o["Key"] for o in s3.list_objects_v2(Bucket=bucket).get("Contents", [])]
        if keys and keys == seen:
            return [(k, s3.get_object(Bucket=bucket, Key=k)["Body"].read()) for k in keys]
        seen = keys
        time.sleep(interval_s)
    raise AssertionError(f"no object delivered to s3://{bucket}/ within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
