"""e2e-put-record-kinesis-source-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-put-record-kinesis-source-rejected"
GROUP = "e2e"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """PutRecord on a Kinesis-sourced stream fails with InvalidArgumentException and delivers
    nothing. A sibling DirectPut stream accepts PutRecord and the record is read back from S3.

    Reference: https://docs.aws.amazon.com/firehose/latest/dev/writing-with-kinesis-streams.html"""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    kinesis = ctx.client("kinesis")
    firehose = ctx.client("firehose")

    bucket = ctx.unique_name("sim2real-fh-ksrc-").lower()
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, s3, bucket))

    kinesis_stream = ctx.unique_name("sim2real-fh-ksrc-")
    kinesis.create_stream(StreamName=kinesis_stream, ShardCount=1)
    ctx.on_cleanup(lambda: _delete_kinesis_stream(ctx, kinesis, kinesis_stream))
    kinesis_arn = _wait_kinesis_active(ctx, kinesis, kinesis_stream)

    role_arn = _create_firehose_role(ctx, iam, bucket, kinesis_arn)

    # --- the stream under test: source is Kinesis, direct PutRecord must be rejected ---
    source_stream = ctx.unique_name("sim2real-fh-ksrc-fh-")
    _create_stream_with_retry(
        ctx,
        firehose,
        DeliveryStreamName=source_stream,
        DeliveryStreamType="KinesisStreamAsSource",
        KinesisStreamSourceConfiguration={"KinesisStreamARN": kinesis_arn, "RoleARN": role_arn},
        ExtendedS3DestinationConfiguration={
            "BucketARN": f"arn:aws:s3:::{bucket}",
            "RoleARN": role_arn,
            "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},
        },
        Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
    )
    ctx.on_cleanup(lambda: _delete_stream_if_present(ctx, firehose, source_stream))
    _wait_stream_active(ctx, firehose, source_stream)

    before = s3.list_objects_v2(Bucket=bucket).get("KeyCount", 0)

    code, msg = _error_code(
        lambda: firehose.put_record(
            DeliveryStreamName=source_stream, Record={"Data": b"should-not-land\n"}
        )
    )
    # PutRecord is disabled for a Kinesis source; the code is InvalidArgumentException
    # (InvalidSourceException is documented for CloudWatch Logs decompression only).
    assert code == "InvalidArgumentException", f"expected InvalidArgumentException, got {code}"
    expected_msg = "This operation is not permitted on KinesisStreamAsSource delivery stream type."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # The call raised synchronously, so nothing was accepted and no wait is needed.
    after = s3.list_objects_v2(Bucket=bucket).get("KeyCount", 0)
    assert after == before, "rejected PutRecord unexpectedly produced an S3 object"

    # --- positive control: a plain DirectPut stream in the same file accepts PutRecord ---
    direct_stream = ctx.unique_name("sim2real-fh-ksrc-direct-")
    _create_stream_with_retry(
        ctx,
        firehose,
        DeliveryStreamName=direct_stream,
        DeliveryStreamType="DirectPut",
        ExtendedS3DestinationConfiguration={
            "BucketARN": f"arn:aws:s3:::{bucket}",
            "RoleARN": role_arn,
            "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},
        },
        Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
    )
    ctx.on_cleanup(lambda: _delete_stream_if_present(ctx, firehose, direct_stream))
    _wait_stream_active(ctx, firehose, direct_stream)

    marker = str(uuid.uuid4())
    resp = firehose.put_record(
        DeliveryStreamName=direct_stream, Record={"Data": (marker + "\n").encode("utf-8")}
    )
    assert "RecordId" in resp, f"expected RecordId in put_record response, got {resp!r}"

    # Wait through the buffering interval for the marker to land in S3.
    keys = _poll_until(
        lambda: [o["Key"] for o in s3.list_objects_v2(Bucket=bucket).get("Contents", [])],
        lambda ks: len(ks) > 0,
        timeout_s=360,
        interval_s=15,
        description=f"record object in destination bucket {bucket}",
    )
    body = s3.get_object(Bucket=bucket, Key=keys[0])["Body"].read()
    assert marker.encode("utf-8") in body, (
        f"delivered object {keys[0]!r} does not contain the record marker"
    )


def _error_code(fn):
    """Call fn(), which must fail; return (Error.Code, Error.Message); a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_bucket(ctx, s3, name: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )


def _empty_and_delete_bucket(ctx, s3, bucket: str) -> None:
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _delete_kinesis_stream(ctx, kinesis, name: str) -> None:
    try:
        kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_kinesis_active(ctx, kinesis, name: str, timeout_s: float = 180.0) -> str:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream(StreamName=name)["StreamDescription"]
        if desc["StreamStatus"] == "ACTIVE":
            return desc["StreamARN"]
        time.sleep(5)
    raise AssertionError(f"kinesis stream {name} did not become ACTIVE within {timeout_s}s")


def _create_firehose_role(ctx, iam, bucket: str, kinesis_arn: str) -> str:
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
    ctx.on_cleanup(lambda: _delete_role(ctx, iam, role_name))
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
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            },
            {
                "Effect": "Allow",
                "Action": [
                    "kinesis:DescribeStream",
                    "kinesis:GetShardIterator",
                    "kinesis:GetRecords",
                    "kinesis:ListShards",
                ],
                "Resource": kinesis_arn,
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="fh-access", PolicyDocument=json.dumps(policy))
    return role_arn


def _delete_role(ctx, iam, role_name: str) -> None:
    try:
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_stream_with_retry(ctx, firehose, timeout_s: float = 90.0, **kwargs) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            firehose.create_delivery_stream(**kwargs)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidArgumentException" and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _wait_stream_active(ctx, firehose, name: str, timeout_s: float = 300.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return
        if status.endswith("FAILED"):
            raise AssertionError(f"stream {name} entered {status}: {desc.get('FailureDescription')}")
        time.sleep(5)
    raise AssertionError(f"stream {name} did not become ACTIVE within {timeout_s}s")


def _delete_stream_if_present(ctx, firehose, name: str) -> None:
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
