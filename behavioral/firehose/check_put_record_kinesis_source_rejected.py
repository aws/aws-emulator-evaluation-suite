"""put-record-kinesis-source-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-record-kinesis-source-rejected"
GROUP = "e2e"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """PutRecord on a KinesisStreamAsSource delivery stream is rejected with
    InvalidArgumentException (only DirectPut streams accept direct puts) and ingests nothing, while
    a sibling DirectPut stream accepts PutRecord and the record arrives in S3."""
    bucket_name, bucket_arn = _create_bucket(ctx)
    kinesis_stream_arn = _create_kinesis_stream(ctx)
    role_arn = _create_firehose_role(ctx, bucket_arn, kinesis_stream_arn)

    # negative subject: KinesisStreamAsSource delivery stream
    kinesis_source_stream = ctx.unique_name("sim2real-behav-fh-ksrc-")
    _create_stream_with_retry(
        ctx,
        DeliveryStreamName=kinesis_source_stream,
        DeliveryStreamType="KinesisStreamAsSource",
        KinesisStreamSourceConfiguration={"KinesisStreamARN": kinesis_stream_arn, "RoleARN": role_arn},
        S3DestinationConfiguration={
            "BucketARN": bucket_arn,
            "RoleARN": role_arn,
            "Prefix": "kinesis-source/",
            "CompressionFormat": "UNCOMPRESSED",
        },
        Tags=[{"Key": "simparity-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_stream(ctx, kinesis_source_stream))
    _wait_stream_active(ctx, kinesis_source_stream)

    firehose = ctx.client("firehose")
    code, message = _error_code(
        lambda: firehose.put_record(
            DeliveryStreamName=kinesis_source_stream, Record={"Data": b"direct-put-should-fail"}
        )
    )
    assert code == "InvalidArgumentException", (
        f"expected InvalidArgumentException for a direct PutRecord against a "
        f"KinesisStreamAsSource stream, got {code!r}"
    )
    assert message == "This operation is not permitted on KinesisStreamAsSource delivery stream type.", (
        f"unexpected refusal message {message!r}"
    )

    # effect absent: the rejected call never ingested anything (nothing under the prefix)
    s3 = ctx.client("s3")
    objects = s3.list_objects_v2(Bucket=bucket_name, Prefix="kinesis-source/").get("Contents", [])
    assert objects == [], f"expected no objects delivered under kinesis-source/, found {objects!r}"

    # positive control: an ordinary DirectPut stream accepts PutRecord in the same file.
    # BufferingHints pinned to the minimum so the terminal read below does not wait out the
    # (much longer) account default.
    direct_put_stream = ctx.unique_name("sim2real-behav-fh-direct-")
    _create_stream_with_retry(
        ctx,
        DeliveryStreamName=direct_put_stream,
        DeliveryStreamType="DirectPut",
        S3DestinationConfiguration={
            "BucketARN": bucket_arn,
            "RoleARN": role_arn,
            "Prefix": "direct-put/",
            "CompressionFormat": "UNCOMPRESSED",
            "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},
        },
        Tags=[{"Key": "simparity-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_stream(ctx, direct_put_stream))
    _wait_stream_active(ctx, direct_put_stream)
    resp = firehose.put_record(DeliveryStreamName=direct_put_stream, Record={"Data": b"direct-put-should-work"})
    assert isinstance(resp.get("RecordId"), str) and len(resp["RecordId"]) > 0, (
        f"expected a non-empty RecordId string in the PutRecord response, got {resp.get('RecordId')!r}"
    )

    # The accepted record must actually arrive in S3, not merely be acknowledged by PutRecord.
    delivered = _wait_for_object_under_prefix(ctx, bucket_name, "direct-put/", timeout_s=180.0)
    assert delivered, (
        f"DirectPut record was accepted (RecordId={resp['RecordId']!r}) but never delivered "
        f"under s3://{bucket_name}/direct-put/ within 180s"
    )


def _error_code(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-behav-fh-").lower()
    kwargs = {"Bucket": bucket_name}
    # S3 quirk, not a region pin: CreateBucket rejects an explicit LocationConstraint for the
    # region that is itself the API default.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]}
    )
    return bucket_name, f"arn:aws:s3:::{bucket_name}"


def _empty_and_delete_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket_name):
        objs = page.get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket_name)


def _wait_for_object_under_prefix(ctx, bucket_name: str, prefix: str, timeout_s: float = 180.0) -> bool:
    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout_s
    while True:
        objects = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix).get("Contents", [])
        if objects:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(2)


def _create_kinesis_stream(ctx) -> str:
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-behav-fh-kds-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1)
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True))
    deadline = time.monotonic() + 180.0
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]
        if desc["StreamStatus"] == "ACTIVE":
            kinesis.add_tags_to_stream(StreamName=stream_name, Tags={"simparity-check": CHECK})
            return desc["StreamARN"]
        time.sleep(5)
    raise AssertionError(f"kinesis stream {stream_name} did not become ACTIVE in time")


def _create_firehose_role(ctx, bucket_arn: str, kinesis_stream_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-fh-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "simparity-check", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {
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
                "Resource": [bucket_arn, f"{bucket_arn}/*"],
            },
            {
                "Effect": "Allow",
                "Action": [
                    "kinesis:DescribeStream",
                    "kinesis:GetShardIterator",
                    "kinesis:GetRecords",
                    "kinesis:ListShards",
                ],
                "Resource": kinesis_stream_arn,
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="FirehoseAccess", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="FirehoseAccess"))
    return role["Arn"]


def _create_stream_with_retry(ctx, **kwargs) -> None:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            firehose.create_delivery_stream(**kwargs)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidArgumentException" and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _safe_delete_stream(ctx, stream_name: str) -> None:
    firehose = ctx.client("firehose")
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=stream_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_stream_active(ctx, stream_name: str, timeout_s: float = 300.0) -> dict:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        if status == "CREATING_FAILED":
            raise AssertionError(f"stream {stream_name} entered CREATING_FAILED")
        time.sleep(5)
    raise AssertionError(f"stream {stream_name} did not become ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
