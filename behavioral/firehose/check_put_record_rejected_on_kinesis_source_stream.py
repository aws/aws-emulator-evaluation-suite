"""put-record-rejected-on-kinesis-source-stream."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-record-rejected-on-kinesis-source-stream"
GROUP = "server-side"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """PutRecord and PutRecordBatch on a KinesisStreamAsSource stream fail with the exact
    InvalidArgumentException; records written to the source Kinesis stream reach S3 instead,
    and none of the rejected payloads do.
    """
    firehose = ctx.client("firehose")
    kinesis = ctx.client("kinesis")

    kinesis_name = ctx.unique_name("sim2real-fh-badsrc-kin-")
    kinesis.create_stream(StreamName=kinesis_name, ShardCount=1)
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=kinesis_name, EnforceConsumerDeletion=True))
    kinesis_arn = _wait_kinesis_active(ctx, kinesis_name)
    kinesis.add_tags_to_stream(StreamName=kinesis_name, Tags={"sim2real-check": CHECK})

    bucket, bucket_arn = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, bucket_arn, kinesis_arn)

    stream_name = ctx.unique_name("sim2real-fh-badsrc-")
    _create_delivery_stream_with_retry(
        firehose,
        DeliveryStreamName=stream_name,
        DeliveryStreamType="KinesisStreamAsSource",
        KinesisStreamSourceConfiguration={"KinesisStreamARN": kinesis_arn, "RoleARN": role_arn},
        S3DestinationConfiguration={
            "RoleARN": role_arn,
            "BucketARN": bucket_arn,
            # Minimum buffering (interval floor is 60s) so delivery lands within the poll budget.
            "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
        },
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stream_and_wait(ctx, stream_name))
    _wait_stream_active(ctx, stream_name)

    reject_marker_single = ctx.unique_name("reject-single-").encode()
    reject_marker_batch_a = ctx.unique_name("reject-batch-a-").encode()
    reject_marker_batch_b = ctx.unique_name("reject-batch-b-").encode()

    err_single, msg_single = _error_code(lambda: firehose.put_record(
        DeliveryStreamName=stream_name, Record={"Data": reject_marker_single}
    ))
    assert err_single == "InvalidArgumentException", f"PutRecord: expected InvalidArgumentException, got {err_single!r}"
    assert msg_single == "This operation is not permitted on KinesisStreamAsSource delivery stream type.", (
        f"PutRecord: unexpected refusal message {msg_single!r}"
    )

    err_batch, msg_batch = _error_code(lambda: firehose.put_record_batch(
        DeliveryStreamName=stream_name,
        Records=[{"Data": reject_marker_batch_a}, {"Data": reject_marker_batch_b}],
    ))
    assert err_batch == "InvalidArgumentException", f"PutRecordBatch: expected InvalidArgumentException, got {err_batch!r}"
    assert msg_batch == "This operation is not permitted on KinesisStreamAsSource delivery stream type.", (
        f"PutRecordBatch: unexpected refusal message {msg_batch!r}"
    )

    # Positive control: the supported path, writing to the source Kinesis stream.
    accept_marker = ctx.unique_name("kin-ok-").encode()
    put_resp = kinesis.put_record(StreamName=kinesis_name, Data=accept_marker, PartitionKey="k")
    assert "SequenceNumber" in put_resp, f"kinesis put_record: expected SequenceNumber, got {put_resp!r}"

    delivered = _poll_s3_for_marker(ctx, bucket, accept_marker)
    assert reject_marker_single not in delivered, "PutRecord's rejected payload was delivered to S3 anyway"
    assert reject_marker_batch_a not in delivered, "PutRecordBatch's rejected payload was delivered to S3 anyway"
    assert reject_marker_batch_b not in delivered, "PutRecordBatch's rejected payload was delivered to S3 anyway"



def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-fh-badsrc-")
    if ctx.region == "us-east-1":
        # us-east-1 is the one region S3 rejects an explicit LocationConstraint for.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    return bucket, f"arn:aws:s3:::{bucket}"


def _poll_s3_for_marker(ctx, bucket, marker: bytes, timeout_s=180, interval_s=10):
    """Wait for `marker` in some delivered object; return all objects' bytes from that poll."""
    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        contents = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        blobs = [s3.get_object(Bucket=bucket, Key=o["Key"])["Body"].read() for o in contents]
        combined = b"".join(blobs)
        if marker in combined:
            return combined
        time.sleep(interval_s)
    raise AssertionError(f"marker {marker!r} not delivered to s3://{bucket} within {timeout_s}s")


def _empty_and_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _wait_kinesis_active(ctx, name, timeout_s=120):
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream(StreamName=name)["StreamDescription"]
        if desc["StreamStatus"] == "ACTIVE":
            return desc["StreamARN"]
        time.sleep(3)
    raise AssertionError(f"kinesis stream {name} not ACTIVE after {timeout_s}s")


def _create_firehose_role(ctx, bucket_arn, kinesis_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-fh-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

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
                "Resource": [bucket_arn, f"{bucket_arn}/*"],
            },
            {
                "Effect": "Allow",
                "Action": [
                    "kinesis:DescribeStream",
                    "kinesis:DescribeStreamSummary",
                    "kinesis:GetShardIterator",
                    "kinesis:GetRecords",
                    "kinesis:ListShards",
                ],
                "Resource": kinesis_arn,
            },
        ],
    }
    policy_name = "fh-source-and-dest-access"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_delivery_stream_with_retry(firehose, timeout_s=60, **kwargs):
    """Retry CreateDeliveryStream while a brand-new IAM role is still propagating."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return firehose.create_delivery_stream(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            msg = (exc.response.get("Error", {}).get("Message") or "").lower()
            propagating = code == "InvalidArgumentException" and (
                "assume" in msg or "not authorized" in msg or "does not exist" in msg
            )
            if propagating and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _wait_stream_active(ctx, name, timeout_s=180):
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        last_status = desc["DeliveryStreamStatus"]
        if last_status == "ACTIVE":
            return desc
        if last_status == "CREATING_FAILED":
            raise AssertionError(f"delivery stream {name} entered CREATING_FAILED")
        time.sleep(3)
    raise AssertionError(f"delivery stream {name} not ACTIVE after {timeout_s}s (last={last_status})")


def _delete_stream_and_wait(ctx, name, timeout_s=90):
    firehose = ctx.client("firehose")
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            firehose.describe_delivery_stream(DeliveryStreamName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
