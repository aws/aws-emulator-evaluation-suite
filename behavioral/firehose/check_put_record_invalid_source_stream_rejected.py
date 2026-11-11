"""put-record-invalid-source-stream-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-record-invalid-source-stream-rejected"
GROUP = "negative-classes"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """PutRecord on a KinesisStreamAsSource stream fails with InvalidArgumentException and the exact
    message; a DirectPut control delivers to S3 and the rejected payload never appears there.

    Reference: https://docs.aws.amazon.com/firehose/latest/dev/writing-with-kinesis-streams.html
    """
    firehose = ctx.client("firehose")
    kinesis = ctx.client("kinesis")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx)
    kinesis_stream_name = ctx.unique_name("sim2real-fh-src-")
    kinesis.create_stream(
        StreamName=kinesis_stream_name, ShardCount=1, Tags={"purpose": "behavioral-check"}
    )
    ctx.on_cleanup(
        lambda: kinesis.delete_stream(StreamName=kinesis_stream_name, EnforceConsumerDeletion=True)
    )
    kinesis_arn = _wait_kinesis_active(ctx, kinesis, kinesis_stream_name)

    role_arn = _create_firehose_kinesis_s3_role(ctx, bucket, kinesis_arn)

    fh_name = ctx.unique_name("sim2real-fh-kdssrc-")
    ctx.on_cleanup(lambda: _best_effort_delete(firehose, fh_name))
    _create_active_kinesis_source_stream(ctx, firehose, fh_name, kinesis_arn, role_arn, bucket)

    rejected_payload = b"direct-put-attempt"
    code, message = _error_code(
        lambda: firehose.put_record(DeliveryStreamName=fh_name, Record={"Data": rejected_payload})
    )
    assert code == "InvalidArgumentException", f"CODE={code!r}"
    assert message == "This operation is not permitted on KinesisStreamAsSource delivery stream type.", (
        f"unexpected refusal message {message!r}"
    )

    # Positive control: a DirectPut stream with the same role and bucket accepts PutRecord.
    dp_name = ctx.unique_name("sim2real-fh-dpctrl-")
    ctx.on_cleanup(lambda: _best_effort_delete(firehose, dp_name))
    accepted_payload = b"direct-put-ok"
    _create_active_stream(
        ctx, firehose, dp_name, role_arn, bucket, buffering={"IntervalInSeconds": 60, "SizeInMBs": 1}
    )
    resp = firehose.put_record(DeliveryStreamName=dp_name, Record={"Data": accepted_payload})
    assert resp.get("RecordId")

    delivered = _wait_for_marker_in_bucket(s3, bucket, accepted_payload, timeout_s=240.0)
    assert delivered, f"accepted PutRecord payload never landed in s3://{bucket}"
    assert not _marker_in_bucket(s3, bucket, rejected_payload), (
        f"rejected PutRecord's payload leaked into s3://{bucket} despite the synchronous "
        "InvalidArgumentException"
    )


def _error_code(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-bkt-").lower()
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "purpose", "Value": "behavioral-check"}]}
    )

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _wait_kinesis_active(ctx, kinesis, name, timeout_s=120.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream(StreamName=name)["StreamDescription"]
        if desc["StreamStatus"] == "ACTIVE":
            return desc["StreamARN"]
        time.sleep(3)
    raise AssertionError(f"kinesis stream {name} never became ACTIVE")


def _create_firehose_kinesis_s3_role(ctx, bucket_name, kinesis_stream_arn):
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
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-fh-policy-")
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
                "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
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
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _wait_for_stream_status(ctx, firehose, name, target_statuses, timeout_s=180.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        last = desc["DeliveryStreamStatus"]
        if last in target_statuses:
            return desc
        time.sleep(3)
    raise AssertionError(f"stream {name} never reached {target_statuses}, last status={last}")


def _create_active_stream(ctx, firehose, name, role_arn, bucket_name, buffering=None):
    s3_config = {"RoleARN": role_arn, "BucketARN": f"arn:aws:s3:::{bucket_name}"}
    if buffering:
        s3_config["BufferingHints"] = buffering
    deadline = time.monotonic() + 90.0
    while True:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                S3DestinationConfiguration=s3_config,
                Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidArgumentException" and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
    return _wait_for_stream_status(ctx, firehose, name, {"ACTIVE"})


def _create_active_kinesis_source_stream(ctx, firehose, name, kinesis_arn, role_arn, bucket_name):
    deadline = time.monotonic() + 90.0
    while True:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="KinesisStreamAsSource",
                KinesisStreamSourceConfiguration={
                    "KinesisStreamARN": kinesis_arn,
                    "RoleARN": role_arn,
                },
                S3DestinationConfiguration={
                    "RoleARN": role_arn,
                    "BucketARN": f"arn:aws:s3:::{bucket_name}",
                },
                Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidArgumentException" and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
    return _wait_for_stream_status(ctx, firehose, name, {"ACTIVE"})


def _best_effort_delete(firehose, name):
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _marker_in_bucket(s3, bucket, marker):
    resp = s3.list_objects_v2(Bucket=bucket)
    for obj in resp.get("Contents", []):
        body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
        if marker in body:
            return True
    return False


def _wait_for_marker_in_bucket(s3, bucket, marker, timeout_s):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _marker_in_bucket(s3, bucket, marker):
            return True
        time.sleep(5)
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
