"""firehose-kinesis-source-missing-role-permission-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firehose-kinesis-source-missing-role-permission-negative"
GROUP = "overly-permissive"
SERVICES = ["firehose", "kinesis", "s3"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:control", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """CreateDeliveryStream refuses a Kinesis-source delivery stream whose IAM role lacks
    Kinesis read permissions with InvalidArgumentException, while a sibling delivery stream
    reading the same stream with a correctly-permissioned role delivers the record to S3."""
    s3 = ctx.client("s3")
    kinesis = ctx.client("kinesis")
    firehose = ctx.client("firehose")

    stream_name, stream_arn = _create_kinesis_stream(ctx)
    bad_bucket, bad_bucket_arn = _create_bucket(ctx)
    good_bucket, good_bucket_arn = _create_bucket(ctx)

    # Role WITHOUT kinesis read permissions (can still write to S3).
    bad_role_arn = _create_role(ctx, [_s3_write_statement(bad_bucket_arn)], "nok")
    # Role WITH full permissions (the positive control).
    good_role_arn = _create_role(
        ctx,
        [_kinesis_read_statement(stream_arn), _s3_write_statement(good_bucket_arn)],
        "full",
    )

    # Firehose validates the source role's kinesis:GetRecords/GetShardIterator/DescribeStream
    # permissions synchronously at CreateDeliveryStream time — so the missing-permission gap
    # surfaces as an immediate InvalidArgumentException, not an async delivery failure. That
    # rejection IS the effect-absent signal: the stream is never created, so it can never
    # deliver a Kinesis record to S3.
    bad_stream = ctx.unique_name("sim2real-fh-bad-")
    denial = _create_delivery_stream_expect_denied(
        ctx,
        firehose,
        bad_stream,
        bad_role_arn,
        DeliveryStreamType="KinesisStreamAsSource",
        KinesisStreamSourceConfiguration={"KinesisStreamARN": stream_arn, "RoleARN": bad_role_arn},
        S3DestinationConfiguration={
            "RoleARN": bad_role_arn,
            "BucketARN": bad_bucket_arn,
            "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
        },
    )
    denial_code = denial.response["Error"]["Code"]
    denial_message = denial.response["Error"].get("Message")
    assert denial_code == "InvalidArgumentException", (
        f"expected CreateDeliveryStream to reject the kinesis-permission-less role with "
        f"InvalidArgumentException, got {denial_code}: {denial_message}"
    )
    want = f"Role {bad_role_arn} is not authorized to perform: kinesis:DescribeStream on resource {stream_arn}."
    assert denial_message == want, f"expected {want!r}, got {denial_message!r}"

    good_stream = ctx.unique_name("sim2real-fh-good-")
    _create_delivery_stream_with_retry(
        ctx,
        firehose,
        good_stream,
        DeliveryStreamType="KinesisStreamAsSource",
        KinesisStreamSourceConfiguration={"KinesisStreamARN": stream_arn, "RoleARN": good_role_arn},
        S3DestinationConfiguration={
            "RoleARN": good_role_arn,
            "BucketARN": good_bucket_arn,
            "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
        },
    )
    _wait_delivery_stream_active(firehose, good_stream)

    marker = ctx.unique_name("marker-")
    kinesis.put_record(StreamName=stream_name, Data=f"payload-{marker}".encode(), PartitionKey="pk-1")

    # (b) positive control: the correctly-permissioned stream delivers the record to S3.
    good_objects = _poll_until(
        lambda: _list_objects(s3, good_bucket), lambda o: len(o) >= 1, timeout_s=240, interval_s=10
    )
    assert len(good_objects) >= 1, (
        f"positive control: correctly-permissioned delivery stream {good_stream} never "
        f"delivered the Kinesis record to s3://{good_bucket}"
    )

    # (a) precondition: no stream exists for the rejected role, so its bucket holds no
    # objects; the rejection asserted above is what shows the missing kinesis read
    # permission is enforced at CreateDeliveryStream time.
    bad_objects = _list_objects(s3, bad_bucket)
    assert bad_objects == [], (
        f"bucket {bad_bucket} for the rejected, kinesis-permission-less delivery stream "
        f"should have received nothing, found {bad_objects!r}"
    )


def _poll_until(probe, predicate, timeout_s: float = 120.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_bucket(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-s3-")
    kwargs: dict[str, Any] = {"Bucket": name}
    # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})

    def _cleanup() -> None:
        token = None
        while True:
            kw: dict[str, Any] = {"Bucket": name}
            if token:
                kw["ContinuationToken"] = token
            resp = s3.list_objects_v2(**kw)
            for obj in resp.get("Contents", []):
                s3.delete_object(Bucket=name, Key=obj["Key"])
            if resp.get("IsTruncated"):
                token = resp.get("NextContinuationToken")
            else:
                break
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name, f"arn:aws:s3:::{name}"


def _create_kinesis_stream(ctx) -> tuple[str, str]:
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-fh-stream-")
    kinesis.create_stream(
        StreamName=name, ShardCount=1, Tags={"sim2real-check": CHECK}
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"][
            "StreamStatus"
        ],
        lambda s: s == "ACTIVE",
        timeout_s=120,
        interval_s=3,
    )
    arn = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamARN"]
    return name, arn


def _kinesis_read_statement(stream_arn: str) -> dict[str, Any]:
    return {
        "Effect": "Allow",
        "Action": [
            "kinesis:DescribeStream",
            "kinesis:DescribeStreamSummary",
            "kinesis:GetRecords",
            "kinesis:GetShardIterator",
            "kinesis:ListShards",
        ],
        "Resource": stream_arn,
    }


def _s3_write_statement(bucket_arn: str) -> dict[str, Any]:
    resource = "*" if bucket_arn == "*" else [bucket_arn, f"{bucket_arn}/*"]
    return {
        "Effect": "Allow",
        "Action": [
            "s3:AbortMultipartUpload",
            "s3:GetBucketLocation",
            "s3:GetObject",
            "s3:ListBucket",
            "s3:ListBucketMultipartUploads",
            "s3:PutObject",
        ],
        "Resource": resource,
    }


def _create_role(ctx, statements: list[dict[str, Any]], suffix: str) -> str:
    iam = ctx.client("iam")
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
    role_name = ctx.unique_name(f"sim2real-fh-role-{suffix}-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "delivery-access"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_delivery_stream_with_retry(ctx, firehose, name: str, **kwargs: Any) -> None:
    deadline = time.monotonic() + 150
    while True:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
                **kwargs,
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidArgumentException" and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True))


def _create_delivery_stream_expect_denied(
    ctx, firehose, name: str, role_arn: str, timeout_s: float = 120.0, **kwargs: Any
) -> ClientError:
    """Attempt CreateDeliveryStream expecting it to be rejected because the source role
    lacks the required Kinesis read permissions. Firehose validates this synchronously, so
    the rejection itself (InvalidArgumentException) is the effect-absent signal — the stream
    is never created and therefore can never deliver a record downstream. If the call
    unexpectedly succeeds, the stream is torn down and the check fails loudly.

    A role created seconds ago is refused with the same code and an "unable to assume role"
    message while IAM propagates; that refusal is retried, because it says nothing about the
    missing Kinesis permission under test."""
    propagating = f"Firehose is unable to assume role {role_arn}. Please check the role provided."
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
                **kwargs,
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidArgumentException":
                if exc.response["Error"].get("Message") == propagating:
                    last_exc = exc
                    time.sleep(5)
                    continue
                return exc
            last_exc = exc
            time.sleep(5)
            continue
        else:
            ctx.on_cleanup(
                lambda: firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
            )
            raise AssertionError(
                f"expected CreateDeliveryStream({name}) to be rejected for missing kinesis read "
                "permissions, but it succeeded"
            )
    if last_exc is not None:
        raise last_exc
    raise AssertionError(f"create_delivery_stream({name}) did not fail as expected within {timeout_s}s")



def _wait_delivery_stream_active(firehose, name: str, timeout_s: float = 180.0) -> None:
    status = _poll_until(
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"][
            "DeliveryStreamStatus"
        ],
        lambda s: s in ("ACTIVE", "CREATING_FAILED"),
        timeout_s=timeout_s,
        interval_s=5,
    )
    if status != "ACTIVE":
        raise AssertionError(f"delivery stream {name} failed to activate: {status}")


def _list_objects(s3, bucket: str, prefix: str = "") -> list[dict[str, Any]]:
    resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
    return resp.get("Contents", [])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
