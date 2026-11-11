"""firehose-s3-buffering-hints-flush-positive."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firehose-s3-buffering-hints-flush-positive"
GROUP = "delivery"
SERVICES = ["firehose", "kinesis", "s3"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Kinesis records buffered by Firehose flush to S3 once the BufferingHints SizeInMBs
    threshold is crossed, well before the (deliberately much longer) IntervalInSeconds timer
    could account for it."""
    s3 = ctx.client("s3")
    kinesis = ctx.client("kinesis")
    firehose = ctx.client("firehose")

    bucket, bucket_arn = _create_bucket(ctx)
    stream_name, stream_arn = _create_kinesis_stream(ctx)
    role_arn = _create_role(
        ctx,
        [_kinesis_read_statement(stream_arn), _s3_write_statement(bucket_arn)],
        "buf",
    )

    delivery_name = ctx.unique_name("sim2real-fh-")
    # Interval is deliberately long (near the 900s max); if an object shows up well inside our
    # poll window, it can only be explained by the 1 MiB size hint, not the timer.
    _create_delivery_stream_with_retry(
        ctx,
        firehose,
        delivery_name,
        DeliveryStreamType="KinesisStreamAsSource",
        KinesisStreamSourceConfiguration={
            "KinesisStreamARN": stream_arn,
            "RoleARN": role_arn,
        },
        S3DestinationConfiguration={
            "RoleARN": role_arn,
            "BucketARN": bucket_arn,
            "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 900},
        },
    )
    _wait_delivery_stream_active(firehose, delivery_name)

    marker = ctx.unique_name("marker-")
    record = (marker + "-" + ("x" * 60000)).encode()  # ~60 KB per record
    for i in range(20):  # ~1.2 MiB total, over the 1 MiB size hint
        kinesis.put_record(StreamName=stream_name, Data=record, PartitionKey=f"pk-{i}")

    # Time semantic: the 280s poll budget is under a third of the 900s interval, so an
    # object inside it can only be size-triggered; the poll fails the check otherwise.
    objects = _poll_until(
        lambda: _list_objects(s3, bucket),
        lambda o: len(o) >= 1,
        timeout_s=280,
        interval_s=10,
    )

    found = False
    for obj in objects:
        body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
        if marker.encode() in body:
            found = True
            break
    assert found, "flushed S3 object did not contain the buffered record payload"


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
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

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
    kinesis.create_stream(StreamName=name, ShardCount=1)
    ctx.on_cleanup(
        lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    )
    _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=name)[
            "StreamDescriptionSummary"
        ]["StreamStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=120,
        interval_s=3,
    )
    arn = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"][
        "StreamARN"
    ]
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
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "delivery-access"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_delivery_stream_with_retry(ctx, firehose, name: str, **kwargs: Any) -> None:
    deadline = time.monotonic() + 150
    while True:
        try:
            firehose.create_delivery_stream(DeliveryStreamName=name, **kwargs)
            break
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] == "InvalidArgumentException"
                and time.monotonic() < deadline
            ):
                time.sleep(5)
                continue
            raise
    ctx.on_cleanup(
        lambda: firehose.delete_delivery_stream(
            DeliveryStreamName=name, AllowForceDelete=True
        )
    )


def _wait_delivery_stream_active(firehose, name: str, timeout_s: float = 180.0) -> None:
    status = _poll_until(
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamStatus"],
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
