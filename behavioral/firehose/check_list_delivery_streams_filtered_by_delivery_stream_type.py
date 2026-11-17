"""list-delivery-streams-filtered-by-delivery-stream-type."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-delivery-streams-filtered-by-delivery-stream-type"
GROUP = "filtering"
SERVICES = ["firehose"]

_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "firehose.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def _access_policy(bucket: str, kinesis_stream_arn: str) -> dict:
    return {
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
                "Resource": kinesis_stream_arn,
            },
        ],
    }


_NAME_ALPHABET = "-." + "0123456789" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "_" + "abcdefghijklmnopqrstuvwxyz"


def _predecessor(name: str) -> str:
    """A string, valid as a DeliveryStreamName cursor, strictly less than ``name``.

    ListDeliveryStreams starts a page strictly after ExclusiveStartDeliveryStreamName, so
    anchoring here makes the very next entry the smallest name >= ``name``. Decrementing the
    last character by raw codepoint can fall outside the name's own alphabet (``'0' - 1``
    is ``'/'``), so the decrement walks ``_NAME_ALPHABET`` instead, borrowing from an earlier
    character (and dropping everything after it) when a character is already that
    alphabet's minimum.
    """
    chars = list(name)
    i = len(chars) - 1
    while i >= 0:
        idx = _NAME_ALPHABET.index(chars[i])
        if idx > 0:
            chars[i] = _NAME_ALPHABET[idx - 1]
            return "".join(chars[: i + 1])
        i -= 1
    return name[:-1] if len(name) > 1 else name


def _quiet_not_found(fn, *codes: str) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in codes:
            raise


def _wait_active(firehose, name: str, timeout_s: float = 150.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return
        time.sleep(3)
    raise AssertionError(f"{name} did not reach ACTIVE within {timeout_s}s")


def _create_with_role_propagation_retry(create_fn, timeout_s: float = 90.0) -> None:
    """Retry ``create_fn()`` while Firehose cannot yet assume the just-created role."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            create_fn()
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidArgumentException" and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDeliveryStreams with a DeliveryStreamType argument returns only the streams of
    that type, in each direction, leaving a stream of the other type out of the page.
    """
    firehose = ctx.client("firehose")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    kinesis = ctx.client("kinesis")

    bucket = ctx.unique_name("sim2real-behav-fh-filt-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _purge_bucket(s3, bucket))

    source_stream_name = ctx.unique_name("sim2real-behav-fh-filt-kds-")
    kinesis.create_stream(StreamName=source_stream_name, ShardCount=1)
    ctx.on_cleanup(
        lambda: _quiet_not_found(
            lambda: kinesis.delete_stream(StreamName=source_stream_name, EnforceConsumerDeletion=True),
            "ResourceNotFoundException",
        )
    )
    source_stream_arn = _wait_kinesis_active(kinesis, source_stream_name)

    role_name = ctx.unique_name("sim2real-behav-fh-filt-role-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(_TRUST_POLICY)
    )["Role"]["Arn"]
    policy_name = f"{role_name}-access"
    ctx.on_cleanup(lambda: _quiet_not_found(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    ctx.on_cleanup(
        lambda: _quiet_not_found(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name), "NoSuchEntity"
        )
    )
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(_access_policy(bucket, source_stream_arn)),
    )

    direct_name = ctx.unique_name("sim2real-behav-fh-filt-direct-")
    ctx.on_cleanup(
        lambda: _quiet_not_found(
            lambda: firehose.delete_delivery_stream(DeliveryStreamName=direct_name, AllowForceDelete=True),
            "ResourceNotFoundException",
        )
    )
    _create_with_role_propagation_retry(
        lambda: firehose.create_delivery_stream(
            DeliveryStreamName=direct_name,
            DeliveryStreamType="DirectPut",
            S3DestinationConfiguration={"RoleARN": role_arn, "BucketARN": f"arn:aws:s3:::{bucket}"},
        )
    )

    source_name = ctx.unique_name("sim2real-behav-fh-filt-source-")
    ctx.on_cleanup(
        lambda: _quiet_not_found(
            lambda: firehose.delete_delivery_stream(DeliveryStreamName=source_name, AllowForceDelete=True),
            "ResourceNotFoundException",
        )
    )
    _create_with_role_propagation_retry(
        lambda: firehose.create_delivery_stream(
            DeliveryStreamName=source_name,
            DeliveryStreamType="KinesisStreamAsSource",
            KinesisStreamSourceConfiguration={"KinesisStreamARN": source_stream_arn, "RoleARN": role_arn},
            S3DestinationConfiguration={"RoleARN": role_arn, "BucketARN": f"arn:aws:s3:::{bucket}"},
        )
    )

    _wait_active(firehose, direct_name)
    _wait_active(firehose, source_name)

    # Anchoring the cursor one character below each name makes the next matching entry,
    # if there is one, the smallest name >= that name: a sentinel for "is it in this filter".
    direct_in_direct = firehose.list_delivery_streams(
        DeliveryStreamType="DirectPut", ExclusiveStartDeliveryStreamName=_predecessor(direct_name), Limit=1
    )["DeliveryStreamNames"]
    assert direct_in_direct == [direct_name], (
        f"expected only {direct_name!r} filtered to DirectPut, got {direct_in_direct!r}"
    )

    source_in_source = firehose.list_delivery_streams(
        DeliveryStreamType="KinesisStreamAsSource",
        ExclusiveStartDeliveryStreamName=_predecessor(source_name),
        Limit=1,
    )["DeliveryStreamNames"]
    assert source_in_source == [source_name], (
        f"expected only {source_name!r} filtered to KinesisStreamAsSource, got {source_in_source!r}"
    )

    source_in_direct = firehose.list_delivery_streams(
        DeliveryStreamType="DirectPut", ExclusiveStartDeliveryStreamName=_predecessor(source_name), Limit=1
    )["DeliveryStreamNames"]
    assert source_name not in source_in_direct, (
        f"the KinesisStreamAsSource stream {source_name!r} must not appear filtered to DirectPut, "
        f"got {source_in_direct!r}"
    )

    direct_in_source = firehose.list_delivery_streams(
        DeliveryStreamType="KinesisStreamAsSource",
        ExclusiveStartDeliveryStreamName=_predecessor(direct_name),
        Limit=1,
    )["DeliveryStreamNames"]
    assert direct_name not in direct_in_source, (
        f"the DirectPut stream {direct_name!r} must not appear filtered to KinesisStreamAsSource, "
        f"got {direct_in_source!r}"
    )


def _wait_kinesis_active(kinesis, name: str, timeout_s: float = 120.0) -> str:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream(StreamName=name)["StreamDescription"]
        if desc["StreamStatus"] == "ACTIVE":
            return desc["StreamARN"]
        time.sleep(3)
    raise AssertionError(f"kinesis stream {name} did not reach ACTIVE within {timeout_s}s")


def _purge_bucket(s3, bucket: str) -> None:
    try:
        objects = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objects:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objects]})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
