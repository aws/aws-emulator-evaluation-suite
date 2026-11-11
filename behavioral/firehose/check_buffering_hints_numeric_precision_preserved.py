"""buffering-hints-numeric-precision-preserved."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "buffering-hints-numeric-precision-preserved"
GROUP = "representation"
SERVICES = ["firehose"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Non-default BufferingHints integers set at create time come back unchanged (no float coercion/rounding)."""
    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, bucket)

    # Deliberately non-default, non-round values: defaults are SizeInMBs=5 / IntervalInSeconds=300,
    # so picking values distinct from those (and from each other) catches any coercion/rounding.
    size_in_mbs = 3
    interval_in_seconds = 61
    stream_name = _create_s3_delivery_stream(
        ctx,
        role_arn,
        bucket,
        prefix="hints-test/",
        buffering_hints={"SizeInMBs": size_in_mbs, "IntervalInSeconds": interval_in_seconds},
    )

    firehose = ctx.client("firehose")
    desc = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)[
        "DeliveryStreamDescription"
    ]
    hints = desc["Destinations"][0]["ExtendedS3DestinationDescription"]["BufferingHints"]

    assert hints["SizeInMBs"] == size_in_mbs, (
        f"SizeInMBs precision lost: expected {size_in_mbs}, got {hints['SizeInMBs']}"
    )
    assert isinstance(hints["SizeInMBs"], int), (
        f"SizeInMBs coerced to non-int type {type(hints['SizeInMBs'])!r}: {hints['SizeInMBs']!r}"
    )
    assert hints["IntervalInSeconds"] == interval_in_seconds, (
        f"IntervalInSeconds precision lost: expected {interval_in_seconds}, got {hints['IntervalInSeconds']}"
    )
    assert isinstance(hints["IntervalInSeconds"], int), (
        f"IntervalInSeconds coerced to non-int type {type(hints['IntervalInSeconds'])!r}: "
        f"{hints['IntervalInSeconds']!r}"
    )


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-fh-s3-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_firehose_role(ctx, bucket: str) -> str:
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
    policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup() -> None:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_s3_delivery_stream(ctx, role_arn: str, bucket: str, prefix: str, buffering_hints=None) -> str:
    firehose = ctx.client("firehose")
    name = ctx.unique_name("sim2real-fh-stream-")
    hints = buffering_hints or {"SizeInMBs": 1, "IntervalInSeconds": 60}
    config = {
        "RoleARN": role_arn,
        "BucketARN": f"arn:aws:s3:::{bucket}",
        "Prefix": prefix,
        "BufferingHints": hints,
        "CompressionFormat": "UNCOMPRESSED",
    }
    deadline = time.monotonic() + 90.0
    last_err: Exception | None = None
    created = False
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=config,
            )
            created = True
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidArgumentException":
                last_err = e
                time.sleep(5)
                continue
            raise
    if not created:
        raise AssertionError(f"delivery stream never created (role propagation?): {last_err}")
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=name))
    _wait_for_stream_active(ctx, name)
    return name


def _wait_for_stream_active(ctx, name: str, timeout_s: float = 120.0) -> None:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return
        time.sleep(3)
    raise AssertionError(f"delivery stream {name} never became ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
