"""update-destination-buffering-hints-numeric-precision-preserved."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-destination-buffering-hints-numeric-precision-preserved"
GROUP = "representation"
SERVICES = ["firehose"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Explicit non-default BufferingHints SizeInMBs and IntervalInSeconds values survive
    an UpdateDestination call and a subsequent DescribeDeliveryStream unchanged, and the
    stream's VersionId is incremented by exactly the update."""
    bucket = _create_bucket(ctx)
    role_arn = _create_role_for_firehose(ctx, bucket)
    # start from the minimum defaults so the update below is an unambiguous change
    stream_name = _create_s3_delivery_stream(
        ctx, bucket, role_arn, buffering_hints={"SizeInMBs": 1, "IntervalInSeconds": 60}
    )

    firehose = ctx.client("firehose")
    desc = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"]
    version_before = desc["VersionId"]
    destination_id = desc["Destinations"][0]["DestinationId"]

    new_size_mb = 7
    new_interval_s = 123
    firehose.update_destination(
        DeliveryStreamName=stream_name,
        CurrentDeliveryStreamVersionId=version_before,
        DestinationId=destination_id,
        ExtendedS3DestinationUpdate={
            "RoleARN": role_arn,
            "BucketARN": f"arn:aws:s3:::{bucket}",
            "BufferingHints": {"SizeInMBs": new_size_mb, "IntervalInSeconds": new_interval_s},
        },
    )

    desc_after = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"]
    version_after = desc_after["VersionId"]
    dest_after = desc_after["Destinations"][0]

    assert int(version_after) == int(version_before) + 1, (
        f"VersionId expected to increment by exactly 1: was {version_before}, now {version_after}"
    )
    hints = dest_after["ExtendedS3DestinationDescription"]["BufferingHints"]
    assert hints["SizeInMBs"] == new_size_mb, f"SizeInMBs precision lost: got {hints['SizeInMBs']} expected {new_size_mb}"
    assert isinstance(hints["SizeInMBs"], int), f"SizeInMBs coerced to {type(hints['SizeInMBs']).__name__}: {hints['SizeInMBs']!r}"
    assert hints["IntervalInSeconds"] == new_interval_s, (
        f"IntervalInSeconds precision lost: got {hints['IntervalInSeconds']} expected {new_interval_s}"
    )
    assert isinstance(hints["IntervalInSeconds"], int), (
        f"IntervalInSeconds coerced to {type(hints['IntervalInSeconds']).__name__}: {hints['IntervalInSeconds']!r}"
    )


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-fh-upd-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_role_for_firehose(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-fh-role-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "firehose.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
    )
    role_arn = role["Role"]["Arn"]
    policy_doc = json.dumps(
        {
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
                }
            ],
        }
    )
    iam.put_role_policy(RoleName=role_name, PolicyName="s3-access", PolicyDocument=policy_doc)

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_s3_delivery_stream(ctx, bucket: str, role_arn: str, prefix: str = "", buffering_hints=None) -> str:
    firehose = ctx.client("firehose")
    name = ctx.unique_name("sim2real-fh-")
    hints = buffering_hints or {"SizeInMBs": 1, "IntervalInSeconds": 60}
    dest = {
        "RoleARN": role_arn,
        "BucketARN": f"arn:aws:s3:::{bucket}",
        "Prefix": prefix,
        "BufferingHints": hints,
        "CompressionFormat": "UNCOMPRESSED",
    }
    deadline = time.monotonic() + 90
    last_err = None
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=dest,
                Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
            )
            break
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] in ("InvalidArgumentException", "AccessDeniedException"):
                time.sleep(5)
                continue
            raise
    else:
        raise AssertionError(f"could not create delivery stream after IAM propagation wait: {last_err}")

    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True))
    _wait_for_stream_active(ctx, name)
    return name


def _wait_for_stream_active(ctx, name: str, timeout_s: float = 180.0) -> dict:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        if status == "CREATING_FAILED":
            raise AssertionError(f"delivery stream {name} entered CREATING_FAILED")
        time.sleep(3)
    raise AssertionError(f"delivery stream {name} did not become ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
