"""tag-value-unicode-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-value-unicode-round-trip"
GROUP = "representation"
SERVICES = ["firehose"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag value containing unicode characters set via TagDeliveryStream round-trips byte-identical."""
    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, bucket)
    stream_name = _create_s3_delivery_stream(ctx, role_arn, bucket, prefix="tags-test/")

    tag_key = "unicode-tag"
    # Firehose tag values allow Unicode letters, digits, whitespace, and _ . / = + - @
    # (no emoji / symbol characters, no em-dash) per the tagging restrictions doc.
    tag_value = "日本語のタグ värde café münchen 3"

    firehose = ctx.client("firehose")
    firehose.tag_delivery_stream(
        DeliveryStreamName=stream_name, Tags=[{"Key": tag_key, "Value": tag_value}]
    )

    tags = firehose.list_tags_for_delivery_stream(DeliveryStreamName=stream_name)["Tags"]
    matches = [t for t in tags if t["Key"] == tag_key]
    assert len(matches) == 1, f"expected exactly one tag keyed {tag_key!r}, found {matches!r} in {tags!r}"
    assert matches[0]["Value"] == tag_value, (
        f"tag value mangled: expected {tag_value!r}, got {matches[0]['Value']!r}"
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
