"""tag-value-empty-string-preserved-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-value-empty-string-preserved-round-trip"
GROUP = "representation"
SERVICES = ["firehose"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag written with an empty-string value is preserved exactly (not coerced to
    null/absent, and not dropped from the tag set) when read back via
    ListTagsForDeliveryStream."""
    bucket = _create_bucket(ctx)
    role_arn = _create_role_for_firehose(ctx, bucket)
    stream_name = _create_s3_delivery_stream(ctx, bucket, role_arn)

    firehose = ctx.client("firehose")
    empty_key = "sim2real-empty-value-tag"
    nonempty_key = "sim2real-nonempty-tag"
    firehose.tag_delivery_stream(
        DeliveryStreamName=stream_name,
        Tags=[
            {"Key": empty_key, "Value": ""},
            {"Key": nonempty_key, "Value": "some-value"},
        ],
    )

    tags = firehose.list_tags_for_delivery_stream(DeliveryStreamName=stream_name)["Tags"]
    by_key = {t["Key"]: t for t in tags}

    assert empty_key in by_key, "empty-string-valued tag was dropped entirely instead of preserved"
    assert "Value" in by_key[empty_key], "tag entry lost its Value field"
    assert by_key[empty_key]["Value"] == "", (
        f"empty-string tag value was coerced to {by_key[empty_key]['Value']!r} instead of preserved as ''"
    )
    # sanity: the sibling non-empty tag round-trips normally too
    assert by_key[nonempty_key]["Value"] == "some-value", (
        f"non-empty sibling tag value mangled: expected 'some-value', got {by_key[nonempty_key]['Value']!r}"
    )


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-fh-tag-")
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)
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
