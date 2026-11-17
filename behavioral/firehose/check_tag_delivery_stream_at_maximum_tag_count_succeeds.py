"""tag-delivery-stream-at-maximum-tag-count-succeeds."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-delivery-stream-at-maximum-tag-count-succeeds"
GROUP = "boundary-validation"
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


def _access_policy(bucket: str) -> dict:
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
            }
        ],
    }


def _quiet_not_found(fn, *codes: str) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in codes:
            raise


def _wait_active(firehose, name: str, timeout_s: float = 120.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return
        time.sleep(3)
    raise AssertionError(f"{name} did not reach ACTIVE within {timeout_s}s")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagDeliveryStream brings a stream to the documented maximum of 50 tags (2 tags, then
    48 more), and every one of the 50 tags reads back from ListTagsForDeliveryStream in one page.
    """
    firehose = ctx.client("firehose")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-fh-maxtags-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _purge_bucket(s3, bucket))

    role_name = ctx.unique_name("sim2real-behav-fh-maxtags-role-")
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
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(_access_policy(bucket))
    )

    name = ctx.unique_name("sim2real-behav-fh-maxtags-")
    ctx.on_cleanup(
        lambda: _quiet_not_found(
            lambda: firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True),
            "ResourceNotFoundException",
        )
    )
    deadline = time.monotonic() + 90.0
    while True:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                S3DestinationConfiguration={"RoleARN": role_arn, "BucketARN": f"arn:aws:s3:::{bucket}"},
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidArgumentException" and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
    _wait_active(firehose, name)

    # A two-tag control first, so the 50-tag call is proven to add to an already-tagged
    # stream rather than merely to populate an empty one.
    firehose.tag_delivery_stream(
        DeliveryStreamName=name, Tags=[{"Key": "env", "Value": "boundary"}, {"Key": "owner", "Value": "sim2real"}]
    )

    fifty = [{"Key": f"bulk-{i:02d}", "Value": f"v{i}"} for i in range(48)]
    firehose.tag_delivery_stream(DeliveryStreamName=name, Tags=fifty)

    page = firehose.list_tags_for_delivery_stream(DeliveryStreamName=name, Limit=50)
    assert page["HasMoreTags"] is False, (
        f"50 tags with Limit=50 must fit on one page, got HasMoreTags={page['HasMoreTags']!r}"
    )
    got = {t["Key"]: t["Value"] for t in page["Tags"]}
    expected = {"env": "boundary", "owner": "sim2real"}
    expected.update({t["Key"]: t["Value"] for t in fifty})
    assert len(got) == 50, f"expected exactly 50 tags on the stream, got {len(got)}: {sorted(got)}"
    assert got == expected, f"expected the 50-tag set {sorted(expected)}, got {sorted(got)}"


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
