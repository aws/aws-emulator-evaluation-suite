"""tag-value-empty-string-preserved."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "tag-value-empty-string-preserved"
GROUP = "representation"
SERVICES = ["firehose"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagDeliveryStream with an explicit empty-string tag value round-trips as "" via ListTags."""
    setup = _create_firehose_role_and_bucket(ctx)
    fh = ctx.client("firehose")
    stream_name = ctx.unique_name("sim2real-fh-tag-")
    s3_config = {
        "RoleARN": setup["role_arn"],
        "BucketARN": f"arn:aws:s3:::{setup['bucket']}",
    }
    _create_delivery_stream_with_retry(ctx, fh, stream_name, s3_config)
    ctx.on_cleanup(lambda: fh.delete_delivery_stream(DeliveryStreamName=stream_name))
    _wait_active(ctx, fh, stream_name)

    fh.tag_delivery_stream(
        DeliveryStreamName=stream_name,
        Tags=[{"Key": "Environment", "Value": ""}, {"Key": "NonEmpty", "Value": "prod"}],
    )

    tags = fh.list_tags_for_delivery_stream(DeliveryStreamName=stream_name)["Tags"]
    by_key = {t["Key"]: t for t in tags}
    assert "Environment" in by_key, "empty-value tag key vanished from ListTagsForDeliveryStream"
    assert "Value" in by_key["Environment"], (
        f"tag entry for Environment lost its Value field entirely: {by_key['Environment']!r}"
    )
    assert by_key["Environment"]["Value"] == "", (
        "empty-string tag value was coerced instead of preserved: "
        f"{by_key['Environment']['Value']!r}"
    )
    assert by_key["NonEmpty"]["Value"] == "prod", (
        f"sibling non-empty tag failed to round-trip: {by_key['NonEmpty']['Value']!r}"
    )


def _role_trust_policy() -> str:
    return json.dumps(
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


def _create_firehose_role_and_bucket(ctx) -> dict:
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-fh-").lower().replace("_", "-")
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))

    role_name = ctx.unique_name("sim2real-fh-role-")
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_role_trust_policy()
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

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
    policy_name = ctx.unique_name("sim2real-fh-policy-")
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy_doc
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )
    return {"bucket": bucket, "role_arn": role["Arn"]}


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            failed = s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_delivery_stream_with_retry(
    ctx, fh, name: str, s3_config: dict, delivery_stream_type: str = "DirectPut"
) -> None:
    from botocore.exceptions import ClientError

    kwargs = {
        "DeliveryStreamName": name,
        "DeliveryStreamType": delivery_stream_type,
        "ExtendedS3DestinationConfiguration": s3_config,
    }
    deadline = time.monotonic() + 90
    last_err = None
    while time.monotonic() < deadline:
        try:
            fh.create_delivery_stream(**kwargs)
            return
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] == "InvalidArgumentException":
                time.sleep(5)
                continue
            raise
    raise last_err


def _wait_active(ctx, fh, name: str, timeout_s: int = 180) -> dict:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = fh.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        if status.endswith("FAILED"):
            raise AssertionError(f"stream entered failed state: {status}")
        time.sleep(5)
    raise AssertionError(f"stream {name} did not become ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
