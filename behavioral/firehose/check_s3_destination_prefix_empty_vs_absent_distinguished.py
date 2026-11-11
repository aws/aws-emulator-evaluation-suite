"""s3-destination-prefix-empty-vs-absent-distinguished."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "s3-destination-prefix-empty-vs-absent-distinguished"
GROUP = "representation"
SERVICES = ["firehose"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An explicitly empty S3 Prefix vs an omitted Prefix must be distinguishable in Describe."""
    setup = _create_firehose_role_and_bucket(ctx)
    fh = ctx.client("firehose")

    stream_explicit = ctx.unique_name("sim2real-fh-pfx-explicit-")
    stream_absent = ctx.unique_name("sim2real-fh-pfx-absent-")

    s3_config_explicit = {
        "RoleARN": setup["role_arn"],
        "BucketARN": f"arn:aws:s3:::{setup['bucket']}",
        "Prefix": "",
    }
    s3_config_absent = {
        "RoleARN": setup["role_arn"],
        "BucketARN": f"arn:aws:s3:::{setup['bucket']}",
    }

    _create_delivery_stream_with_retry(ctx, fh, stream_explicit, s3_config_explicit)
    ctx.on_cleanup(lambda: fh.delete_delivery_stream(DeliveryStreamName=stream_explicit))
    _create_delivery_stream_with_retry(ctx, fh, stream_absent, s3_config_absent)
    ctx.on_cleanup(lambda: fh.delete_delivery_stream(DeliveryStreamName=stream_absent))

    desc_explicit = _wait_active(ctx, fh, stream_explicit)
    desc_absent = _wait_active(ctx, fh, stream_absent)

    dest_explicit = desc_explicit["Destinations"][0]["ExtendedS3DestinationDescription"]
    dest_absent = desc_absent["Destinations"][0]["ExtendedS3DestinationDescription"]

    assert "Prefix" in dest_explicit, "explicitly empty Prefix vanished from DescribeDeliveryStream"
    assert dest_explicit["Prefix"] == "", (
        f"explicitly empty Prefix was not preserved verbatim: {dest_explicit['Prefix']!r}"
    )
    assert "Prefix" not in dest_absent, (
        "an omitted Prefix was normalized to an explicit value instead of staying absent: "
        f"{dest_absent.get('Prefix')!r}"
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
    # us-east-1 is the one region CreateBucket rejects a LocationConstraint for.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]}
    )

    role_name = ctx.unique_name("sim2real-fh-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_role_trust_policy(),
        Tags=[{"Key": "sim2real", "Value": "true"}],
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
        "Tags": [{"Key": "sim2real", "Value": "true"}],
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
