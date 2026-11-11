"""put-record-unicode-payload-byte-equal-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-record-unicode-payload-byte-equal-round-trip"
GROUP = "representation"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "concern:representation", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A record containing multi-byte unicode data written via PutRecord lands in S3
    byte-for-byte identical to the original input (no re-encoding, normalization, or
    truncation along the way)."""
    bucket = _create_bucket(ctx)
    role_arn = _create_role_for_firehose(ctx, bucket)
    stream_name = _create_s3_delivery_stream(ctx, bucket, role_arn)

    payload = "Hello 世界 🌍 — Ñoño déjà vu 中文测试 Ω≈ç√∫ 한글".encode("utf-8")

    firehose = ctx.client("firehose")
    firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": payload})

    key = _wait_for_object(ctx, bucket, "")
    s3 = ctx.client("s3")
    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()

    assert body == payload, (
        f"delivered bytes differ from original unicode payload: "
        f"got {body!r} expected {payload!r}"
    )
    # a single PutRecord must land as exactly one object, never split or duplicated
    # across separate buffer flushes
    objects = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
    assert len(objects) == 1, (
        f"expected exactly one delivered object for a single put_record, "
        f"got {len(objects)}: {[o['Key'] for o in objects]}"
    )


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-fh-uni-")
    kwargs = {"Bucket": bucket}
    # us-east-1 is CreateBucket's implicit default region and rejects an explicit
    # LocationConstraint for itself
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]},
    )

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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )
            break
        except ClientError as e:
            last_err = e
            # IAM role propagation into Firehose's control plane can lag briefly.
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


def _wait_for_object(ctx, bucket: str, prefix: str, timeout_s: float = 300.0) -> str:
    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
        contents = resp.get("Contents", [])
        if contents:
            return contents[0]["Key"]
        time.sleep(5)
    raise AssertionError(f"no object delivered to s3://{bucket}/{prefix} within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
