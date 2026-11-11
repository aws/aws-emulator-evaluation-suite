"""put-record-batch-binary-blob-round-trip."""
from __future__ import annotations

import json
import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-record-batch-binary-blob-round-trip"
GROUP = "representation"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "concern:representation", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Raw binary blobs sent with PutRecordBatch (FailedPutCount 0) are delivered to S3 byte for byte: the delivered
    bytes split into exactly the blobs sent, in any order."""
    bucket = _create_bucket(ctx)
    role_arn = _create_role_for_firehose(ctx, bucket)
    stream_name = _create_s3_delivery_stream(ctx, bucket, role_arn)

    blob_len = 256
    blobs = [os.urandom(blob_len) for _ in range(5)]

    firehose = ctx.client("firehose")
    resp = firehose.put_record_batch(
        DeliveryStreamName=stream_name, Records=[{"Data": b} for b in blobs]
    )
    assert resp["FailedPutCount"] == 0, f"unexpected per-record failures: {resp}"

    delivered = _wait_for_total_bytes(ctx, bucket, "", expected_total=len(blobs) * blob_len)

    # An S3 destination concatenates records without a delimiter, in no guaranteed order. Every blob has the
    # same length, so slicing into blob_len chunks recovers the exact set of original blobs.
    assert len(delivered) == len(blobs) * blob_len, (
        f"expected {len(blobs) * blob_len} delivered bytes, got {len(delivered)}"
    )
    chunks = [delivered[i * blob_len : (i + 1) * blob_len] for i in range(len(blobs))]
    assert sorted(chunks) == sorted(blobs), "delivered binary content does not match the exact set of sent blobs"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-fh-bin-")
    kwargs = {"Bucket": bucket}
    # us-east-1 rejects an explicit LocationConstraint matching the endpoint's own region.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "behavioral"}]}
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
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
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
                Tags=[{"Key": "sim2real", "Value": "behavioral"}],
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


def _wait_for_total_bytes(ctx, bucket: str, prefix: str, expected_total: int, timeout_s: float = 300.0) -> bytes:
    """Poll until objects under prefix sum to expected_total bytes, then return their
    concatenation in key-sorted (~delivery-time-ordered) order."""
    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
        keys = sorted(o["Key"] for o in resp.get("Contents", []))
        if keys:
            total = sum(o["Size"] for o in resp.get("Contents", []))
            if total >= expected_total:
                blob = b"".join(s3.get_object(Bucket=bucket, Key=k)["Body"].read() for k in keys)
                return blob
        time.sleep(5)
    raise AssertionError(f"did not observe {expected_total} delivered bytes under s3://{bucket}/{prefix} within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
