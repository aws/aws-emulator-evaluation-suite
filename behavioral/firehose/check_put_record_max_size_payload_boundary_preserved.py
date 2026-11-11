"""put-record-max-size-payload-boundary-preserved."""
from __future__ import annotations

import json
import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-record-max-size-payload-boundary-preserved"
GROUP = "representation"
SERVICES = ["firehose"]

# Per API_Record.html: Data max length is exactly 1,024,000 bytes (1,000 KiB).
_MAX_RECORD_BYTES = 1024000


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A record at exactly the maximum allowed size (1,000 KiB / 1,024,000 bytes) is
    accepted and delivered to S3 with no truncation, padding, or corruption."""
    bucket = _create_bucket(ctx)
    role_arn = _create_role_for_firehose(ctx, bucket)
    stream_name = _create_s3_delivery_stream(ctx, bucket, role_arn)

    payload = os.urandom(_MAX_RECORD_BYTES)
    assert len(payload) == _MAX_RECORD_BYTES, f"test setup generated {len(payload)} bytes, want {_MAX_RECORD_BYTES}"

    firehose = ctx.client("firehose")
    put_resp = firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": payload})
    assert "RecordId" in put_resp, f"PutRecord at the max-size boundary must return a RecordId, got {put_resp!r}"

    key = _wait_for_object(ctx, bucket, "", timeout_s=_budget_s(ctx, 300.0))
    s3 = ctx.client("s3")
    head = s3.head_object(Bucket=bucket, Key=key)
    assert head["ContentLength"] == _MAX_RECORD_BYTES, (
        f"delivered object size {head['ContentLength']} != original max payload size {_MAX_RECORD_BYTES}"
    )

    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert len(body) == _MAX_RECORD_BYTES, f"delivered body is {len(body)} bytes, want {_MAX_RECORD_BYTES}"
    assert body == payload, "max-size payload was corrupted, truncated, or padded during delivery"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-fh-max-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})

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
        Tags=[{"Key": "sim2real", "Value": "true"}],
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
    hints = buffering_hints or {"SizeInMBs": 1, "IntervalInSeconds": 0}
    dest = {
        "RoleARN": role_arn,
        "BucketARN": f"arn:aws:s3:::{bucket}",
        "Prefix": prefix,
        "BufferingHints": hints,
        "CompressionFormat": "UNCOMPRESSED",
    }
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
    last_err = None
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=dest,
                Tags=[{"Key": "sim2real", "Value": "true"}],
            )
            break
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] in ("InvalidArgumentException", "AccessDeniedException"):
                time.sleep(2)
                continue
            raise
    else:
        if _budget_spent(ctx):
            raise TimeoutError(f"delivery stream {name} creation past IAM propagation: the run budget ended first; not graded")
        raise AssertionError(f"could not create delivery stream after IAM propagation wait: {last_err}")

    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True))
    _wait_for_stream_active(ctx, name, timeout_s=_budget_s(ctx, 180.0))
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
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"delivery stream {name} becoming ACTIVE: the run budget ended first; not graded")
    raise AssertionError(f"delivery stream {name} did not become ACTIVE within {timeout_s}s")


def _wait_for_object(ctx, bucket: str, prefix: str, timeout_s: float = 300.0) -> str:
    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
        contents = resp.get("Contents", [])
        if contents:
            return contents[0]["Key"]
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"an object delivered to s3://{bucket}/{prefix}: the run budget ended first; not graded")
    raise AssertionError(f"no object delivered to s3://{bucket}/{prefix} within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
