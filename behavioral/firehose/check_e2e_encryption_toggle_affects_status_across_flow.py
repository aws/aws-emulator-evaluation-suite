"""e2e-encryption-toggle-affects-status-across-flow."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-encryption-toggle-affects-status-across-flow"
GROUP = "e2e"
SERVICES = ["firehose"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Enabling and disabling server-side encryption changes DescribeDeliveryStream's
    encryption status around live record ingestion, ending in teardown."""
    firehose = ctx.client("firehose")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = _create_bucket(ctx, s3)
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))

    role_name, role_arn = _create_firehose_role(ctx, iam, bucket)
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))

    stream_name = ctx.unique_name("sim2real-behav-fh-ds-")
    _create_delivery_stream_with_role_retry(
        firehose,
        DeliveryStreamName=stream_name,
        DeliveryStreamType="DirectPut",
        ExtendedS3DestinationConfiguration={
            "BucketARN": f"arn:aws:s3:::{bucket}",
            "RoleARN": role_arn,
            "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},
        },
        Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
    )
    ctx.on_cleanup(lambda: _delete_stream_if_exists(firehose, stream_name))
    initial = _wait_stream_active(firehose, stream_name)

    initial_status = initial.get("DeliveryStreamEncryptionConfiguration", {}).get("Status", "DISABLED")
    assert initial_status == "DISABLED", (
        f"expected a freshly created delivery stream to report encryption status DISABLED, got {initial_status!r}"
    )

    unencrypted_put = firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": b"before-encryption\n"})
    assert unencrypted_put.get("Encrypted") is False, (
        f"expected PutRecord.Encrypted False before encryption is enabled, got {unencrypted_put.get('Encrypted')!r}"
    )

    firehose.start_delivery_stream_encryption(
        DeliveryStreamName=stream_name,
        DeliveryStreamEncryptionConfigurationInput={"KeyType": "AWS_OWNED_CMK"},
    )
    enabled_desc = _poll_encryption_status(firehose, stream_name, "ENABLED", timeout_s=120)
    enabled_status = enabled_desc["DeliveryStreamEncryptionConfiguration"]["Status"]
    assert enabled_status == "ENABLED", f"expected encryption status ENABLED after start, got {enabled_status!r}"

    put_resp = firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": b"encrypted-payload\n"})
    assert put_resp.get("Encrypted") is True, (
        f"expected PutRecord.Encrypted True while encryption is ENABLED, got {put_resp.get('Encrypted')!r}"
    )

    firehose.stop_delivery_stream_encryption(DeliveryStreamName=stream_name)
    disabled_desc = _poll_encryption_status(firehose, stream_name, "DISABLED", timeout_s=120)
    disabled_status = disabled_desc["DeliveryStreamEncryptionConfiguration"]["Status"]
    assert disabled_status == "DISABLED", f"expected encryption status DISABLED after stop, got {disabled_status!r}"

    reverted_put = firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": b"after-disable\n"})
    assert reverted_put.get("Encrypted") is False, (
        f"expected PutRecord.Encrypted False again after encryption is stopped, got {reverted_put.get('Encrypted')!r}"
    )

    firehose.delete_delivery_stream(DeliveryStreamName=stream_name, AllowForceDelete=True)
    _wait_stream_deleted(firehose, stream_name)


def _create_bucket(ctx, s3) -> str:
    name = ctx.unique_name("sim2real-behav-fh-bkt-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "purpose", "Value": "behavioral-check"}]})
    return name


def _empty_bucket(s3, bucket: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")


def _delete_bucket(s3, bucket: str) -> None:
    try:
        _empty_bucket(s3, bucket)
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_firehose_role(ctx, iam, bucket: str) -> tuple[str, str]:
    role_name = ctx.unique_name("sim2real-behav-fh-role-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
    )
    role_arn = role["Role"]["Arn"]
    policy = {
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
    iam.put_role_policy(RoleName=role_name, PolicyName="firehose-s3-access", PolicyDocument=json.dumps(policy))
    return role_name, role_arn


def _delete_role(iam, role_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="firehose-s3-access")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_delivery_stream_with_role_retry(firehose, timeout_s: float = 90, **kwargs) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return firehose.create_delivery_stream(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "").lower()
            if code == "InvalidArgumentException" and "role" in msg and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _delete_stream_if_exists(firehose, name: str) -> None:
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_stream_active(firehose, name: str, timeout_s: float = 180, interval_s: float = 5) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        if status.endswith("_FAILED"):
            raise AssertionError(f"delivery stream {name} entered {status}")
        time.sleep(interval_s)
    raise AssertionError(f"delivery stream {name} did not become ACTIVE within {timeout_s}s")


def _wait_stream_deleted(firehose, name: str, timeout_s: float = 180, interval_s: float = 5) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            firehose.describe_delivery_stream(DeliveryStreamName=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"delivery stream {name} still present after {timeout_s}s")


def _poll_encryption_status(firehose, name: str, expected: str, timeout_s: float = 120, interval_s: float = 5) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        enc = desc.get("DeliveryStreamEncryptionConfiguration", {})
        last = enc.get("Status")
        if last == expected:
            return desc
        if last is not None and last.endswith("_FAILED"):
            raise AssertionError(f"encryption transition failed with status {last}: {enc.get('FailureDescription')}")
        time.sleep(interval_s)
    raise AssertionError(f"encryption status never reached {expected!r}, last seen {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
