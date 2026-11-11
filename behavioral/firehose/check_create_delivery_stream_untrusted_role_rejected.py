"""create-delivery-stream-untrusted-role-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-delivery-stream-untrusted-role-rejected"
GROUP = "e2e"
SERVICES = ["firehose"]


def _error(fn):
    """Call fn() and return (Code, Message) of the ClientError it raised; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")



@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDeliveryStream with a role that does not trust firehose.amazonaws.com is rejected with
    InvalidArgumentException and creates no stream; a stream with a correctly-trusted role reaches
    ACTIVE."""
    firehose = ctx.client("firehose")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = _create_bucket(ctx, s3)
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))

    bad_role_name, bad_role_arn = _create_untrusted_role(ctx, iam, bucket)
    ctx.on_cleanup(lambda: _delete_role(iam, bad_role_name, "s3-access"))

    bad_stream_name = ctx.unique_name("sim2real-behav-fh-badtrust-")
    code, message = _error(
        lambda: firehose.create_delivery_stream(
            DeliveryStreamName=bad_stream_name,
            DeliveryStreamType="DirectPut",
            ExtendedS3DestinationConfiguration={
                "BucketARN": f"arn:aws:s3:::{bucket}",
                "RoleARN": bad_role_arn,
                "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},
            },
        )
    )
    assert code == "InvalidArgumentException", f"expected InvalidArgumentException, got {code}"
    expected = f"Firehose is unable to assume role {bad_role_arn}. Please check the role provided."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    ctx.on_cleanup(lambda: _delete_stream_if_exists(firehose, bad_stream_name))

    # Effect absent: the synchronously-rejected request never created a stream at all.
    not_found_code, not_found_message = _error(
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=bad_stream_name)
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"expected no stream to exist after rejected create, got {not_found_code}"
    )
    expected = f"Firehose under account {ctx.account} not found."
    assert not_found_message == expected, f"expected message {expected!r}, got {not_found_message!r}"

    # Positive control: a correctly-trusted role reaches ACTIVE.
    good_role_name, good_role_arn = _create_firehose_role(ctx, iam, bucket)
    ctx.on_cleanup(lambda: _delete_role(iam, good_role_name, "firehose-s3-access"))

    good_stream_name = ctx.unique_name("sim2real-behav-fh-goodtrust-")
    _create_delivery_stream_with_role_retry(
        firehose,
        DeliveryStreamName=good_stream_name,
        DeliveryStreamType="DirectPut",
        ExtendedS3DestinationConfiguration={
            "BucketARN": f"arn:aws:s3:::{bucket}",
            "RoleARN": good_role_arn,
            "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},
        },
    )
    ctx.on_cleanup(lambda: _delete_stream_if_exists(firehose, good_stream_name))
    good_desc = _wait_stream_active(firehose, good_stream_name, timeout_s=180)
    assert good_desc["DeliveryStreamStatus"] == "ACTIVE", (
        f"expected positive control to reach ACTIVE, got {good_desc['DeliveryStreamStatus']}"
    )



def _create_bucket(ctx, s3) -> str:
    name = ctx.unique_name("sim2real-behav-fh-bkt-").lower()
    # us-east-1 is the one region CreateBucket rejects a LocationConstraint for.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
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


def _create_untrusted_role(ctx, iam, bucket: str) -> tuple[str, str]:
    role_name = ctx.unique_name("sim2real-behav-fh-badrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(policy))
    return role_name, role_arn


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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
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


def _delete_role(iam, role_name: str, policy_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
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


def _poll_until_terminal_create(firehose, name: str, timeout_s: float = 180, interval_s: float = 5) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status in ("ACTIVE", "CREATING_FAILED"):
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"delivery stream {name} did not reach a terminal creation state within {timeout_s}s")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
