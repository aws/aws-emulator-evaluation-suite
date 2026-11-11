"""e2e-create-put-land-delete-full-flow."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-create-put-land-delete-full-flow"
GROUP = "e2e"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Create a stream, PutRecord several records, observe them land as objects in
    S3, delete the stream, and confirm it is gone."""
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
        Tags=[
            {"Key": "sim2real", "Value": "e2e-create-put-land-delete-full-flow"},
            {"Key": "sim2real:managed", "Value": "true"},
        ],
    )
    ctx.on_cleanup(lambda: _delete_stream_if_exists(firehose, stream_name))
    _wait_stream_active(firehose, stream_name)

    markers = set()
    for i in range(3):
        marker = ctx.unique_name(f"marker{i}-")
        markers.add(marker)
        firehose.put_record(
            DeliveryStreamName=stream_name,
            Record={"Data": f"record::{marker}\n".encode("utf-8")},
        )

    remaining = _wait_for_objects_containing(s3, bucket, markers, timeout_s=240, interval_s=15)
    assert not remaining, f"markers never landed in s3://{bucket}: {remaining}"

    firehose.delete_delivery_stream(DeliveryStreamName=stream_name, AllowForceDelete=True)
    _wait_stream_deleted(firehose, stream_name)

    code, msg = _error_code(lambda: firehose.describe_delivery_stream(DeliveryStreamName=stream_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException from describe after delete, got {code!r}"
    expected_msg = f"Firehose under account {ctx.account} not found."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    put_code, put_msg = _error_code(
        lambda: firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": b"after-delete"})
    )
    assert put_code == "ResourceNotFoundException", (
        f"expected PutRecord against the deleted stream to be rejected with ResourceNotFoundException, got {put_code!r}"
    )
    expected_put_msg = f"Firehose not found under account {ctx.account}."
    assert put_msg == expected_put_msg, f"expected message {expected_put_msg!r}, got {put_msg!r}"


def _error_code(fn):
    """Call fn(), which must fail; return (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _create_bucket(ctx, s3) -> str:
    name = ctx.unique_name("sim2real-behav-fh-bkt-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "e2e-create-put-land-delete-full-flow"},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})
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
        Tags=[
            {"Key": "sim2real", "Value": "e2e-create-put-land-delete-full-flow"},
            {"Key": "sim2real:managed", "Value": "true"},
        ],
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
    """A freshly-created IAM role can take a few seconds to become assumable by
    Firehose; retry CreateDeliveryStream while it reports that specific error."""
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


def _wait_for_objects_containing(
    s3, bucket: str, markers: set[str], timeout_s: float = 240, interval_s: float = 15
) -> set[str]:
    remaining = set(markers)
    seen_keys: set[str] = set()
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and remaining:
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            key = obj["Key"]
            if key in seen_keys:
                continue
            seen_keys.add(key)
            body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
            text = body.decode("utf-8", errors="ignore")
            for m in list(remaining):
                if m in text:
                    remaining.discard(m)
        if remaining:
            time.sleep(interval_s)
    return remaining


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
