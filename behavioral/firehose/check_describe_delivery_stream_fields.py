"""describe-delivery-stream-fields."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-delivery-stream-fields"
GROUP = 'lifecycle'
SERVICES = ['firehose']

TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "firehose.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}

ACCESS_POLICY = {
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
                "kms:Decrypt",
                "kms:GenerateDataKey",
                "logs:PutLogEvents",
            ],
            "Resource": "*",
        }
    ],
}

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

def _bucket_arn(bucket_name):
    return f"arn:aws:s3:::{bucket_name}"

def _describe(ctx, name):
    return ctx.client("firehose").describe_delivery_stream(DeliveryStreamName=name)[
        "DeliveryStreamDescription"
    ]

def _delivery_role_arn(ctx):
    """Create a real IAM role Firehose can assume (validated at CreateDeliveryStream
    time, so a fabricated ARN is not usable); register its teardown."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-fh-role-")
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
        Description="SimParityProbe behavioral fixture role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    iam.put_role_policy(
        RoleName=name,
        PolicyName="firehose-destination-access",
        PolicyDocument=json.dumps(ACCESS_POLICY),
    )

    def _teardown():
        try:
            for pn in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
                try:
                    iam.delete_role_policy(RoleName=name, PolicyName=pn)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "NoSuchEntity":
                        raise
            iam.delete_role(RoleName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_teardown)
    return resp["Role"]["Arn"]

def _make_bucket(ctx):
    """Create an S3 destination bucket and register its (empty-then-delete) teardown."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-firehose-dst-")
    kwargs = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )

    def _teardown():
        try:
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=name):
                for obj in page.get("Contents", []):
                    s3.delete_object(Bucket=name, Key=obj["Key"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise
        try:
            s3.delete_bucket(Bucket=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_teardown)
    return name

def _default_s3_config(ctx, bucket_name):
    return {
        "RoleARN": _delivery_role_arn(ctx),
        "BucketARN": _bucket_arn(bucket_name),
        "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
    }

def _delete_stream(ctx, name, force=True):
    try:
        ctx.client("firehose").delete_delivery_stream(
            DeliveryStreamName=name, AllowForceDelete=force
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

def _create_stream(ctx, name, bucket_name=None, **extra):
    """Create a delivery stream with a minimal ExtendedS3 destination unless the
    caller supplies their own destination kwargs. Retries while the IAM role is
    still propagating (Firehose rejects a brand-new role until it is visible)."""
    fh = ctx.client("firehose")
    if bucket_name is None and not any(
        k.endswith("DestinationConfiguration") for k in extra
    ):
        bucket_name = _make_bucket(ctx)
    kwargs = {"DeliveryStreamName": name, "Tags": [{"Key": "sim2real", "Value": CHECK}]}
    if bucket_name is not None:
        kwargs["ExtendedS3DestinationConfiguration"] = _default_s3_config(ctx, bucket_name)
    kwargs.update(extra)

    deadline = time.monotonic() + 60
    while True:
        try:
            resp = fh.create_delivery_stream(**kwargs)
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            msg = (exc.response.get("Error", {}).get("Message") or "").lower()
            propagating = code == "InvalidArgumentException" and (
                "assume" in msg or "not authorized" in msg or "does not exist" in msg
            )
            if propagating and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
    ctx.on_cleanup(lambda: _delete_stream(ctx, name))
    return resp

def _wait_active(ctx, name, timeout_s=100, interval_s=3):
    return _poll_until(
        lambda: _describe(ctx, name),
        lambda d: d["DeliveryStreamStatus"] == "ACTIVE",
        timeout_s=timeout_s,
        interval_s=interval_s,
    )

def _shared_stream(ctx):
    """An ACTIVE DirectPut -> ExtendedS3 stream (self-contained: created per check)."""
    name = ctx.unique_name("sim2real-behav-fh-shared-")
    _create_stream(ctx, name)
    _wait_active(ctx, name, timeout_s=100, interval_s=3)
    return name

def _shared_bucket(ctx):
    return _make_bucket(ctx)

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeDeliveryStream on an ACTIVE stream reports exactly one
    destination, the DirectPut source type and a well-formed ARN reflecting the
    configured S3 destination."""
    # Create the destination bucket and role ONCE and capture them; the helpers
    # provision fresh resources on every call, so the expected values must come
    # from the same objects the stream was created with (not a second call).
    bucket = _make_bucket(ctx)
    role_arn = _delivery_role_arn(ctx)
    name = ctx.unique_name("sim2real-behav-fh-shared-")
    _create_stream(
        ctx,
        name,
        ExtendedS3DestinationConfiguration={
            "RoleARN": role_arn,
            "BucketARN": _bucket_arn(bucket),
            "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
        },
    )
    _wait_active(ctx, name, timeout_s=100, interval_s=3)
    desc = _describe(ctx, name)

    assert desc["DeliveryStreamStatus"] == "ACTIVE", desc["DeliveryStreamStatus"]
    assert desc["DeliveryStreamType"] == "DirectPut", desc["DeliveryStreamType"]
    destinations = desc["Destinations"]
    assert len(destinations) == 1, f"expected exactly 1 destination, got {len(destinations)}"
    dest = destinations[0]
    assert dest.get("DestinationId"), "destination must carry a DestinationId"
    s3_dest = dest.get("ExtendedS3DestinationDescription") or dest.get("S3DestinationDescription")
    assert s3_dest is not None, "expected an S3 destination description"
    assert s3_dest["BucketARN"] == _bucket_arn(bucket), (
        f"expected BucketARN {_bucket_arn(bucket)!r}, got {s3_dest['BucketARN']!r}"
    )
    assert s3_dest["RoleARN"] == role_arn, f"expected RoleARN {role_arn!r}, got {s3_dest['RoleARN']!r}"
    assert ":deliverystream/" in desc["DeliveryStreamARN"], desc["DeliveryStreamARN"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
