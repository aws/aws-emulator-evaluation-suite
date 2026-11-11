"""extended-s3-destination-configuration-defaults."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "extended-s3-destination-configuration-defaults"
GROUP = 'configuration'
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

# Transient Firehose validation failures caused by S3/IAM eventual consistency.
_PROPAGATION_HINTS = ("bucket", "assume", "privilege", "not authorized", "does not exist")


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


def _describe(ctx, name):
    return ctx.client("firehose").describe_delivery_stream(DeliveryStreamName=name)[
        "DeliveryStreamDescription"
    ]


def _wait_active(ctx, name, timeout_s=120, interval_s=3):
    """Poll until ACTIVE; a terminal CREATING_FAILED/DELETING_FAILED is a hard failure."""

    def is_active(desc):
        status = desc.get("DeliveryStreamStatus")
        if status in ("CREATING_FAILED", "DELETING_FAILED"):
            raise AssertionError(f"stream {name} entered terminal failure state {status}")
        return status == "ACTIVE"

    return _poll_until(
        lambda: _describe(ctx, name), is_active, timeout_s=timeout_s, interval_s=interval_s
    )


def _delivery_role_arn(ctx):
    """Create a real IAM role Firehose can assume (Firehose validates RoleARN at
    CreateDeliveryStream time, so a fabricated ARN is not usable); register teardown.
    IAM is eventually consistent, so give the role time to propagate."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-fh-role-")[:64]
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
        Description="sim2real behavioral probe role for Amazon Data Firehose",
        Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
    )
    iam.put_role_policy(
        RoleName=name,
        PolicyName="firehose-access",
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
    """Create the S3 destination bucket and register its (empty-then-delete) teardown."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-fh-bucket-").lower()
    kwargs = {"Bucket": name}
    # us-east-1 is the API's default region and rejects an explicit LocationConstraint.
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "purpose", "Value": "behavioral-check"}]}
    )

    def _teardown():
        try:
            for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
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
    # Read-after-create: make sure the bucket is visible before Firehose looks.
    _poll_until(
        lambda: _head_ok(s3, name), lambda ok: ok, timeout_s=60, interval_s=2,
        description="destination bucket visible",
    )
    return name


def _head_ok(s3, bucket):
    try:
        s3.head_bucket(Bucket=bucket)
        return True
    except Exception:
        return False


def _bucket_arn(bucket_name):
    return f"arn:aws:s3:::{bucket_name}"


def _create_stream(ctx, name, **kwargs):
    """Create a delivery stream and register its teardown.

    Retries only the *propagation* flavours of InvalidArgumentException (bucket
    not yet visible / role not yet assumable). Genuine argument errors are raised
    immediately so negative checks stay fast and precise.
    """
    fh = ctx.client("firehose")
    deadline = time.monotonic() + 120
    while True:
        try:
            resp = fh.create_delivery_stream(DeliveryStreamName=name, **kwargs)
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            msg = (err.get("Message") or "").lower()
            transient = err.get("Code") == "InvalidArgumentException" and any(
                hint in msg for hint in _PROPAGATION_HINTS
            )
            if transient and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise
    ctx.on_cleanup(lambda: _delete_stream(ctx, name))
    return resp


def _delete_stream(ctx, name):
    try:
        ctx.client("firehose").delete_delivery_stream(
            DeliveryStreamName=name, AllowForceDelete=True
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ExtendedS3DestinationConfiguration is echoed back with service-applied defaults on Describe."""
    name = ctx.unique_name("sim2real-behav-fh-extended-")
    bucket = _make_bucket(ctx)
    role_arn = _delivery_role_arn(ctx)
    _create_stream(
        ctx,
        name,
        ExtendedS3DestinationConfiguration={
            "RoleARN": role_arn,
            "BucketARN": _bucket_arn(bucket),
            "Prefix": "extended/",
            "ErrorOutputPrefix": "errors/",
            "CompressionFormat": "GZIP",
            "BufferingHints": {"SizeInMBs": 8, "IntervalInSeconds": 120},
        },
        Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
    )
    desc = _wait_active(ctx, name)

    dest = desc["Destinations"][0]
    ext = dest["ExtendedS3DestinationDescription"]
    assert ext["Prefix"] == "extended/", f"expected Prefix='extended/', got {ext['Prefix']!r}"
    assert ext["ErrorOutputPrefix"] == "errors/", (
        f"expected ErrorOutputPrefix='errors/', got {ext['ErrorOutputPrefix']!r}"
    )
    assert ext["CompressionFormat"] == "GZIP", (
        f"expected CompressionFormat='GZIP', got {ext['CompressionFormat']!r}"
    )
    assert ext["BufferingHints"] == {"SizeInMBs": 8, "IntervalInSeconds": 120}, (
        f"expected supplied BufferingHints to round-trip, got {ext['BufferingHints']!r}"
    )
    # Service-applied defaults for fields the caller never supplied.
    assert ext.get("S3BackupMode") == "Disabled", f"expected default S3BackupMode=Disabled, got {ext.get('S3BackupMode')}"
    assert ext["EncryptionConfiguration"]["NoEncryptionConfig"] == "NoEncryption", (
        f"expected default EncryptionConfiguration=NoEncryption, got {ext['EncryptionConfiguration']!r}"
    )
    assert ext["CloudWatchLoggingOptions"]["Enabled"] is False, (
        f"expected default CloudWatchLoggingOptions.Enabled=False, got {ext['CloudWatchLoggingOptions']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
