"""stop-encryption-on-unencrypted-stream."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-encryption-on-unencrypted-stream"
GROUP = 'encryption'
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


def _error(fn):
    """Call fn(); return the botocore Error dict if a ClientError was raised.

    Raises on unexpected success rather than returning a falsy sentinel, so an
    over-permissive target's acceptance fails as an acceptance, not a code mismatch.
    """
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, call succeeded with {resp!r}")


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


def _wait_encryption_status(ctx, name, statuses, timeout_s=90, interval_s=2):
    """Poll until the stream's encryption Status is one of *statuses*; a terminal
    ENABLING_FAILED/DISABLING_FAILED is a hard failure."""

    def matches(desc):
        enc = desc.get("DeliveryStreamEncryptionConfiguration") or {}
        status = enc.get("Status")
        if status in ("ENABLING_FAILED", "DISABLING_FAILED"):
            raise AssertionError(f"encryption for {name} entered terminal failure state {status}")
        return status in statuses

    return _poll_until(
        lambda: _describe(ctx, name), matches, timeout_s=timeout_s, interval_s=interval_s
    )


def _delivery_role_arn(ctx):
    """Create a real IAM role Firehose can assume (Firehose validates RoleARN at
    CreateDeliveryStream time, so a fabricated ARN is not usable); register teardown."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-fh-role-")[:64]
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
        Description="sim2real behavioral probe role for Amazon Data Firehose",
        Tags=[{"Key": "sim2real-purpose", "Value": CHECK}],
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


def _head_ok(s3, bucket):
    try:
        s3.head_bucket(Bucket=bucket)
        return True
    except Exception:
        return False


def _make_bucket(ctx):
    """Create the S3 destination bucket and register its (empty-then-delete) teardown."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-fh-bucket-").lower()
    kwargs = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-purpose", "Value": CHECK}]}
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


def _bucket_arn(bucket_name):
    return f"arn:aws:s3:::{bucket_name}"


def _delete_stream(ctx, name, timeout_s=120.0):
    """Delete the stream and wait until it is gone: a DELETING stream is still listed."""
    fh = ctx.client("firehose")
    try:
        fh.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            status = _describe(ctx, name)["DeliveryStreamStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"stream {name} still {status} {timeout_s}s after DeleteDeliveryStream")
        time.sleep(2)


def _create_stream(ctx, name, **kwargs):
    """Create a delivery stream (defaults to a DirectPut/S3 stream) and register teardown.

    Retries only the *propagation* flavours of InvalidArgumentException (bucket
    not yet visible / role not yet assumable). Genuine argument errors are raised
    immediately so negative checks stay fast and precise.
    """
    fh = ctx.client("firehose")
    if (
        "S3DestinationConfiguration" not in kwargs
        and "ExtendedS3DestinationConfiguration" not in kwargs
        and "DeliveryStreamType" not in kwargs
    ):
        kwargs["S3DestinationConfiguration"] = {
            "RoleARN": _delivery_role_arn(ctx),
            "BucketARN": _bucket_arn(_make_bucket(ctx)),
            "BufferingHints": {"SizeInMBs": 5, "IntervalInSeconds": 300},
        }
    kwargs.setdefault("Tags", [{"Key": "sim2real-purpose", "Value": CHECK}])

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


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StopDeliveryStreamEncryption on a never-encrypted stream is rejected with
    InvalidArgumentException (not an idempotent no-op) and leaves DISABLED untouched; once ENABLED,
    the identical call succeeds and drives the stream to DISABLED."""
    fh = ctx.client("firehose")
    name = ctx.unique_name("sim2real-behav-fh-stopnoenc-")
    _create_stream(ctx, name)
    _wait_active(ctx, name)

    before = _describe(ctx, name).get("DeliveryStreamEncryptionConfiguration") or {}
    assert before.get("Status", "DISABLED") == "DISABLED", (
        f"expected a freshly created stream to start unencrypted, got {before!r}"
    )

    err = _error(lambda: fh.stop_delivery_stream_encryption(DeliveryStreamName=name))
    assert err.get("Code") == "InvalidArgumentException", (
        f"expected InvalidArgumentException stopping encryption on an unencrypted stream, got {err!r}"
    )
    expected_msg = (
        f"Cannot disable encryption on firehose: {name} when encryption is already disabled"
    )
    assert err.get("Message") == expected_msg, (
        f"expected message {expected_msg!r}, got {err.get('Message')!r}"
    )

    # Effect-absent: the rejected call left the stream's encryption state untouched.
    after = _describe(ctx, name).get("DeliveryStreamEncryptionConfiguration") or {}
    assert after.get("Status", "DISABLED") == "DISABLED", (
        f"a rejected StopDeliveryStreamEncryption must not change encryption state, got {after!r}"
    )

    # Positive control: the same call, on the same stream, succeeds once there is
    # something real to stop -- ruling out a target that rejects every call.
    fh.start_delivery_stream_encryption(
        DeliveryStreamName=name,
        DeliveryStreamEncryptionConfigurationInput={"KeyType": "AWS_OWNED_CMK"},
    )
    _wait_encryption_status(ctx, name, ("ENABLED",))

    fh.stop_delivery_stream_encryption(DeliveryStreamName=name)
    desc = _wait_encryption_status(ctx, name, ("DISABLED",))
    assert desc["DeliveryStreamEncryptionConfiguration"]["Status"] == "DISABLED", (
        "expected StopDeliveryStreamEncryption on a genuinely ENABLED stream to reach DISABLED"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
