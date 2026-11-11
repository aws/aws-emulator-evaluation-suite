"""start-encryption-enabling-then-enabled."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-encryption-enabling-then-enabled"
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
    kwargs = {"DeliveryStreamName": name}
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

def _wait_encryption_status(ctx, name, target, timeout_s=60, interval_s=2):
    def matches(desc):
        cfg = desc.get("DeliveryStreamEncryptionConfiguration") or {}
        return cfg.get("Status") in target

    return _poll_until(
        lambda: _describe(ctx, name),
        matches,
        timeout_s=timeout_s,
        interval_s=interval_s,
    )

def _encryption_stream(ctx):
    """A separate ACTIVE stream dedicated to the SSE state-machine checks."""
    name = ctx.unique_name("sim2real-behav-fh-enc-")
    _create_stream(ctx, name)
    _wait_active(ctx, name, timeout_s=100, interval_s=3)
    return name

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After StartDeliveryStreamEncryption the encryption status reads ENABLING or ENABLED and
    settles ENABLED with KeyType AWS_OWNED_CMK, the stream stays ACTIVE, and records put
    afterwards are reported as Encrypted."""
    name = _encryption_stream(ctx)

    # Make the starting point deterministic without depending on other checks.
    cfg = _describe(ctx, name).get("DeliveryStreamEncryptionConfiguration") or {}
    if cfg.get("Status") in ("ENABLING", "ENABLED"):
        if cfg.get("Status") == "ENABLING":
            _wait_encryption_status(ctx, name, {"ENABLED"}, timeout_s=90, interval_s=3)
        ctx.client("firehose").stop_delivery_stream_encryption(DeliveryStreamName=name)
        _wait_encryption_status(ctx, name, {"DISABLED"}, timeout_s=90, interval_s=3)

    ctx.client("firehose").start_delivery_stream_encryption(
        DeliveryStreamName=name,
        DeliveryStreamEncryptionConfigurationInput={"KeyType": "AWS_OWNED_CMK"},
    )
    interim = _describe(ctx, name)
    assert interim["DeliveryStreamStatus"] == "ACTIVE", (
        f"expected stream to stay ACTIVE during encryption enable, got {interim['DeliveryStreamStatus']!r}"
    )
    # Firehose sets ENABLING first, then ENABLED; no ENABLING duration is documented.
    assert interim["DeliveryStreamEncryptionConfiguration"]["Status"] in ("ENABLING", "ENABLED"), (
        "expected ENABLING or ENABLED right after StartDeliveryStreamEncryption, got "
        f"{interim['DeliveryStreamEncryptionConfiguration']['Status']}"
    )

    desc = _wait_encryption_status(ctx, name, {"ENABLED"}, timeout_s=90, interval_s=3)
    cfg = desc["DeliveryStreamEncryptionConfiguration"]
    assert cfg["Status"] == "ENABLED", f"expected encryption to settle at ENABLED, got {cfg['Status']!r}"
    assert cfg["KeyType"] == "AWS_OWNED_CMK", f"expected KeyType AWS_OWNED_CMK, got {cfg.get('KeyType')!r}"
    assert desc["DeliveryStreamStatus"] == "ACTIVE", (
        f"expected stream to stay ACTIVE once encryption is ENABLED, got {desc['DeliveryStreamStatus']!r}"
    )

    resp = ctx.client("firehose").put_record(DeliveryStreamName=name, Record={"Data": b"secret"})
    assert resp.get("Encrypted") is True, (
        f"PutRecord on an SSE-enabled stream must report Encrypted=True, got {resp.get('Encrypted')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
