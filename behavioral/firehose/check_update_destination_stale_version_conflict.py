"""update-destination-stale-version-conflict."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-destination-stale-version-conflict"
GROUP = 'overly-permissive'
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

def _err(fn):
    """Call fn(); return the botocore Error dict (Code, Message). An unexpected success
    raises, so a target that accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, the call succeeded with {result!r}")


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

def _shared_stream(ctx):
    """An ACTIVE DirectPut -> ExtendedS3 stream."""
    name = ctx.unique_name("sim2real-behav-fh-shared-")
    _create_stream(ctx, name)
    _wait_active(ctx, name, timeout_s=100, interval_s=3)
    return name

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateDestination with a stale CurrentDeliveryStreamVersionId fails with
    ConcurrentModificationException and its payload never lands; a follow-up call with the current
    version succeeds."""
    fh = ctx.client("firehose")
    name = _shared_stream(ctx)
    desc = _describe(ctx, name)
    stale_version_id = desc["VersionId"]
    destination_id = desc["Destinations"][0]["DestinationId"]

    # Advance the version once (positive control) so `stale_version_id` becomes outdated.
    fh.update_destination(
        DeliveryStreamName=name,
        CurrentDeliveryStreamVersionId=stale_version_id,
        DestinationId=destination_id,
        ExtendedS3DestinationUpdate={
            "BufferingHints": {"SizeInMBs": 2, "IntervalInSeconds": 90},
        },
    )

    def probe():
        return _describe(ctx, name)

    desc1 = _poll_until(
        probe,
        lambda d: d["VersionId"] != stale_version_id and d["DeliveryStreamStatus"] == "ACTIVE",
        timeout_s=60,
        interval_s=3,
        description="VersionId advanced after first UpdateDestination",
    )
    current_version_id = desc1["VersionId"]

    err = _err(
        lambda: fh.update_destination(
            DeliveryStreamName=name,
            CurrentDeliveryStreamVersionId=stale_version_id,
            DestinationId=destination_id,
            ExtendedS3DestinationUpdate={
                "BufferingHints": {"SizeInMBs": 3, "IntervalInSeconds": 100},
            },
        )
    )
    assert err.get("Code") == "ConcurrentModificationException", (
        f"expected ConcurrentModificationException, got {err!r}"
    )
    expected_msg = (
        f"Cannot update firehose: {name} since the current version id: {current_version_id} "
        f"and specified version id: {stale_version_id} do not match"
    )
    assert err.get("Message") == expected_msg, (
        f"expected message {expected_msg!r}, got {err.get('Message')!r}"
    )

    # Effect absent: the rejected call's payload (3/100) never landed, and the
    # VersionId did not move again.
    desc2 = _describe(ctx, name)
    assert desc2["VersionId"] == current_version_id, (
        f"VersionId must not advance on a rejected UpdateDestination, "
        f"was {current_version_id} now {desc2['VersionId']}"
    )
    rejected_hints = desc2["Destinations"][0]["ExtendedS3DestinationDescription"]["BufferingHints"]
    assert rejected_hints == {"SizeInMBs": 2, "IntervalInSeconds": 90}, (
        f"rejected UpdateDestination's payload must not land, got {rejected_hints}"
    )

    # Restore: the identical intent, now using the correct current version, succeeds.
    fh.update_destination(
        DeliveryStreamName=name,
        CurrentDeliveryStreamVersionId=current_version_id,
        DestinationId=destination_id,
        ExtendedS3DestinationUpdate={
            "BufferingHints": {"SizeInMBs": 3, "IntervalInSeconds": 100},
        },
    )
    desc3 = _poll_until(
        probe,
        lambda d: d["VersionId"] != current_version_id and d["DeliveryStreamStatus"] == "ACTIVE",
        timeout_s=60,
        interval_s=3,
        description="VersionId advanced after restored UpdateDestination",
    )
    restored_hints = desc3["Destinations"][0]["ExtendedS3DestinationDescription"]["BufferingHints"]
    assert restored_hints == {"SizeInMBs": 3, "IntervalInSeconds": 100}, (
        f"restored UpdateDestination with the correct version must apply, got {restored_hints}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
