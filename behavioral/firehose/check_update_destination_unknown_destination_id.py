"""update-destination-unknown-destination-id."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-destination-unknown-destination-id"
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
    """UpdateDestination rejects a DestinationId that does not belong to the stream without bumping
    the version; a prior update on the real DestinationId succeeds, so not every call is refused."""
    name = _shared_stream(ctx)
    desc0 = _describe(ctx, name)
    real_destination_id = desc0["Destinations"][0]["DestinationId"]
    version_id_0 = desc0["VersionId"]

    # Positive control: updating the real destination with the matching
    # version succeeds, bumps VersionId, and the new hint is reflected.
    ctx.client("firehose").update_destination(
        DeliveryStreamName=name,
        CurrentDeliveryStreamVersionId=version_id_0,
        DestinationId=real_destination_id,
        ExtendedS3DestinationUpdate={
            "BufferingHints": {"SizeInMBs": 3, "IntervalInSeconds": 90},
        },
    )
    desc1 = _describe(ctx, name)
    version_id_1 = desc1["VersionId"]
    assert version_id_1 != version_id_0, (
        f"positive control update did not bump VersionId: still {version_id_0!r}"
    )
    applied_hints = desc1["Destinations"][0]["ExtendedS3DestinationDescription"]["BufferingHints"]
    assert applied_hints["IntervalInSeconds"] == 90, (
        f"positive control update not reflected: expected IntervalInSeconds=90, got {applied_hints!r}"
    )

    # Negative: a DestinationId that does not belong to the stream is refused,
    # even though the version and destination-update body are otherwise valid.
    err = _err(
        lambda: ctx.client("firehose").update_destination(
            DeliveryStreamName=name,
            CurrentDeliveryStreamVersionId=version_id_1,
            DestinationId="destinationId-000000000099",
            ExtendedS3DestinationUpdate={
                "BufferingHints": {"SizeInMBs": 4, "IntervalInSeconds": 110},
            },
        )
    )
    assert err.get("Code") == "InvalidArgumentException", f"expected InvalidArgumentException, got {err!r}"
    expected_msg = "Destination Id destinationId-000000000099 not found"
    assert err.get("Message") == expected_msg, (
        f"expected message {expected_msg!r}, got {err.get('Message')!r}"
    )

    # Rejected update must not have bumped the version or touched the hints
    # the positive control just set.
    desc2 = _describe(ctx, name)
    assert desc2["VersionId"] == version_id_1, (
        f"rejected update bumped VersionId: expected {version_id_1!r}, got {desc2['VersionId']!r}"
    )
    rejected_hints = desc2["Destinations"][0]["ExtendedS3DestinationDescription"]["BufferingHints"]
    assert rejected_hints["IntervalInSeconds"] == 90, (
        f"rejected update mutated BufferingHints: expected IntervalInSeconds=90, got {rejected_hints!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
