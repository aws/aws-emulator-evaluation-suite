"""tag-delivery-stream-nonexistent-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-delivery-stream-nonexistent-rejected"
GROUP = 'overly-permissive'
SERVICES = ['firehose']

def _err(fn):
    """Call fn(); return the botocore Error dict (Code, Message) if a ClientError is raised. An
    unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected rejection, but the call succeeded: {result!r}")

def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "NoSuchBucket",
            "NoSuchEntity",
            "NoSuchKey",
            "ResourceNotFoundException",
        ):
            raise

def _describe(ctx, name):
    return ctx.client("firehose").describe_delivery_stream(DeliveryStreamName=name)[
        "DeliveryStreamDescription"
    ]

def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")

def _make_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-fh-tag-absent-dst-")
    kwargs = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _teardown():
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=name):
            for obj in page.get("Contents", []):
                _swallow(lambda o=obj: s3.delete_object(Bucket=name, Key=o["Key"]))
        _swallow(lambda: s3.delete_bucket(Bucket=name))

    ctx.on_cleanup(_teardown)
    return name

def _delivery_role_arn(ctx):
    """A real IAM role Firehose accepts on CreateDeliveryStream (validated at
    creation time, so a fabricated ARN would not get us to an ACTIVE stream)."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-fh-tag-absent-role-")
    trust_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "firehose.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    access_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:GetObject",
                "s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:PutObject",
            ],
            "Resource": "*",
        }],
    })
    resp = iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust_policy)
    iam.put_role_policy(RoleName=name, PolicyName="fh-dst-access", PolicyDocument=access_policy)

    def _teardown():
        _swallow(lambda: iam.delete_role_policy(RoleName=name, PolicyName="fh-dst-access"))
        _swallow(lambda: iam.delete_role(RoleName=name))

    ctx.on_cleanup(_teardown)
    return resp["Role"]["Arn"]

def _create_stream(ctx, name, bucket_name, role_arn):
    """CreateDeliveryStream, retrying while the freshly created role's PassRole
    grant propagates (Firehose rejects a brand-new role until it is visible)."""
    fh = ctx.client("firehose")
    deadline = time.monotonic() + 60
    while True:
        try:
            fh.create_delivery_stream(
                DeliveryStreamName=name,
                ExtendedS3DestinationConfiguration={
                    "RoleARN": role_arn,
                    "BucketARN": f"arn:aws:s3:::{bucket_name}",
                    "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
                },
            )
            return
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

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagDeliveryStream on a nonexistent stream is rejected with ResourceNotFoundException, as is
    ListTagsForDeliveryStream; tagging a real stream succeeds, confirmed by an independent read."""
    fh = ctx.client("firehose")

    real_name = ctx.unique_name("sim2real-behav-fh-tag-real-")
    bucket_name = _make_bucket(ctx)
    role_arn = _delivery_role_arn(ctx)
    _create_stream(ctx, real_name, bucket_name, role_arn)
    ctx.on_cleanup(lambda: _swallow(
        lambda: fh.delete_delivery_stream(DeliveryStreamName=real_name, AllowForceDelete=True)
    ))
    _poll_until(
        lambda: _describe(ctx, real_name),
        lambda d: d["DeliveryStreamStatus"] == "ACTIVE",
        timeout_s=100, interval_s=3, description="real stream reaching ACTIVE",
    )

    fh.tag_delivery_stream(DeliveryStreamName=real_name, Tags=[{"Key": "k", "Value": "v"}])
    live_tags = {
        t["Key"]: t["Value"]
        for t in fh.list_tags_for_delivery_stream(DeliveryStreamName=real_name)["Tags"]
    }
    assert live_tags.get("k") == "v", (
        f"positive control failed: tag not visible via independent read: {live_tags}"
    )

    absent_name = ctx.unique_name("sim2real-behav-fh-tag-absent-")
    expected_msg = f"Firehose under account {ctx.account} not found."
    err = _err(
        lambda: fh.tag_delivery_stream(
            DeliveryStreamName=absent_name, Tags=[{"Key": "k", "Value": "v"}]
        )
    )
    assert err.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {err!r}"
    )
    assert err.get("Message") == expected_msg, (
        f"expected message {expected_msg!r}, got {err.get('Message')!r}"
    )

    # Terminal assertion: an independent read (not the mutating call above)
    # confirms there is nothing to tag — same not-found contract, different operation.
    read_err = _err(lambda: fh.list_tags_for_delivery_stream(DeliveryStreamName=absent_name))
    assert read_err.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException on independent read, got {read_err!r}"
    )
    assert read_err.get("Message") == expected_msg, (
        f"expected message {expected_msg!r} on independent read, got {read_err.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
