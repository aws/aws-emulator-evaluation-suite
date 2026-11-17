"""put-event-selectors-neither-or-both-selectors-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-event-selectors-neither-or-both-selectors-rejected"
GROUP = "rejected"
SERVICES = ["cloudtrail", "s3"]

_NEITHER = (
    "InvalidEventSelectorsException",
    "You must select events by using either EventSelectors or AdvancedEventSelectors, "
    "but you cannot use both.",
)
_BOTH = (
    "InvalidEventSelectorsException",
    "You can select events by using either EventSelectors or AdvancedEventSelectors, "
    "but not both.",
)


def expect_error(fn, code: str, message: str) -> None:
    """Assert fn() raises a ClientError with exactly this (code, message); raise on success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        assert err.get("Code") == code, err
        assert err.get("Message") == message, err
        return
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


def _retry_transient(fn, attempts: int = 8):
    """Retry a CloudTrail control-plane call past transient S3-policy propagation lag."""
    transient = {
        "S3BucketDoesNotExistException",
        "InsufficientS3BucketPolicyException",
        "ThrottlingException",
    }
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in transient and i < attempts - 1:
                last = exc
                time.sleep(2.0 * (i + 1))
                continue
            raise
    raise last


def _create_trail_bucket(s3, bucket: str, region: str) -> None:
    kwargs = {"Bucket": bucket}
    if region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    try:
        s3.create_bucket(**kwargs)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            raise
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket}",
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]},
    )


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                errors = s3.delete_objects(
                    Bucket=bucket,
                    Delete={"Objects": [{"Key": o["Key"]} for o in objs]},
                ).get("Errors")
                if errors:
                    raise AssertionError(f"DeleteObjects left {len(errors)} object(s): {errors[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _delete_trail(ct, name: str) -> None:
    try:
        ct.delete_trail(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutEventSelectors refuses a call naming neither selector kind, and one naming both,
    each with its own exact message, and both leave an accepted ReadOnly selector untouched.

    Reference: https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_PutEventSelectors.html
    """
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")

    name = ctx.unique_name("sim2real-behav-ct-trail-")
    bucket = ctx.unique_name("sim2real-behav-ct-bkt-").lower()[:63]
    _create_trail_bucket(s3, bucket, ctx.region)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    _retry_transient(lambda: ct.create_trail(Name=name, S3BucketName=bucket))
    ctx.on_cleanup(lambda: _delete_trail(ct, name))

    # Positive control: an EventSelectors-only call naming ReadOnly is accepted, and
    # GetEventSelectors echoes exactly it. This is the "last accepted" baseline every
    # refusal below is checked against.
    accepted = ct.put_event_selectors(
        TrailName=name,
        EventSelectors=[{"ReadWriteType": "ReadOnly", "IncludeManagementEvents": True}],
    )["EventSelectors"]
    assert len(accepted) == 1, accepted
    assert accepted[0]["ReadWriteType"] == "ReadOnly", accepted
    assert accepted[0]["IncludeManagementEvents"] is True, accepted
    baseline = ct.get_event_selectors(TrailName=name)["EventSelectors"]
    assert baseline == accepted, baseline

    # Neither EventSelectors nor AdvancedEventSelectors supplied.
    expect_error(lambda: ct.put_event_selectors(TrailName=name), *_NEITHER)
    after_neither = ct.get_event_selectors(TrailName=name)["EventSelectors"]
    assert after_neither == baseline, after_neither

    # Both EventSelectors and AdvancedEventSelectors supplied in the same call.
    expect_error(
        lambda: ct.put_event_selectors(
            TrailName=name,
            EventSelectors=[{"ReadWriteType": "All", "IncludeManagementEvents": True}],
            AdvancedEventSelectors=[
                {
                    "Name": "mgmt-only",
                    "FieldSelectors": [{"Field": "eventCategory", "Equals": ["Management"]}],
                }
            ],
        ),
        *_BOTH,
    )
    after_both = ct.get_event_selectors(TrailName=name)["EventSelectors"]
    assert after_both == baseline, after_both


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
