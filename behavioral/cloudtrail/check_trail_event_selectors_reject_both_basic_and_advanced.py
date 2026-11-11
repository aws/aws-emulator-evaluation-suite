"""trail-event-selectors-reject-both-basic-and-advanced."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "trail-event-selectors-reject-both-basic-and-advanced"
GROUP = 'overly-permissive'
SERVICES = ['cloudtrail']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """EventSelectors and AdvancedEventSelectors are mutually exclusive — supplying
    both in one PutEventSelectors call must be rejected, not silently merged, and
    must not fall back to resetting the trail's selectors to their default."""
    ct = ctx.client("cloudtrail")
    name = _create_trail(ctx)

    # Positive control: a valid, NON-DEFAULT basic selector set is accepted and takes
    # effect. Without this, the terminal read below (proving the rejected call left the
    # trail untouched) would be indistinguishable from a target that reset the trail to
    # its DEFAULT selectors — "All" is both the untouched value and a fresh trail's
    # default, so a reset-on-rejection target would read identically to a correct one.
    baseline = ct.put_event_selectors(
        TrailName=name,
        EventSelectors=[
            {"ReadWriteType": "WriteOnly", "IncludeManagementEvents": True, "DataResources": []}
        ],
    )["EventSelectors"]
    assert baseline[0]["ReadWriteType"] == "WriteOnly", baseline
    got = ct.get_event_selectors(TrailName=name)["EventSelectors"]
    assert got == baseline, got

    err = _expect_error(
        lambda: ct.put_event_selectors(
            TrailName=name,
            EventSelectors=[
                {"ReadWriteType": "All", "IncludeManagementEvents": True, "DataResources": []}
            ],
            AdvancedEventSelectors=[
                {
                    "Name": "mgmt-only",
                    "FieldSelectors": [
                        {"Field": "eventCategory", "Equals": ["Management"]}
                    ],
                }
            ],
        )
    )
    assert err == (
        "InvalidEventSelectorsException",
        "You can select events by using either EventSelectors or AdvancedEventSelectors, "
        "but not both.",
    ), err

    # The rejected call must leave the non-default baseline untouched — not reset to
    # the trail's original default ("All"), the failure mode a check that compares only
    # against the default cannot see.
    after = ct.get_event_selectors(TrailName=name)["EventSelectors"]
    assert after == baseline, after


def _expect_error(fn):
    """The exact AWS (Error.Code, Error.Message), RAISING if the call unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError("PutEventSelectors unexpectedly SUCCEEDED on a mutually-exclusive selector payload")


def _bucket_reachable(s3, bucket) -> bool:
    """True once HeadBucket succeeds; a ClientError means the bucket is not visible yet."""
    try:
        s3.head_bucket(Bucket=bucket)
    except ClientError:
        return False
    return True


def _create_bucket_with_trail_policy(ctx) -> str:
    """An S3 bucket whose policy lets CloudTrail write to it.

    Deliberately does NOT swallow errors: a silently-failed bucket create
    surfaces later as a confusing S3BucketDoesNotExistException from CreateTrail.
    """
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-ct-bucket-").lower()[:63]
    params = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    try:
        s3.create_bucket(**params)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("BucketAlreadyOwnedByYou",):
            raise
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]})

    # Bucket creation is eventually consistent for policy attachment.
    _poll_until(
        lambda: _bucket_reachable(s3, bucket),
        lambda ok: ok,
        timeout_s=60,
        interval_s=2,
        description="bucket head_bucket ok",
    )

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
                # Wildcard (rather than AWSLogs/<account>/*) so trails that add an
                # S3KeyPrefix still satisfy CloudTrail's bucket-policy validation.
                "Resource": f"arn:aws:s3:::{bucket}/*",
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    return bucket


def _create_trail(ctx) -> str:
    """A trail backed by a freshly created, policy-attached S3 bucket. Returns its name.

    Retries the transient S3-consistency errors CreateTrail raises while the
    just-written bucket policy propagates.
    """
    ct = ctx.client("cloudtrail")
    name = ctx.unique_name("sim2real-behav-trail-")
    bucket = _create_bucket_with_trail_policy(ctx)
    transient = {
        "S3BucketDoesNotExistException",
        "InsufficientS3BucketPolicyException",
        "ThrottlingException",
    }
    deadline = time.monotonic() + 120
    while True:
        try:
            ct.create_trail(Name=name, S3BucketName=bucket)
            ctx.on_cleanup(lambda: ct.delete_trail(Name=name))
            return name
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in transient and time.monotonic() < deadline:
                time.sleep(4)
                continue
            raise


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            for obj in page.get("Versions", []) + page.get("DeleteMarkers", []):
                try:
                    s3.delete_object(Bucket=bucket, Key=obj["Key"], VersionId=obj["VersionId"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                        raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
            try:
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                    raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    s3.delete_bucket(Bucket=bucket)


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float = 1.0,
                description: str = "condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
