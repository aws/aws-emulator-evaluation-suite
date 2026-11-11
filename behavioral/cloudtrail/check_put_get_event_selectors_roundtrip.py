"""put-get-event-selectors-roundtrip."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _call(fn, retry_codes=(
    "ThrottlingException",
    "MaximumNumberOfTrailsExceededException",
    "ConflictException",
    "InsufficientS3BucketPolicyException",
), attempts=7):
    """Invoke fn(), retrying transient CloudTrail control-plane errors."""
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in retry_codes and i < attempts - 1:
                last = exc
                time.sleep(2.0 * (i + 1))
                continue
            raise
    raise last


def _create_bucket_only(s3, bucket, region):
    """Create a plain S3 bucket (no CloudTrail policy).

    S3's CreateBucket rejects an explicit LocationConstraint for us-east-1 (its
    legacy default endpoint); ctx.region still drives bucket placement everywhere
    else, so this is not a region pin of the check.
    """
    kwargs = {"Bucket": bucket}
    if region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    try:
        s3.create_bucket(**kwargs)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            raise


def _create_trail_bucket(s3, bucket, region, account_id):
    """Create an S3 bucket with the policy CloudTrail needs to deliver logs."""
    _create_bucket_only(s3, bucket, region)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"},
    ]})
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
                "Resource": [
                    f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/*",
                    f"arn:aws:s3:::{bucket}/*/AWSLogs/{account_id}/*",
                ],
                "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))


def _empty_and_delete_bucket(s3, bucket):
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket,
                    Delete={"Objects": [{"Key": o["Key"]} for o in objs]},
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _delete_trail(ct, name):
    """Best-effort teardown: stop logging (if on) then delete the trail."""
    try:
        ct.stop_logging(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise
    try:
        _call(lambda: ct.delete_trail(Name=name))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise


def _trail_arn(ctx, name):
    account = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:cloudtrail:{ctx.region}:{account}:trail/{name}"


def _create_trail(ctx, ct, s3, name, **kwargs):
    """Create a trail (provisioning a policy-ready bucket unless S3BucketName is
    given) and register best-effort teardown of the trail and any bucket made."""
    bucket = kwargs.pop("S3BucketName", None)
    if not bucket:
        bucket = ctx.unique_name("sim2real-behav-ct-bkt-").lower()
        account = ctx.client("sts").get_caller_identity()["Account"]
        _create_trail_bucket(s3, bucket, ctx.region, account)
        ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    params = {
        "Name": name,
        "S3BucketName": bucket,
        "TagsList": [
            {"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"},
        ],
    }
    params.update(kwargs)
    resp = _call(lambda: ct.create_trail(**params))
    ctx.on_cleanup(lambda: _delete_trail(ct, name))
    return resp


def _poll_until(fn, predicate, attempts=10, delay=2.0):
    """Poll fn() until predicate holds, bounding GetEventSelectors read-after-write lag."""
    last = None
    for i in range(attempts):
        last = fn()
        if predicate(last):
            return last
        if i < attempts - 1:
            time.sleep(delay)
    raise AssertionError(f"did not converge after {attempts} attempts, last={last!r}")


CHECK = "put-get-event-selectors-roundtrip"
GROUP = 'trail-config'
SERVICES = ['cloudtrail']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutEventSelectors persists exactly what GetEventSelectors later returns."""
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-ct-trail-")
    _create_trail(ctx, ct, s3, name)

    selectors = [
        {
            "ReadWriteType": "WriteOnly",
            "IncludeManagementEvents": True,
            "DataResources": [],
        }
    ]
    # AWS echoes back each selector with defaults for fields not supplied (e.g. an
    # empty ExcludeManagementEventSources list), so compare against the fully
    # populated form rather than a handful of hand-picked fields.
    expected = [{**selectors[0], "ExcludeManagementEventSources": []}]
    arn = _trail_arn(ctx, name)

    put_resp = _call(
        lambda: ct.put_event_selectors(TrailName=name, EventSelectors=selectors)
    )
    assert put_resp["TrailARN"] == arn, (
        f"expected TrailARN {arn!r}, got {put_resp.get('TrailARN')!r}"
    )
    assert put_resp["EventSelectors"] == expected, (
        f"expected EventSelectors {expected!r}, got {put_resp.get('EventSelectors')!r}"
    )

    # GetEventSelectors can lag PutEventSelectors briefly; bound the wait instead of
    # trusting the very next read.
    got = _poll_until(
        lambda: ct.get_event_selectors(TrailName=name),
        lambda r: r.get("EventSelectors") == expected,
    )
    assert got["TrailARN"] == arn, (
        f"expected TrailARN {arn!r}, got {got.get('TrailARN')!r}"
    )
    assert got["EventSelectors"] == expected, (
        f"expected EventSelectors {expected!r}, got {got.get('EventSelectors')!r}"
    )
    assert got.get("AdvancedEventSelectors", []) == [], (
        f"expected no AdvancedEventSelectors alongside basic selectors, got {got.get('AdvancedEventSelectors')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
