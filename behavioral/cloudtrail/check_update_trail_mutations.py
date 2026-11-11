"""update-trail-mutations."""

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
    """Create a plain S3 bucket (no CloudTrail policy)."""
    kwargs = {"Bucket": bucket}
    # S3's own API quirk, not a region pin of this check: LocationConstraint must be
    # omitted for us-east-1 and is required for every other region.
    if region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    try:
        s3.create_bucket(**kwargs)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            raise
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-owner", "Value": "simparity"}]}
    )


def _create_trail_bucket(s3, bucket, region, account_id):
    """Create an S3 bucket with the policy CloudTrail needs to deliver logs."""
    _create_bucket_only(s3, bucket, region)
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


def _create_trail(ctx, ct, s3, name, **kwargs):
    """Create a trail (provisioning a policy-ready bucket unless S3BucketName is
    given) and register best-effort teardown of the trail and any bucket made."""
    bucket = kwargs.pop("S3BucketName", None)
    if not bucket:
        bucket = ctx.unique_name("sim2real-behav-ct-bkt-").lower()
        account = ctx.client("sts").get_caller_identity()["Account"]
        _create_trail_bucket(s3, bucket, ctx.region, account)
        ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    params = {"Name": name, "S3BucketName": bucket}
    params.update(kwargs)
    params.setdefault("TagsList", [{"Key": "sim2real-owner", "Value": "simparity"}])
    resp = _call(lambda: ct.create_trail(**params))
    ctx.on_cleanup(lambda: _delete_trail(ct, name))
    return resp


CHECK = "update-trail-mutations"
GROUP = 'trail-lifecycle'
SERVICES = ['cloudtrail']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateTrail is a partial update: touched fields change, untouched fields persist."""
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-ct-trail-")
    created = _create_trail(ctx, ct, s3, name)
    bucket = ct.get_trail(Name=name)["Trail"]["S3BucketName"]

    updated = _call(
        lambda: ct.update_trail(
            Name=name,
            IncludeGlobalServiceEvents=False,
            EnableLogFileValidation=True,
            S3KeyPrefix="behav-prefix",
        )
    )
    assert updated["TrailARN"] == created["TrailARN"], (updated.get("TrailARN"), created["TrailARN"])
    assert updated["IncludeGlobalServiceEvents"] is False, updated.get("IncludeGlobalServiceEvents")
    assert updated["LogFileValidationEnabled"] is True, updated.get("LogFileValidationEnabled")

    trail = ct.get_trail(Name=name)["Trail"]
    assert trail["IncludeGlobalServiceEvents"] is False, trail.get("IncludeGlobalServiceEvents")
    assert trail["LogFileValidationEnabled"] is True, trail.get("LogFileValidationEnabled")
    assert trail["S3KeyPrefix"] == "behav-prefix", trail.get("S3KeyPrefix")
    # Untouched configuration survives the partial update.
    assert trail["S3BucketName"] == bucket, (trail.get("S3BucketName"), bucket)
    assert not trail.get("IsMultiRegionTrail"), trail.get("IsMultiRegionTrail")

    # And the mutation is reversible.
    _call(
        lambda: ct.update_trail(
            Name=name, IncludeGlobalServiceEvents=True, EnableLogFileValidation=False
        )
    )
    trail = ct.get_trail(Name=name)["Trail"]
    assert trail["IncludeGlobalServiceEvents"] is True, trail.get("IncludeGlobalServiceEvents")
    assert trail["LogFileValidationEnabled"] is False, trail.get("LogFileValidationEnabled")
    assert trail["S3KeyPrefix"] == "behav-prefix", trail.get("S3KeyPrefix")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
