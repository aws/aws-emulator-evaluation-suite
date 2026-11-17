"""update-trail-second-bucket-then-unpolicied-third-bucket-refused."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-trail-second-bucket-then-unpolicied-third-bucket-refused"
GROUP = "error-semantics"
SERVICES = ["cloudtrail", "s3"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateTrail re-points a trail at another bucket that grants CloudTrail delivery and turns
    global service events off, as UpdateTrail, GetTrail and DescribeTrails all report; re-pointing
    it at a bucket with no policy is refused InsufficientS3BucketPolicyException naming that bucket."""
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")

    first_bucket = _create_policied_bucket(ctx, s3)
    trail_name = ctx.unique_name("sim2real-behav-ct-trail-")
    # A freshly written bucket policy is eventually consistent, so the trail-policy
    # validation CreateTrail/UpdateTrail perform can transiently see it as insufficient.
    _retrying(
        lambda: ct.create_trail(
            Name=trail_name, S3BucketName=first_bucket, IncludeGlobalServiceEvents=True
        )
    )
    ctx.on_cleanup(_teardown(lambda: ct.delete_trail(Name=trail_name), "TrailNotFoundException"))

    second_bucket = _create_policied_bucket(ctx, s3)
    updated = _retrying(
        lambda: ct.update_trail(
            Name=trail_name, S3BucketName=second_bucket, IncludeGlobalServiceEvents=False
        )
    )
    assert updated["S3BucketName"] == second_bucket, updated["S3BucketName"]
    assert updated["IncludeGlobalServiceEvents"] is False, updated["IncludeGlobalServiceEvents"]

    trail = ct.get_trail(Name=trail_name)["Trail"]
    assert trail["S3BucketName"] == second_bucket, trail["S3BucketName"]
    assert trail["IncludeGlobalServiceEvents"] is False, trail["IncludeGlobalServiceEvents"]
    described = _describe(ct, trail_name)
    assert described["S3BucketName"] == second_bucket, described["S3BucketName"]
    assert described["IncludeGlobalServiceEvents"] is False, described["IncludeGlobalServiceEvents"]

    third_bucket = ctx.unique_name("sim2real-behav-ct-bkt-").lower()
    _create_bucket_only(ctx, s3, third_bucket)

    _REFUSAL = (
        "InsufficientS3BucketPolicyException",
        f"Incorrect S3 bucket policy is detected for bucket: {third_bucket}",
    )
    expect_error(
        lambda: ct.update_trail(Name=trail_name, S3BucketName=third_bucket), *_REFUSAL
    )

    trail = ct.get_trail(Name=trail_name)["Trail"]
    assert trail["S3BucketName"] == second_bucket, trail["S3BucketName"]
    assert trail["IncludeGlobalServiceEvents"] is False, trail["IncludeGlobalServiceEvents"]
    described = _describe(ct, trail_name)
    assert described["S3BucketName"] == second_bucket, described["S3BucketName"]
    assert described["IncludeGlobalServiceEvents"] is False, described["IncludeGlobalServiceEvents"]


def _retrying(fn, attempts: int = 7):
    """Retry fn() on CloudTrail's transient bucket-policy-propagation lag."""
    import time

    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InsufficientS3BucketPolicyException" or i == attempts - 1:
                raise
            last = exc
            time.sleep(2.0 * (i + 1))
    raise last


def expect_error(fn, code: str, message: str) -> None:
    """Call fn(); assert it raises exactly (code, message), never a weaker check."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        assert error.get("Code") == code, error.get("Code")
        assert error.get("Message") == message, error.get("Message")
        return
    raise AssertionError(f"call unexpectedly succeeded where a rejection was required: {result!r}")


def _describe(ct, name: str) -> dict:
    for trail in ct.describe_trails(includeShadowTrails=True)["trailList"]:
        if trail["Name"] == name:
            return trail
    raise AssertionError(f"DescribeTrails does not list {name!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_bucket_only(ctx, s3, bucket: str) -> None:
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)


def _create_policied_bucket(ctx, s3) -> str:
    """A bucket with the CloudTrail delivery policy CreateTrail/UpdateTrail require."""
    bucket = ctx.unique_name("sim2real-behav-ct-bkt-").lower()
    _create_bucket_only(ctx, s3, bucket)
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
                    f"arn:aws:s3:::{bucket}/AWSLogs/{ctx.account}/*",
                    f"arn:aws:s3:::{bucket}/*/AWSLogs/{ctx.account}/*",
                ],
                "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))

    def _cleanup_policy() -> None:
        _teardown(lambda: s3.delete_bucket_policy(Bucket=bucket), "NoSuchBucketPolicy")()

    ctx.on_cleanup(_cleanup_policy)
    return bucket


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
