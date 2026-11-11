"""put-insight-selectors-insufficient-s3-policy-fails."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "put-insight-selectors-insufficient-s3-policy-fails"
GROUP = "error-semantics"
SERVICES = ["cloudtrail"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutInsightSelectors raises InsufficientS3BucketPolicyException once the trail's
    destination S3 bucket has no bucket policy at all (so CloudTrail has no permission to
    write Insights events there), and restoring the policy lets the same call succeed."""
    cloudtrail = ctx.client("cloudtrail")
    s3 = ctx.client("s3")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    bucket = _create_trail_bucket(ctx)
    full_policy = _trail_bucket_policy(bucket, account_id, include_write=True)
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(full_policy))

    trail_name = ctx.unique_name("sim2real-behav-trail-")
    cloudtrail.create_trail(
        Name=trail_name, S3BucketName=bucket, IsMultiRegionTrail=False
    )
    ctx.on_cleanup(
        lambda: _teardown_call(lambda: cloudtrail.delete_trail(Name=trail_name), "TrailNotFoundException")
    )

    # remove the bucket policy entirely so CloudTrail has no permission whatsoever
    # (neither GetBucketAcl nor PutObject) to deliver Insights events
    s3.delete_bucket_policy(Bucket=bucket)

    code, message = _expect_error(
        lambda: cloudtrail.put_insight_selectors(
            TrailName=trail_name,
            InsightSelectors=[{"InsightType": "ApiCallRateInsight"}],
        )
    )
    assert code == "InsufficientS3BucketPolicyException", f"unexpected error code: {code}"
    assert message == f"Incorrect S3 bucket policy is detected for bucket: {bucket}", message

    # Insights were not enabled by the failed call: since Insights were never successfully
    # enabled on this trail, GetInsightSelectors itself reports InsightNotEnabledException
    # rather than an empty selector list.
    get_code, get_message = _expect_error(lambda: cloudtrail.get_insight_selectors(TrailName=trail_name))
    assert get_code == "InsightNotEnabledException", (
        f"expected Insights to remain disabled after the failed call, got {get_code}"
    )
    expected_get_message = (
        f"Trail arn:aws:cloudtrail:{ctx.region}:{ctx.account}:trail/{trail_name} does not have Insights "
        "enabled. Edit the trail settings to enable Insights, and then try the operation again."
    )
    assert get_message == expected_get_message, get_message

    # positive control: restore the full policy, the same call now succeeds
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(full_policy))
    cloudtrail.put_insight_selectors(
        TrailName=trail_name,
        InsightSelectors=[{"InsightType": "ApiCallRateInsight"}],
    )
    # GetInsightSelectors can lag a successful PutInsightSelectors; poll for the expected
    # InsightTypes within a bound.
    # Real AWS augments each returned selector with an "EventCategory" field
    # (currently always "Management") that was never supplied in the
    # PutInsightSelectors request -- the service fills it in as a default.
    # Comparing the raw dicts for exact equality is therefore the wrong
    # assumption; what the check actually cares about is which InsightTypes
    # ended up enabled, so compare on that projection instead.
    enabled = _poll_until(
        lambda: cloudtrail.get_insight_selectors(TrailName=trail_name)["InsightSelectors"],
        lambda selectors: [s.get("InsightType") for s in selectors] == ["ApiCallRateInsight"],
        timeout=180,
        interval=5,
    )
    assert [s.get("InsightType") for s in enabled] == ["ApiCallRateInsight"], enabled


# ===== helpers =====
def _poll_until(fetch, predicate, timeout=30, interval=2):
    import time

    deadline = time.monotonic() + timeout
    result = fetch()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout}s waiting for the predicate; last result: {result!r}"
            )
        time.sleep(interval)
        result = fetch()
    return result


def _teardown_call(fn, *gone_codes):
    """Run a teardown call; a resource already gone (gone_codes) is done, any other error raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] not in gone_codes:
            raise


def _expect_error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message), but RAISE if the call
    unexpectedly succeeds, so an over-permissive target fails as an acceptance, not a code
    mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"call unexpectedly succeeded where a rejection was required: {result!r}")


def _trail_bucket_policy(bucket: str, account_id: str, include_write: bool) -> dict:
    statements = [
        {
            "Sid": "AWSCloudTrailAclCheck",
            "Effect": "Allow",
            "Principal": {"Service": "cloudtrail.amazonaws.com"},
            "Action": "s3:GetBucketAcl",
            "Resource": f"arn:aws:s3:::{bucket}",
        }
    ]
    if include_write:
        statements.append(
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/*",
                "Condition": {
                    "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                },
            }
        )
    return {"Version": "2012-10-17", "Statement": statements}


def _create_trail_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-trail-bkt-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        _teardown_call(lambda: s3.delete_bucket_policy(Bucket=bucket), "NoSuchBucketPolicy")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
