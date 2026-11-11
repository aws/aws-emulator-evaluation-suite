"""list-insights-data-invalid-parameter-rejected."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-insights-data-invalid-parameter-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudtrail"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListInsightsData on an Insights-enabled trail answers ValidationException "The start time must be before
    the end time." when EndTime precedes StartTime, and returns Events for the same call with the range ordered."""
    ct = ctx.client("cloudtrail")
    trail_arn = _create_insight_trail(ctx)

    now = datetime.now(timezone.utc)
    code, message = _error(
        lambda: ct.list_insights_data(
            InsightSource=trail_arn,
            DataType="InsightsEvents",
            StartTime=now,
            EndTime=now - timedelta(hours=1),
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == "The start time must be before the end time.", message

    # Positive control: the operation is not universally broken -- the identical call
    # shape succeeds once the time range is ordered correctly.
    resp = ct.list_insights_data(
        InsightSource=trail_arn,
        DataType="InsightsEvents",
        StartTime=now - timedelta(hours=1),
        EndTime=now,
    )
    assert "Events" in resp


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected success raises, so an
    over-permissive target accepting input AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-ctins-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return bucket


def _delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    try:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _bucket_policy(bucket, trail_arn, account_id):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AWSCloudTrailAclCheck",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:GetBucketAcl",
                    "Resource": f"arn:aws:s3:::{bucket}",
                    "Condition": {"StringEquals": {"aws:SourceArn": trail_arn}},
                },
                {
                    "Sid": "AWSCloudTrailWrite",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/*",
                    "Condition": {
                        "StringEquals": {
                            "s3:x-amz-acl": "bucket-owner-full-control",
                            "aws:SourceArn": trail_arn,
                        }
                    },
                },
            ],
        }
    )


def _create_insight_trail(ctx):
    """Create a trail with Insights enabled, wire its bucket policy, and register cleanup.

    Returns the trail's ARN.
    """
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    ct = ctx.client("cloudtrail")
    name = ctx.unique_name("sim2real-ctins-trail-")
    trail_arn = f"arn:aws:cloudtrail:{ctx.region}:{account_id}:trail/{name}"
    s3.put_bucket_policy(Bucket=bucket, Policy=_bucket_policy(bucket, trail_arn, account_id))

    deadline = time.monotonic() + 20.0
    last_exc = None
    created = False
    while time.monotonic() < deadline:
        try:
            ct.create_trail(Name=name, S3BucketName=bucket)
            created = True
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InsufficientS3BucketPolicyException":
                raise
            last_exc = exc
            time.sleep(2.0)
    if not created:
        raise last_exc
    ctx.on_cleanup(lambda: ct.delete_trail(Name=name))
    ct.add_tags(ResourceId=trail_arn, TagsList=[{"Key": "sim2real", "Value": CHECK}])
    ct.put_insight_selectors(TrailName=name, InsightSelectors=[{"InsightType": "ApiCallRateInsight"}])
    return trail_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
