"""list-insights-data-not-enabled-unsupported-operation."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-insights-data-not-enabled-unsupported-operation"
GROUP = "error-semantics"
SERVICES = ["cloudtrail"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On a trail without Insights, GetInsightSelectors answers InsightNotEnabledException with its exact message
    and ListInsightsData returns an empty Events list; an event data store ARN as InsightSource answers
    ValidationException "... is not a valid trail ARN."; after enabling Insights the trail still returns []."""
    ct = ctx.client("cloudtrail")
    trail = _create_minimal_trail(ctx)
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    baseline_code, baseline_message = _error(lambda: ct.get_insight_selectors(TrailName=trail["name"]))
    assert baseline_code == "InsightNotEnabledException", (
        f"expected InsightNotEnabledException, got {baseline_code}"
    )
    assert baseline_message == (
        f"Trail {trail['arn']} does not have Insights enabled. Edit the trail settings to enable "
        "Insights, and then try the operation again."
    ), baseline_message

    # ListInsightsData against the same trail, still with no Insight selectors
    # configured, does not raise -- it returns an empty Events list.
    resp = ct.list_insights_data(InsightSource=trail["arn"], DataType="InsightsEvents")
    assert resp.get("Events") == [], (
        f"expected an empty Events list before Insights were enabled, got {resp.get('Events')}"
    )

    # ListInsightsData rejects an InsightSource that names a resource type it does
    # not support (an event data store ARN, rather than a trail ARN) with a
    # ValidationException -- distinct from the missing-selectors case above, which
    # succeeds with an empty list rather than raising at all.
    non_trail_source = (
        f"arn:aws:cloudtrail:{ctx.region}:{account_id}:eventdatastore/"
        "00000000-0000-0000-0000-000000000000"
    )
    listing_code, listing_message = _error(
        lambda: ct.list_insights_data(InsightSource=non_trail_source, DataType="InsightsEvents")
    )
    assert listing_code == "ValidationException", f"expected ValidationException, got {listing_code}"
    assert listing_message == f"The Insight source {non_trail_source} is not a valid trail ARN.", listing_message

    ct.put_insight_selectors(
        TrailName=trail["name"],
        InsightSelectors=[{"InsightType": "ApiCallRateInsight", "EventCategories": ["Management"]}],
    )
    _wait_until(
        lambda: bool(ct.get_insight_selectors(TrailName=trail["name"])["InsightSelectors"]),
        timeout_s=30.0,
    )

    resp = ct.list_insights_data(InsightSource=trail["arn"], DataType="InsightsEvents")
    assert resp.get("Events") == [], (
        "expected ListInsightsData to remain reachable (still an empty Events list -- no "
        f"anomaly baseline period has elapsed) once Insight selectors are enabled on the "
        f"same trail that was rejected above, got {resp.get('Events')}"
    )


def _error(fn) -> tuple[str, str | None]:
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected success raises,
    so a target accepting a call AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_until(predicate, *, timeout_s: float, interval_s: float = 1.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s")


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    """CloudTrail writes into the trail bucket, so empty it before DeleteBucket."""
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
    s3.delete_bucket(Bucket=bucket)


def _create_minimal_trail(ctx) -> dict[str, Any]:
    s3 = ctx.client("s3")
    ct = ctx.client("cloudtrail")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    bucket = ctx.unique_name("sim2real-ct-trail-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

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
                "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/*",
                "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))

    name = ctx.unique_name("sim2real-ct-trail-")
    resp = ct.create_trail(
        Name=name,
        S3BucketName=bucket,
        IsMultiRegionTrail=False,
        TagsList=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: ct.delete_trail(Name=name))
    return {"name": name, "arn": resp["TrailARN"], "bucket": bucket}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

