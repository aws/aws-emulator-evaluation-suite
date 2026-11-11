"""list-insights-data-malformed-parameter-rejected."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-insights-data-malformed-parameter-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudtrail"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListInsightsData with StartTime after EndTime answers ValidationException "The start time must be before
    the end time."; the same call on the same Insights-enabled trail without a time range returns an Events list."""
    ct = ctx.client("cloudtrail")
    trail = _create_minimal_trail(ctx)

    ct.put_insight_selectors(
        TrailName=trail["name"],
        InsightSelectors=[{"InsightType": "ApiCallRateInsight", "EventCategories": ["Management"]}],
    )

    now = datetime.now(timezone.utc)
    start_after_end = now
    end_before_start = now - timedelta(hours=1)

    code, message = _error(
        lambda: ct.list_insights_data(
            InsightSource=trail["arn"],
            DataType="InsightsEvents",
            StartTime=start_after_end,
            EndTime=end_before_start,
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == "The start time must be before the end time.", message

    # Positive control: same trail, same InsightSource, no malformed time range -> succeeds.
    resp = ct.list_insights_data(InsightSource=trail["arn"], DataType="InsightsEvents")
    assert isinstance(resp.get("Events"), list), f"expected Events list, got {resp.get('Events')!r}"


def _error(fn) -> tuple[str, str | None]:
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected success raises, so an
    emulator accepting input AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": bucket}]})

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
    deadline = time.monotonic() + 20.0
    resp = None
    while True:
        try:
            resp = ct.create_trail(
                Name=name,
                S3BucketName=bucket,
                IsMultiRegionTrail=False,
                TagsList=[{"Key": "sim2real", "Value": name}],
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InsufficientS3BucketPolicyException" or time.monotonic() > deadline:
                raise
            time.sleep(2.0)
    ctx.on_cleanup(lambda: ct.delete_trail(Name=name))
    return {"name": name, "arn": resp["TrailARN"], "bucket": bucket}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
