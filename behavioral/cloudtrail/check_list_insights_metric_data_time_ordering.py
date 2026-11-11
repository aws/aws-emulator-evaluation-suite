"""list-insights-metric-data-time-ordering."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags

CHECK = "list-insights-metric-data-time-ordering"
GROUP = "ordering"
SERVICES = ["cloudtrail"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListInsightsMetricData pairs one Value per Timestamp, FillWithZeros produces exactly
    (window / period) datapoints regardless of whether any real anomaly was ever detected, and
    those datapoints are ascending in time."""

    ct = ctx.client("cloudtrail")
    trail = _create_trail_with_bucket(ctx)
    ct.put_event_selectors(
        TrailName=trail["name"],
        EventSelectors=[{"ReadWriteType": "All", "IncludeManagementEvents": True}],
    )
    ct.put_insight_selectors(
        TrailName=trail["name"],
        InsightSelectors=[{"InsightType": "ApiCallRateInsight", "EventCategories": ["Management"]}],
    )

    end = datetime.now(timezone.utc).replace(microsecond=0)
    period = 300  # valid Period values are 60, 300, 3600 -- anything else is InvalidParameterException
    start = end - timedelta(seconds=period * 6)

    resp = ct.list_insights_metric_data(
        EventSource="iam.amazonaws.com",
        EventName="ConsoleLogin",
        InsightType="ApiCallRateInsight",
        TrailName=trail["name"],
        StartTime=start,
        EndTime=end,
        Period=period,
        DataType="FillWithZeros",
        MaxResults=200,
    )
    timestamps = resp.get("Timestamps", [])
    values = resp.get("Values", [])

    assert len(timestamps) == len(values), (
        f"Timestamps/Values length mismatch: {len(timestamps)} vs {len(values)}"
    )

    expected = int((end - start).total_seconds() // period)
    assert len(timestamps) == expected, (
        f"FillWithZeros should produce exactly {expected} datapoints for a "
        f"{(end - start).total_seconds():.0f}s window at a {period}s period, got {len(timestamps)}: "
        f"{timestamps}"
    )

    assert timestamps == sorted(timestamps), f"Timestamps are not ascending: {timestamps}"


def _account_id(ctx: Any) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_trail_with_bucket(ctx: Any) -> dict[str, str]:
    s3 = ctx.client("s3")
    ct = ctx.client("cloudtrail")
    bucket = ctx.unique_name("sim2real-ct-b-").lower().replace("_", "-")
    trail_name = ctx.unique_name("sim2real-ct-trail-")
    account_id = _account_id(ctx)
    trail_arn = f"arn:aws:cloudtrail:{ctx.region}:{account_id}:trail/{trail_name}"

    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )

    def _cleanup_bucket() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            )
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup_bucket)
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]}
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
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))

    resp = _create_trail_with_retry(ct, trail_name, bucket)
    ctx.on_cleanup(lambda: ct.delete_trail(Name=trail_name))
    return {"name": trail_name, "arn": resp["TrailARN"], "bucket": bucket}


def _create_trail_with_retry(ct: Any, trail_name: str, bucket: str, attempts: int = 5) -> dict:
    last_exc = None
    for _ in range(attempts):
        try:
            return ct.create_trail(
                Name=trail_name,
                S3BucketName=bucket,
                TagsList=[{"Key": "sim2real", "Value": "true"}],
            )
        except ct.exceptions.InsufficientS3BucketPolicyException as exc:  # policy propagation
            last_exc = exc
            time.sleep(5.0)
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
