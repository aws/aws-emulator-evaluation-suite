"""list-insights-metric-data-reflects-dashboard-activity."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags

CHECK = "list-insights-metric-data-reflects-dashboard-activity"
GROUP = "telemetry"
SERVICES = ["cloudtrail"]


@tags("axis:happy-path", "cap:c2", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """With Insights enabled, ListInsightsMetricData FillWithZeros returns exactly window/period
    datapoints (a wider window returns more), and NonZeroData never exceeds that bucket count."""
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

    end_time = datetime.now(timezone.utc).replace(microsecond=0)
    period = 300

    narrow_start = end_time - timedelta(seconds=1500)  # 5 buckets of 300s
    narrow = ct.list_insights_metric_data(
        EventSource="iam.amazonaws.com",
        EventName="ConsoleLogin",
        InsightType="ApiCallRateInsight",
        TrailName=trail["name"],
        StartTime=narrow_start,
        EndTime=end_time,
        Period=period,
        DataType="FillWithZeros",
    )
    expected_narrow = int((end_time - narrow_start).total_seconds() // period)
    assert len(narrow["Timestamps"]) == expected_narrow, narrow["Timestamps"]
    assert len(narrow["Values"]) == expected_narrow, narrow["Values"]

    wide_start = end_time - timedelta(seconds=3000)  # 10 buckets of 300s
    wide = ct.list_insights_metric_data(
        EventSource="iam.amazonaws.com",
        EventName="ConsoleLogin",
        InsightType="ApiCallRateInsight",
        TrailName=trail["name"],
        StartTime=wide_start,
        EndTime=end_time,
        Period=period,
        DataType="FillWithZeros",
    )
    expected_wide = int((end_time - wide_start).total_seconds() // period)
    assert len(wide["Timestamps"]) == expected_wide, wide["Timestamps"]
    assert expected_wide != expected_narrow, (expected_wide, expected_narrow)
    assert len(wide["Timestamps"]) != len(narrow["Timestamps"]), (
        f"wide window returned {len(wide['Timestamps'])} datapoints, "
        f"narrow window returned {len(narrow['Timestamps'])}; a wider window must "
        f"produce proportionally more, not the same fixed count"
    )

    nonzero = ct.list_insights_metric_data(
        EventSource="iam.amazonaws.com",
        EventName="ConsoleLogin",
        InsightType="ApiCallRateInsight",
        TrailName=trail["name"],
        StartTime=narrow_start,
        EndTime=end_time,
        Period=period,
        DataType="NonZeroData",
    )
    assert len(nonzero["Timestamps"]) <= expected_narrow, (
        f"NonZeroData returned {len(nonzero['Timestamps'])} datapoints, more than the "
        f"{expected_narrow} buckets the narrow window can hold"
    )


def _account_id(ctx: Any) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_trail_with_bucket(ctx: Any) -> dict[str, str]:
    s3 = ctx.client("s3")
    ct = ctx.client("cloudtrail")
    bucket = ctx.unique_name("sim2real-ct-b-").lower().replace("_", "-")
    trail_name = ctx.unique_name("sim2real-ct-trail-")
    account_id = _account_id(ctx)
    trail_arn = f"arn:aws:cloudtrail:{ctx.region}:{account_id}:trail/{trail_name}"

    if ctx.region == "us-east-1":  # S3 CreateBucket rejects an explicit LocationConstraint here
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
            return ct.create_trail(Name=trail_name, S3BucketName=bucket)
        except ct.exceptions.InsufficientS3BucketPolicyException as exc:  # policy propagation
            last_exc = exc
            time.sleep(5.0)
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
