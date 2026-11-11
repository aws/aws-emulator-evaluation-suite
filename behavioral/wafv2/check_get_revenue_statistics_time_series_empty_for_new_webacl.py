"""get-revenue-statistics-time-series-empty-for-new-webacl."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-revenue-statistics-time-series-empty-for-new-webacl"
GROUP = "data-plane"
SERVICES = ["wafv2"]

_SCOPE = "CLOUDFRONT"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetRevenueStatisticsTimeSeries over a 24-hour window, filtered on a never-created WebACL ARN,
    returns an empty DataPoints list and no NextMarker.
    """
    # CLOUDFRONT-scope WAF operations are only accepted against the us-east-1 endpoint,
    # regardless of the runner's configured region.
    wafv2 = ctx.client("wafv2", region="us-east-1")

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    never_created_webacl_arn = (
        f"arn:aws:wafv2:us-east-1:{account_id}:global/webacl/"
        f"{ctx.unique_name('sim2real-behav-revts-')}/{uuid.uuid4()}"
    )

    now = datetime.now(timezone.utc)
    try:
        resp = wafv2.get_revenue_statistics_time_series(
            StatisticType="DATE_HISTOGRAM",
            Interval="HOURLY",
            TimeWindow={"StartTime": now - timedelta(hours=24), "EndTime": now},
            Scope=_SCOPE,
            Currency="USDC",
            Filters=[{"Name": "WebACLArn", "Values": [never_created_webacl_arn]}],
        )
    except ClientError as err:
        if err.response["Error"]["Code"] == "AccessDeniedException":
            raise AssertionError(
                "this account's automation role has no identity-based policy "
                "allowing wafv2:GetRevenueStatisticsTimeSeries -- CLOUDFRONT-"
                "scope WAF/CloudFront monetization features are gated behind "
                "a separate grant this sandbox role doesn't hold"
            )
        raise

    data_points = resp.get("DataPoints", [])
    assert data_points == [], (
        f"expected an empty DataPoints series for a WebACL ARN that never carried "
        f"monetized traffic, got {data_points!r}"
    )
    next_marker = resp.get("NextMarker")
    assert not next_marker, f"expected no NextMarker on an empty result, got {next_marker!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

