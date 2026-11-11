"""revenue-statistics-summary-matches-timeseries-aggregation."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal

from behavioral_harness import tags

CHECK = "revenue-statistics-summary-matches-timeseries-aggregation"
GROUP = "server-side"
SERVICES = ["wafv2"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetRevenueStatisticsSummary's TotalAmount equals the sum of GetRevenueStatisticsTimeSeries
    bucket TotalAmounts for the identical CLOUDFRONT scope, one-hour window and currency.

    Reference: https://docs.aws.amazon.com/waf/latest/developerguide/waf-ai-traffic-monetization-getting-started.html
    """
    # CLOUDFRONT-scope revenue endpoints are only valid when signed for us-east-1.
    wafv2 = ctx.client("wafv2", region="us-east-1")
    now = datetime.now(timezone.utc)
    time_window = {"StartTime": now - timedelta(hours=1), "EndTime": now}

    summary = wafv2.get_revenue_statistics_summary(
        TimeWindow=time_window, Scope="CLOUDFRONT", Currency="USDC"
    )["RevenueBreakdown"]
    data_points = wafv2.get_revenue_statistics_time_series(
        StatisticType="DATE_HISTOGRAM",
        TimeWindow=time_window,
        Scope="CLOUDFRONT",
        Interval="HOURLY",
        Currency="USDC",
    )["DataPoints"]

    total_from_summary = Decimal(summary["TotalAmount"])
    total_from_series = sum((Decimal(dp["TotalAmount"]) for dp in data_points), Decimal("0"))

    assert total_from_summary == total_from_series, (summary, data_points)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


