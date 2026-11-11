"""settlement-records-consistent-with-revenue-statistics."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "settlement-records-consistent-with-revenue-statistics"
GROUP = "server-side"
SERVICES = ["wafv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListSettlementRecords and GetRevenueStatistics (TOP_PATHS_BY_REVENUE) agree on activity for
    the same CLOUDFRONT window: equal entry counts, both empty without a MonetizationConfig.

    Reference: https://docs.aws.amazon.com/waf/latest/developerguide/waf-ai-traffic-monetization-getting-started.html
    """
    wafv2 = _wafv2_in_region(ctx, "us-east-1")
    now = datetime.now(timezone.utc)
    time_window = {"StartTime": now - timedelta(hours=1), "EndTime": now}

    settlements = wafv2.list_settlement_records(
        TimeWindow=time_window, Scope="CLOUDFRONT", Currency="USDC"
    )["Settlements"]
    revenue_stats = wafv2.get_revenue_statistics(
        StatisticType="TOP_PATHS_BY_REVENUE",
        TimeWindow=time_window,
        Scope="CLOUDFRONT",
        Currency="USDC",
    )
    path_stats = revenue_stats.get("RevenuePathStatistics", [])

    assert len(settlements) == len(path_stats), (settlements, path_stats)
    # With no MonetizationConfig ever attached, neither endpoint reports placeholder entries.
    assert settlements == [], settlements
    assert path_stats == [], path_stats


def _wafv2_in_region(ctx, region):
    """A wafv2 client pinned to region: CLOUDFRONT-scope calls must be signed for us-east-1."""
    return ctx.client("wafv2", region=region)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


