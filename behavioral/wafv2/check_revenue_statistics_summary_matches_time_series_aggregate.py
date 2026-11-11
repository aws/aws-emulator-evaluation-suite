"""revenue-statistics-summary-matches-time-series-aggregate."""
from __future__ import annotations

import datetime as dt
from decimal import Decimal

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "revenue-statistics-summary-matches-time-series-aggregate"
GROUP = "data-plane"
SERVICES = ["wafv2"]


def _cloudfront_wafv2_client(ctx):
    """A wafv2 client pinned to us-east-1, where CLOUDFRONT-scope calls are served."""
    return ctx.client("wafv2", region="us-east-1")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetRevenueStatisticsSummary's TotalAmount for a 24h window equals the sum of the
    GetRevenueStatisticsTimeSeries buckets, and on an account without monetization it is a
    zeroed RevenueBreakdown.
    """
    wafv2 = _cloudfront_wafv2_client(ctx)
    scope = "CLOUDFRONT"
    currency = "USDC"
    end = dt.datetime.now(dt.timezone.utc)
    start = end - dt.timedelta(hours=24)
    time_window = {"StartTime": start, "EndTime": end}

    # Monetization cannot be provisioned through any WAFv2 API; a fresh account gets a 200
    # with a zeroed RevenueBreakdown, so a refusal fails rather than skips.
    try:
        summary = wafv2.get_revenue_statistics_summary(
            TimeWindow=time_window, Scope=scope, Currency=currency
        )["RevenueBreakdown"]
    except ClientError as err:
        raise AssertionError(
            "GetRevenueStatisticsSummary refused a fresh account's 24h window with "
            f"{err.response['Error']}; real AWS answers 200 with a zeroed RevenueBreakdown. "
            "Monetization (crypto wallet + settlement pipeline) is not provisionable "
            "through any WAFv2 API, so a check cannot set it up"
        ) from err

    series = wafv2.get_revenue_statistics_time_series(
        StatisticType="DATE_HISTOGRAM",
        TimeWindow=time_window,
        Scope=scope,
        Interval="HOURLY",
        Currency=currency,
    )
    bucket_total = sum(
        (Decimal(p["TotalAmount"]) for p in series["DataPoints"]),
        Decimal("0"),
    )
    summary_total = Decimal(summary["TotalAmount"])
    assert abs(bucket_total - summary_total) <= Decimal("0.01"), (
        f"sum of time-series buckets {bucket_total} != summary total {summary_total}"
    )
    # Without a MonetizationConfig both report exactly zero; a nonzero placeholder on both
    # sides would satisfy the sum identity vacuously.
    assert summary_total == Decimal("0"), f"expected zero revenue, got {summary_total}"
    zeroed = {
        "Currency": summary.get("Currency"),
        "VerifiedAmount": Decimal(summary["VerifiedAmount"]),
        "UnverifiedAmount": Decimal(summary["UnverifiedAmount"]),
        "TotalSettled": summary.get("TotalSettled"),
        "TotalMonetizeServed": summary.get("TotalMonetizeServed"),
    }
    assert zeroed == {
        "Currency": currency, "VerifiedAmount": Decimal("0"), "UnverifiedAmount": Decimal("0"),
        "TotalSettled": 0, "TotalMonetizeServed": 0,
    }, f"expected a zeroed RevenueBreakdown, got {summary!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
