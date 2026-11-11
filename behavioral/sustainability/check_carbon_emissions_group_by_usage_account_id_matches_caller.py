"""carbon-emissions-group-by-usage-account-id-matches-caller."""
from __future__ import annotations

import datetime as dt

from behavioral_harness import tags

CHECK = "carbon-emissions-group-by-usage-account-id-matches-caller"
GROUP = "data-plane"
SERVICES = ["sustainability"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Grouping GetEstimatedCarbonEmissions by USAGE_ACCOUNT_ID reports the
    caller's own account ID (cross-checked against STS GetCallerIdentity), never
    a different or placeholder account."""
    sustainability = _sustainability_client(ctx)
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    start, end = _carbon_window(24)
    resp = sustainability.get_estimated_carbon_emissions(
        TimePeriod={"Start": start, "End": end},
        GroupBy=["USAGE_ACCOUNT_ID"],
        MaxResults=5000,
    )
    results = resp["Results"]
    if not results:
        raise AssertionError(
            "account has no estimated carbon emissions data for the last 24 months; "
            "cannot verify USAGE_ACCOUNT_ID GroupBy content."
        )
    for r in results:
        assert r["DimensionsValues"]["USAGE_ACCOUNT_ID"] == account_id, r["DimensionsValues"]


def _sustainability_client(ctx):
    """AWS Sustainability only accepts requests signed for us-east-1 regardless of the
    harness's shared target region; pin the region on this client only via ctx.client's
    region override, which leaves credential/endpoint wiring untouched on both targets."""
    return ctx.client("sustainability", region="us-east-1")


def _add_months(base: dt.datetime, months: int) -> dt.datetime:
    m = base.month - 1 + months
    y = base.year + m // 12
    m = m % 12 + 1
    return base.replace(year=y, month=m)


def _month_start(year: int, month: int) -> dt.datetime:
    return dt.datetime(year, month, 1, tzinfo=dt.timezone.utc)


def _carbon_window(months_back: int = 6) -> tuple[dt.datetime, dt.datetime]:
    now = dt.datetime.now(dt.timezone.utc)
    end = _month_start(now.year, now.month)
    start = _add_months(end, -months_back)
    return start, end


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
