"""carbon-emissions-group-by-multiple-dimensions."""
from __future__ import annotations

import datetime as dt

from behavioral_harness import tags

CHECK = "carbon-emissions-group-by-multiple-dimensions"
GROUP = "data-plane"
SERVICES = ["sustainability"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GroupBy=["REGION", "SERVICE"] on GetEstimatedCarbonEmissions causes every
    result's DimensionsValues to carry exactly those two dimension keys together
    (compound grouping), distinct from requesting either dimension alone."""
    sustainability = _sustainability_client(ctx)
    start, end = _carbon_window(36)
    resp = sustainability.get_estimated_carbon_emissions(
        TimePeriod={"Start": start, "End": end},
        GroupBy=["REGION", "SERVICE"],
        MaxResults=5000,
    )
    results = resp["Results"]
    if not results:
        raise AssertionError(
            "account has no estimated carbon emissions data for the last 36 months; "
            "cannot verify compound GroupBy content."
        )
    for r in results:
        assert set(r["DimensionsValues"].keys()) == {"REGION", "SERVICE"}, r["DimensionsValues"]
        assert r["DimensionsValues"]["REGION"] and r["DimensionsValues"]["SERVICE"]


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
