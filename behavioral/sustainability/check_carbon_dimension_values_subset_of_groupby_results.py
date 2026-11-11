"""carbon-dimension-values-subset-of-groupby-results."""
from __future__ import annotations

import datetime as dt

from behavioral_harness import tags

CHECK = "carbon-dimension-values-subset-of-groupby-results"
GROUP = "consistency"
SERVICES = ["sustainability"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Every SERVICE value that appears in GetEstimatedCarbonEmissions results
    (grouped by SERVICE) must be one of the values GetEstimatedCarbonEmissionsDimensionValues
    reports as available for the same account and time window."""
    sustainability = _sustainability_client(ctx)
    start, end = _carbon_window(6)
    dims = sustainability.get_estimated_carbon_emissions_dimension_values(
        TimePeriod={"Start": start, "End": end},
        Dimensions=["SERVICE"],
    )
    allowed = {d["Value"] for d in dims["Results"]}
    grouped = sustainability.get_estimated_carbon_emissions(
        TimePeriod={"Start": start, "End": end},
        Granularity="MONTHLY",
        GroupBy=["SERVICE"],
    )
    observed = {
        r["DimensionsValues"]["SERVICE"]
        for r in grouped["Results"]
        if "SERVICE" in r["DimensionsValues"]
    }
    if not observed:
        raise AssertionError(
            "account has no SERVICE-grouped carbon emissions data for the last 6 "
            "months; the subset relationship is untestable without an observed side"
        )
    assert observed <= allowed, (
        f"SERVICE values grouped in emissions results {observed} are not a subset "
        f"of the dimension-values endpoint's reported values {allowed}"
    )


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
