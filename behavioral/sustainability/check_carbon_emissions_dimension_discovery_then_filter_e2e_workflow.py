"""carbon-emissions-dimension-discovery-then-filter-e2e-workflow."""
from __future__ import annotations

import datetime as dt

from behavioral_harness import tags

CHECK = "carbon-emissions-dimension-discovery-then-filter-e2e-workflow"
GROUP = "data-plane"
SERVICES = ["sustainability"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """FilterBy actually narrows GetEstimatedCarbonEmissions results to the
    requested SERVICE dimension value - it is not a no-op accepted-but-ignored
    parameter."""
    sustainability = _sustainability_client(ctx)
    start, end = _carbon_window(6)
    dims = sustainability.get_estimated_carbon_emissions_dimension_values(
        TimePeriod={"Start": start, "End": end},
        Dimensions=["SERVICE"],
    )
    values = [d["Value"] for d in dims["Results"]]
    if not values:
        raise AssertionError(
            "account has no SERVICE usage dimension values for the last 6 months; "
            "cannot verify FilterBy narrowing without a concrete filter value"
        )
    target = values[0]
    resp = sustainability.get_estimated_carbon_emissions(
        TimePeriod={"Start": start, "End": end},
        Granularity="MONTHLY",
        GroupBy=["SERVICE"],
        FilterBy={"Dimensions": {"SERVICE": [target]}},
    )
    results = resp["Results"]
    assert results, f"FilterBy on known-present value {target!r} returned no results"
    for item in results:
        assert item["DimensionsValues"]["SERVICE"] == target, (
            f"FilterBy={target!r} leaked unrelated SERVICE value {item['DimensionsValues']}"
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
