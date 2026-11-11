"""water-dimension-values-subset-of-groupby-results."""
from __future__ import annotations

import datetime as dt

from behavioral_harness import tags

CHECK = "water-dimension-values-subset-of-groupby-results"
GROUP = "consistency"
SERVICES = ["sustainability"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Every REGION in GetEstimatedWaterAllocation results grouped by REGION is one of the values
    GetEstimatedWaterAllocationDimensionValues reports for the same window."""
    sustainability = _sustainability_client(ctx)
    start, end = _water_window(3)
    dims = sustainability.get_estimated_water_allocation_dimension_values(
        TimePeriod={"Start": start, "End": end},
        Dimensions=["REGION"],
    )
    allowed = {d["Value"] for d in dims["Results"]}
    grouped = sustainability.get_estimated_water_allocation(
        TimePeriod={"Start": start, "End": end},
        Granularity="YEARLY_CALENDAR",
        GroupBy=["REGION"],
    )
    observed = {
        r["DimensionsValues"]["REGION"]
        for r in grouped["Results"]
        if "REGION" in r["DimensionsValues"]
    }
    assert observed <= allowed, (
        f"REGION values grouped in water allocation results {observed} are not a "
        f"subset of the dimension-values endpoint's reported values {allowed}"
    )


def _sustainability_client(ctx):
    """AWS Sustainability accepts only requests signed for us-east-1, so the client is pinned to that region."""
    return ctx.client("sustainability", region="us-east-1")


def _water_window(years_back: int = 3) -> tuple[dt.datetime, dt.datetime]:
    now = dt.datetime.now(dt.timezone.utc)
    end = dt.datetime(now.year, 1, 1, tzinfo=dt.timezone.utc)
    start = dt.datetime(now.year - years_back, 1, 1, tzinfo=dt.timezone.utc)
    return start, end


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
