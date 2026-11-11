"""dimension-values-echo-requested-dimension."""
from __future__ import annotations

import datetime as dt

from behavioral_harness import tags

CHECK = "dimension-values-echo-requested-dimension"
GROUP = "data-plane"
SERVICES = ["sustainability"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetEstimatedCarbonEmissionsDimensionValues only ever echoes the single
    Dimension that was requested, never a different dimension enum value."""
    sustainability = _sustainability_client(ctx)
    start, end = _carbon_window(6)
    resp = sustainability.get_estimated_carbon_emissions_dimension_values(
        TimePeriod={"Start": start, "End": end},
        Dimensions=["SERVICE"],
    )
    for entry in resp["Results"]:
        assert entry["Dimension"] == "SERVICE", f"unexpected dimension echoed: {entry}"
        assert 0 < len(entry["Value"]) <= 256, f"dimension value out of bounds: {entry}"


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
