"""carbon-dimension-values-echo-requested-dimension."""
from __future__ import annotations

from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "carbon-dimension-values-echo-requested-dimension"
GROUP = "state"
SERVICES = ["sustainability"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetEstimatedCarbonEmissionsDimensionValues only ever echoes back a Dimension that was
    actually requested, each paired with a non-empty concrete Value."""
    client = _sustainability_client(ctx)
    start, end = _carbon_window(ctx)
    requested = {"REGION", "SERVICE"}

    resp = client.get_estimated_carbon_emissions_dimension_values(
        TimePeriod={"Start": start, "End": end}, Dimensions=list(requested)
    )
    for entry in resp.get("Results", []):
        assert entry["Dimension"] in requested, (
            f"echoed Dimension {entry['Dimension']!r} was never requested; requested={requested}"
        )
        assert isinstance(entry["Value"], str) and len(entry["Value"]) > 0, (
            f"expected a non-empty string Value for Dimension {entry['Dimension']!r}, got {entry.get('Value')!r}"
        )


def _sustainability_client(ctx):
    """AWS Sustainability only accepts requests signed for us-east-1 regardless of the
    harness's shared target region; pin the region on this client only via ctx.client's
    region override, which leaves credential/endpoint wiring untouched on both targets."""
    return ctx.client("sustainability", region="us-east-1")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _month_floor(dt: datetime) -> datetime:
    return dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def _add_months(dt: datetime, n: int) -> datetime:
    total = dt.month - 1 + n
    year = dt.year + total // 12
    month = total % 12 + 1
    return dt.replace(year=year, month=month, day=1, hour=0, minute=0, second=0, microsecond=0)


def _carbon_window(ctx):
    now = _utc_now()
    end = _add_months(_month_floor(now), -3)
    start = _add_months(end, -12)
    return start, end


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
