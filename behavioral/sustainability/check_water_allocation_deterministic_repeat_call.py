"""water-allocation-deterministic-repeat-call."""
from __future__ import annotations

import datetime as dt

from behavioral_harness import tags

CHECK = "water-allocation-deterministic-repeat-call"
GROUP = "data-plane"
SERVICES = ["sustainability"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two identical GetEstimatedWaterAllocation calls for a settled TimePeriod return the same entries with
    the same AllocationValues and ModelVersion."""
    sustainability = _sustainability_client(ctx)
    start, end = _water_window(4)
    kwargs = dict(TimePeriod={"Start": start, "End": end}, GroupBy=["REGION"], MaxResults=5000)

    resp1 = sustainability.get_estimated_water_allocation(**kwargs)
    resp2 = sustainability.get_estimated_water_allocation(**kwargs)

    by_key1 = {_entry_key(r): r for r in resp1["Results"]}
    by_key2 = {_entry_key(r): r for r in resp2["Results"]}
    assert set(by_key1.keys()) == set(by_key2.keys()), (by_key1.keys(), by_key2.keys())
    for key, r1 in by_key1.items():
        r2 = by_key2[key]
        assert r1["AllocationValues"] == r2["AllocationValues"], (
            key,
            r1["AllocationValues"],
            r2["AllocationValues"],
        )
        assert r1["ModelVersion"] == r2["ModelVersion"], (key, r1["ModelVersion"], r2["ModelVersion"])


def _entry_key(r):
    return (
        r["TimePeriod"]["Start"].isoformat(),
        r["TimePeriod"]["End"].isoformat(),
        tuple(sorted(r["DimensionsValues"].items())),
    )


def _sustainability_client(ctx):
    """AWS Sustainability accepts only requests signed for us-east-1, so the client is pinned to that region."""
    return ctx.client("sustainability", region="us-east-1")


def _water_window(years_back: int = 4) -> tuple[dt.datetime, dt.datetime]:
    now = dt.datetime.now(dt.timezone.utc)
    end = dt.datetime(now.year, 1, 1, tzinfo=dt.timezone.utc)
    start = dt.datetime(now.year - years_back, 1, 1, tzinfo=dt.timezone.utc)
    return start, end


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
