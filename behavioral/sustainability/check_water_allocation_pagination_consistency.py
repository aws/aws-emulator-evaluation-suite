"""water-allocation-pagination-consistency."""
from __future__ import annotations

import datetime as dt

from behavioral_harness import tags

CHECK = "water-allocation-pagination-consistency"
GROUP = "pagination"
SERVICES = ["sustainability"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Paging GetEstimatedWaterAllocation with MaxResults=1 returns exactly the entries of one MaxResults=5000
    call, with no duplicates and no drops."""
    sustainability = _sustainability_client(ctx)
    start, end = _water_window(4)
    base_kwargs = dict(TimePeriod={"Start": start, "End": end}, GroupBy=["REGION", "SERVICE"])

    baseline = sustainability.get_estimated_water_allocation(MaxResults=5000, **base_kwargs)
    assert not baseline.get("NextToken"), (
        "single call with MaxResults=5000 unexpectedly paginated; cannot compare against it"
    )
    baseline_keys = _entry_keys(baseline["Results"])

    paged_keys: list = []
    token = None
    pages = 0
    while True:
        pages += 1
        if pages > len(baseline_keys) + 5:
            raise AssertionError("pagination did not terminate within the expected page count")
        req = dict(base_kwargs)
        req["MaxResults"] = 1
        if token:
            req["NextToken"] = token
        page = sustainability.get_estimated_water_allocation(**req)
        paged_keys.extend(_entry_keys(page["Results"]))
        token = page.get("NextToken")
        if not token:
            break

    assert sorted(paged_keys) == sorted(baseline_keys), (paged_keys, baseline_keys)
    assert len(paged_keys) == len(set(paged_keys)), "pagination produced duplicate entries"


def _entry_keys(results):
    return [
        (
            r["TimePeriod"]["Start"].isoformat(),
            r["TimePeriod"]["End"].isoformat(),
            tuple(sorted(r["DimensionsValues"].items())),
        )
        for r in results
    ]


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
