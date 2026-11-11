"""dimension-values-pagination-consistency."""
from __future__ import annotations

import datetime as dt

from behavioral_harness import tags

CHECK = "dimension-values-pagination-consistency"
GROUP = "pagination"
SERVICES = ["sustainability"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Paging through GetEstimatedCarbonEmissionsDimensionValues one entry at a
    time (MaxResults=1 with NextToken) returns exactly the same set of (Dimension,
    Value) entries as a single large-page call, with no duplicates and no drops."""
    sustainability = _sustainability_client(ctx)
    start, end = _carbon_window(36)
    base_kwargs = dict(TimePeriod={"Start": start, "End": end}, Dimensions=["SERVICE"])

    baseline = sustainability.get_estimated_carbon_emissions_dimension_values(
        MaxResults=5000, **base_kwargs
    )
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
        page = sustainability.get_estimated_carbon_emissions_dimension_values(**req)
        assert len(page["Results"]) <= 1, (
            "page returned more entries than the requested MaxResults=1",
            page["Results"],
        )
        paged_keys.extend(_entry_keys(page["Results"]))
        token = page.get("NextToken")
        if not token:
            break

    assert sorted(paged_keys) == sorted(baseline_keys), (paged_keys, baseline_keys)
    assert len(paged_keys) == len(set(paged_keys)), "pagination produced duplicate entries"


def _entry_keys(results):
    return [(e["Dimension"], e["Value"]) for e in results]


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
