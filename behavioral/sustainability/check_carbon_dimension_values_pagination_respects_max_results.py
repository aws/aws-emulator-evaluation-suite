"""carbon-dimension-values-pagination-respects-max-results."""
from __future__ import annotations

from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "carbon-dimension-values-pagination-respects-max-results"
GROUP = "state"
SERVICES = ["sustainability"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Paginating GetEstimatedCarbonEmissionsDimensionValues with MaxResults 1 returns at most one entry
    per page, terminates within a bounded number of pages, and yields exactly the entries of one
    unpaginated call, with no duplicate (Dimension, Value) pair."""
    client = _sustainability_client(ctx)
    start, end = _carbon_window(ctx)
    dimensions = ["REGION", "SERVICE"]

    baseline = client.get_estimated_carbon_emissions_dimension_values(
        TimePeriod={"Start": start, "End": end}, Dimensions=dimensions, MaxResults=5000
    )
    baseline_entries = {(e["Dimension"], e["Value"]) for e in baseline.get("Results", [])}
    assert "NextToken" not in baseline or not baseline["NextToken"], (
        f"single call with MaxResults=5000 unexpectedly paginated: {baseline.get('NextToken')!r}"
    )

    paged_entries: set[tuple[str, str]] = set()
    next_token = None
    for _ in range(len(baseline_entries) + 5):
        kwargs = {"TimePeriod": {"Start": start, "End": end}, "Dimensions": dimensions, "MaxResults": 1}
        if next_token:
            kwargs["NextToken"] = next_token
        page = client.get_estimated_carbon_emissions_dimension_values(**kwargs)
        page_results = page.get("Results", [])
        assert len(page_results) <= 1, page_results
        for entry in page_results:
            key = (entry["Dimension"], entry["Value"])
            assert key not in paged_entries, f"duplicate entry across pages: {key}"
            paged_entries.add(key)
        next_token = page.get("NextToken")
        if not next_token:
            break
    else:
        raise AssertionError("pagination did not terminate within the expected number of pages")

    assert paged_entries == baseline_entries, (paged_entries, baseline_entries)


def _sustainability_client(ctx):
    """AWS Sustainability only accepts requests signed for us-east-1 whatever the target
    region, so this client pins us-east-1 through ctx.client's region override."""
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
