"""carbon-emissions-pagination-respects-max-results."""
from __future__ import annotations

from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "carbon-emissions-pagination-respects-max-results"
GROUP = "state"
SERVICES = ["sustainability"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Paginating GetEstimatedCarbonEmissions with MaxResults=1 yields at most one result per page, ends
    within a bounded page count, and totals as many results as one MaxResults=5000 call."""
    client = _sustainability_client(ctx)
    start, end = _carbon_window(ctx)
    group_by = ["SERVICE"]

    baseline = client.get_estimated_carbon_emissions(
        TimePeriod={"Start": start, "End": end}, GroupBy=group_by, MaxResults=5000
    )
    baseline_count = len(baseline.get("Results", []))
    assert "NextToken" not in baseline or not baseline["NextToken"], (
        f"MaxResults=5000 unexpectedly paginated (NextToken={baseline.get('NextToken')!r}); "
        "cannot use this call as the unpaginated baseline"
    )

    paged_total = 0
    next_token = None
    for _ in range(baseline_count + 5):
        kwargs = {"TimePeriod": {"Start": start, "End": end}, "GroupBy": group_by, "MaxResults": 1}
        if next_token:
            kwargs["NextToken"] = next_token
        page = client.get_estimated_carbon_emissions(**kwargs)
        page_results = page.get("Results", [])
        assert len(page_results) <= 1, page_results
        paged_total += len(page_results)
        next_token = page.get("NextToken")
        if not next_token:
            break
    else:
        raise AssertionError("pagination did not terminate within the expected number of pages")

    assert paged_total == baseline_count, (paged_total, baseline_count)


def _sustainability_client(ctx):
    """AWS Sustainability accepts only requests signed for us-east-1, so the client is pinned to that region."""
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
