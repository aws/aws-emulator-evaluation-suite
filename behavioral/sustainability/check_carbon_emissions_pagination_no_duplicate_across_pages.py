"""carbon-emissions-pagination-no-duplicate-across-pages."""
from __future__ import annotations

import datetime as dt

from behavioral_harness import tags

CHECK = "carbon-emissions-pagination-no-duplicate-across-pages"
GROUP = "pagination"
SERVICES = ["sustainability"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Paging through GetEstimatedCarbonEmissions with NextToken never returns the
    same (month, SERVICE) row twice, and pagination terminates within a bounded
    number of pages."""
    sustainability = _sustainability_client(ctx)
    start, end = _carbon_window(12)
    seen: set[tuple] = set()
    token = None
    max_pages = 50
    for page in range(max_pages):
        kwargs = {
            "TimePeriod": {"Start": start, "End": end},
            "Granularity": "MONTHLY",
            "GroupBy": ["SERVICE"],
            "MaxResults": 2,
        }
        if token:
            kwargs["NextToken"] = token
        resp = sustainability.get_estimated_carbon_emissions(**kwargs)
        for item in resp["Results"]:
            key = (item["TimePeriod"]["Start"], item["DimensionsValues"].get("SERVICE"))
            assert key not in seen, f"duplicate row {key} returned across pages"
            seen.add(key)
        token = resp.get("NextToken")
        if not token:
            break
    else:
        raise AssertionError(f"pagination did not terminate within {max_pages} pages")


def _sustainability_client(ctx):
    """AWS Sustainability signs every request for us-east-1 regardless of the harness's
    shared target region; pin the region on this client only via ctx.client's region
    override, which leaves credential/endpoint wiring untouched on both targets."""
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
