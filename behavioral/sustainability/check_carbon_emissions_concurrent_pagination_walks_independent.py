"""carbon-emissions-concurrent-pagination-walks-independent."""
from __future__ import annotations

import datetime as dt
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "carbon-emissions-concurrent-pagination-walks-independent"
GROUP = "concurrency"
SERVICES = ["sustainability"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two concurrent MaxResults=1 walks of the same GetEstimatedCarbonEmissions query each return exactly
    the entries of one MaxResults=5000 call, without duplicates: a NextToken is scoped to its own walk."""
    sustainability = _sustainability_client(ctx)
    start, end = _carbon_window(36)
    kwargs = dict(TimePeriod={"Start": start, "End": end}, GroupBy=["REGION", "SERVICE"])

    baseline = sustainability.get_estimated_carbon_emissions(MaxResults=5000, **kwargs)
    assert not baseline.get("NextToken"), (
        "single call with MaxResults=5000 unexpectedly paginated; cannot compare against it"
    )
    baseline_keys = sorted(_entry_keys(baseline["Results"]))

    def _walk(_i):
        collected: list = []
        token = None
        pages = 0
        while True:
            pages += 1
            if pages > len(baseline_keys) + 5:
                raise AssertionError("pagination walk did not terminate as expected")
            req = dict(kwargs)
            req["MaxResults"] = 1
            if token:
                req["NextToken"] = token
            page = sustainability.get_estimated_carbon_emissions(**req)
            collected.extend(_entry_keys(page["Results"]))
            token = page.get("NextToken")
            if not token:
                break
        return sorted(collected)

    with ThreadPoolExecutor(max_workers=2) as pool:
        walk_a, walk_b = list(pool.map(_walk, range(2)))

    assert walk_a == baseline_keys, ("concurrent walk A diverged from the baseline", walk_a)
    assert walk_b == baseline_keys, ("concurrent walk B diverged from the baseline", walk_b)
    assert len(walk_a) == len(set(walk_a)), "concurrent walk A produced duplicate entries"
    assert len(walk_b) == len(set(walk_b)), "concurrent walk B produced duplicate entries"


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
