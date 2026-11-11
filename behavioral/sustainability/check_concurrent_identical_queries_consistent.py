"""concurrent-identical-queries-consistent."""
from __future__ import annotations

import concurrent.futures
import datetime as dt

from behavioral_harness import tags

CHECK = "concurrent-identical-queries-consistent"
GROUP = "concurrency"
SERVICES = ["sustainability"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Firing the same GetEstimatedCarbonEmissions query from several threads at
    once returns the same Results to every caller - reads are not torn or
    randomized under concurrent access."""
    sustainability = _sustainability_client(ctx)
    start, end = _carbon_window(6)
    kwargs = {
        "TimePeriod": {"Start": start, "End": end},
        "Granularity": "MONTHLY",
        "GroupBy": ["SERVICE"],
    }

    def _call():
        return sustainability.get_estimated_carbon_emissions(**kwargs)["Results"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        futures = [pool.submit(_call) for _ in range(5)]
        outcomes = [f.result() for f in futures]

    baseline = outcomes[0]
    for idx, outcome in enumerate(outcomes[1:], start=1):
        assert outcome == baseline, (
            f"concurrent call {idx} returned Results different from call 0's"
        )


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
