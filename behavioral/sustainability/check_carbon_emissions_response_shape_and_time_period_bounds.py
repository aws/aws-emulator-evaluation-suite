"""carbon-emissions-response-shape-and-time-period-bounds."""
from __future__ import annotations

import datetime as dt
import re

from behavioral_harness import tags

CHECK = "carbon-emissions-response-shape-and-time-period-bounds"
GROUP = "data-plane"
SERVICES = ["sustainability"]

_MODEL_VERSION_RE = re.compile(r"^v\d+\.\d+\.\d+")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Each returned EstimatedCarbonEmissions result stays within the requested
    TimePeriod window and carries a valid semver ModelVersion string."""
    sustainability = _sustainability_client(ctx)
    start, end = _carbon_window(6)
    resp = sustainability.get_estimated_carbon_emissions(
        TimePeriod={"Start": start, "End": end},
        Granularity="MONTHLY",
    )
    results = resp["Results"]
    if not results:
        raise AssertionError(
            "account has no estimated carbon emissions data for the last 6 months; "
            "GetEstimatedCarbonEmissions only returns data once the account has accrued "
            "AWS usage/billing history - closing this gap requires a test account with "
            "real historical usage, or an emulator that seeds sample carbon data"
        )
    for item in results:
        tp = item["TimePeriod"]
        assert tp["Start"] >= start and tp["End"] <= end, (
            f"result TimePeriod {tp} falls outside requested window {start}..{end}"
        )
        assert _MODEL_VERSION_RE.match(item["ModelVersion"]), (
            f"ModelVersion {item['ModelVersion']!r} is not a valid semver-style string"
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
