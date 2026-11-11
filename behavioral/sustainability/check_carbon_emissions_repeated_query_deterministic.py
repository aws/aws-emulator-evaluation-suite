"""carbon-emissions-repeated-query-deterministic."""
from __future__ import annotations

import datetime as dt

from behavioral_harness import tags

CHECK = "carbon-emissions-repeated-query-deterministic"
GROUP = "consistency"
SERVICES = ["sustainability"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Issuing the identical GetEstimatedCarbonEmissions query twice in a row
    returns identical Results - the same reporting month always yields the same
    ModelVersion and EmissionsValues at a given point in time."""
    sustainability = _sustainability_client(ctx)
    start, end = _carbon_window(6)
    kwargs = {
        "TimePeriod": {"Start": start, "End": end},
        "Granularity": "MONTHLY",
        "GroupBy": ["SERVICE"],
    }
    first = sustainability.get_estimated_carbon_emissions(**kwargs)["Results"]
    if not first:
        raise AssertionError(
            "account has no estimated carbon emissions data for the last 6 months; "
            "GetEstimatedCarbonEmissions only returns data once the account has accrued "
            "AWS usage/billing history - closing this gap requires a test account with "
            "real historical usage, or an emulator that seeds sample carbon data"
        )
    second = sustainability.get_estimated_carbon_emissions(**kwargs)["Results"]
    assert first == second, "identical GetEstimatedCarbonEmissions queries returned different Results"


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
