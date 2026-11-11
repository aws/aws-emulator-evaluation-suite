"""water-unsupported-monthly-granularity-rejected."""
from __future__ import annotations

import datetime as dt

from behavioral_harness import tags

CHECK = "water-unsupported-monthly-granularity-rejected"
GROUP = "overly-permissive"
SERVICES = ["sustainability"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetEstimatedWaterAllocation refuses MONTHLY granularity with ValidationException and its exact
    message, while YEARLY_CALENDAR on the same window returns year-aligned results."""
    sustainability = _sustainability_client(ctx)
    start, end = _water_window(1)

    def _bad():
        return sustainability.get_estimated_water_allocation(
            TimePeriod={"Start": start, "End": end}, Granularity="MONTHLY"
        )

    code, msg = _error_code(_bad)
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = "Invalid input: invalid granularity: only YEARLY_CALENDAR can be requested"
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    # positive control: the supported granularity on the same window must still succeed
    resp = sustainability.get_estimated_water_allocation(
        TimePeriod={"Start": start, "End": end}, Granularity="YEARLY_CALENDAR"
    )
    results = resp["Results"]
    assert isinstance(results, list), f"Results not a list: {results!r}"
    for r in results:
        period = r["TimePeriod"]
        s, e = period["Start"], period["End"]
        assert s.month == 1 and s.day == 1 and e == s.replace(year=s.year + 1), (
            f"YEARLY_CALENDAR result not year-aligned: {s} -> {e}"
        )


def _sustainability_client(ctx):
    """AWS Sustainability accepts only requests signed for us-east-1, so the client is pinned to that region."""
    return ctx.client("sustainability", region="us-east-1")


def _error_code(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an
    over-permissive target accepting a request real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected ValidationException, but the call SUCCEEDED and returned {result!r}")


def _water_window(years_back: int = 3) -> tuple[dt.datetime, dt.datetime]:
    now = dt.datetime.now(dt.timezone.utc)
    end = dt.datetime(now.year, 1, 1, tzinfo=dt.timezone.utc)
    start = dt.datetime(now.year - years_back, 1, 1, tzinfo=dt.timezone.utc)
    return start, end


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
