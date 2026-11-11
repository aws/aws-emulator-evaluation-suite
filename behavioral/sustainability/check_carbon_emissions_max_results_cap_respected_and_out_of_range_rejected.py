"""carbon-emissions-max-results-cap-respected-and-out-of-range-rejected."""
from __future__ import annotations

import datetime as dt

from behavioral_harness import tags

CHECK = "carbon-emissions-max-results-cap-respected-and-out-of-range-rejected"
GROUP = "pagination"
SERVICES = ["sustainability"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """MaxResults=1 returns at most one entry and any NextToken is 1-2000 characters long; MaxResults=5001,
    above the documented maximum, is refused with ValidationException and its exact message."""
    sustainability = _sustainability_client(ctx)
    start, end = _carbon_window(12)
    resp = sustainability.get_estimated_carbon_emissions(
        TimePeriod={"Start": start, "End": end},
        Granularity="MONTHLY",
        GroupBy=["SERVICE"],
        MaxResults=1,
    )
    assert len(resp["Results"]) <= 1, f"MaxResults=1 but got {len(resp['Results'])} results"
    token = resp.get("NextToken")
    if token is not None:
        assert 1 <= len(token) <= 2000, f"NextToken length {len(token)} outside 1..2000"

    # Distinct negative boundary: MaxResults=5001 exceeds the documented 1..5000 range.
    code, message = _client_error(
        lambda: sustainability.get_estimated_carbon_emissions(
            TimePeriod={"Start": start, "End": end}, MaxResults=5001
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = (
        "1 validation error detected: Value '5001' at 'maxResults' failed to satisfy "
        "constraint: Member must have value less than or equal to 5000"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
