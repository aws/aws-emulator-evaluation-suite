"""dimension-values-end-before-start-rejected."""
from __future__ import annotations

import datetime as dt

from behavioral_harness import tags

CHECK = "dimension-values-end-before-start-rejected"
GROUP = "overly-permissive"
SERVICES = ["sustainability"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetEstimatedCarbonEmissionsDimensionValues refuses an End before Start with ValidationException and
    its exact message, and returns Results once Start and End are in order."""
    sustainability = _sustainability_client(ctx)
    start, end = _carbon_window(2)

    def _bad():
        sustainability.get_estimated_carbon_emissions_dimension_values(
            TimePeriod={"Start": end, "End": start}, Dimensions=["SERVICE"]
        )

    code, message = _error(_bad)
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = "Invalid input: invalid time period: start must be before end"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: the correctly ordered window succeeds.
    resp = sustainability.get_estimated_carbon_emissions_dimension_values(
        TimePeriod={"Start": start, "End": end}, Dimensions=["SERVICE"]
    )
    assert "Results" in resp


def _sustainability_client(ctx):
    """AWS Sustainability accepts only requests signed for us-east-1, so the client is pinned to that region."""
    return ctx.client("sustainability", region="us-east-1")


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an over-permissive target accepting input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
