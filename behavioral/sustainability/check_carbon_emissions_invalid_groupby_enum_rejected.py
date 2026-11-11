"""carbon-emissions-invalid-groupby-enum-rejected."""
from __future__ import annotations

from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "carbon-emissions-invalid-groupby-enum-rejected"
GROUP = "overly-permissive"
SERVICES = ["sustainability"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetEstimatedCarbonEmissions rejects a GroupBy entry outside the Dimension enum with
    ValidationException (this is a server-side check: botocore does not validate enum
    membership client-side), while a valid dimension in the same slot succeeds."""
    client = _sustainability_client(ctx)
    start, end = _carbon_window(ctx)

    code, message = _client_error(
        lambda: client.get_estimated_carbon_emissions(
            TimePeriod={"Start": start, "End": end}, GroupBy=["NOT_A_REAL_DIMENSION"]
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = (
        "1 validation error detected: Value '[NOT_A_REAL_DIMENSION]' at 'groupBy' failed to "
        "satisfy constraint: Member must satisfy constraint: [Member must satisfy enum value "
        "set: [USAGE_ACCOUNT_ID, REGION, SERVICE]]"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: a real Dimension enum value in the same slot succeeds.
    resp = client.get_estimated_carbon_emissions(
        TimePeriod={"Start": start, "End": end}, GroupBy=["REGION"]
    )
    results = resp["Results"]
    assert isinstance(results, list), f"expected Results as a list, got {results!r}"
    for result in results:
        assert set(result["DimensionsValues"].keys()) == {"REGION"}, result["DimensionsValues"]


def _sustainability_client(ctx):
    """AWS Sustainability only accepts requests signed for us-east-1 regardless of the
    harness's shared target region; pin the region on this client only via ctx.client's
    region override, which leaves credential/endpoint wiring untouched on both targets."""
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


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
