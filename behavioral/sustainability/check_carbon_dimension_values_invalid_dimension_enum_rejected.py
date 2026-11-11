"""carbon-dimension-values-invalid-dimension-enum-rejected."""
from __future__ import annotations

from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "carbon-dimension-values-invalid-dimension-enum-rejected"
GROUP = "overly-permissive"
SERVICES = ["sustainability"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetEstimatedCarbonEmissionsDimensionValues rejects a Dimensions entry outside the
    Dimension enum with ValidationException, while a real enum value in the same slot
    succeeds and echoes only that dimension in the results."""
    client = _sustainability_client(ctx)
    start, end = _carbon_window(ctx)

    code, message = _error(
        lambda: client.get_estimated_carbon_emissions_dimension_values(
            TimePeriod={"Start": start, "End": end}, Dimensions=["NOT_A_REAL_DIMENSION"]
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        "1 validation error detected: Value '[NOT_A_REAL_DIMENSION]' at 'dimensions' failed to "
        "satisfy constraint: Member must satisfy constraint: [Member must satisfy enum value set: "
        "[USAGE_ACCOUNT_ID, REGION, SERVICE]]"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: a real Dimension enum value in the same slot succeeds.
    resp = client.get_estimated_carbon_emissions_dimension_values(
        TimePeriod={"Start": start, "End": end}, Dimensions=["REGION"]
    )
    # Real AWS may report no carbon-emissions history at all for a new account with no usage history, so
    # Results can legitimately be empty here; require the key itself (a malformed response
    # missing it entirely is not the same thing) and check any entries it does contain.
    results = resp["Results"]
    for entry in results:
        assert entry["Dimension"] == "REGION", f"expected Dimension 'REGION', got {entry['Dimension']!r}"


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


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
