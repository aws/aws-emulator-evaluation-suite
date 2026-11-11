"""dimension-values-invalid-dimension-enum-rejected."""
from __future__ import annotations

import datetime as dt

from behavioral_harness import tags

CHECK = "dimension-values-invalid-dimension-enum-rejected"
GROUP = "overly-permissive"
SERVICES = ["sustainability"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetEstimatedCarbonEmissionsDimensionValues rejects a Dimensions entry that
    is not one of the USAGE_ACCOUNT_ID | REGION | SERVICE enum values, while the
    identical call with a valid Dimension succeeds."""
    sustainability = _sustainability_client(ctx)
    start, end = _carbon_window(6)

    code, message = _error(
        lambda: sustainability.get_estimated_carbon_emissions_dimension_values(
            TimePeriod={"Start": start, "End": end}, Dimensions=["NOT_A_REAL_DIMENSION"]
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = (
        "1 validation error detected: Value '[NOT_A_REAL_DIMENSION]' at 'dimensions' failed to "
        "satisfy constraint: Member must satisfy constraint: [Member must satisfy enum value set: "
        "[USAGE_ACCOUNT_ID, REGION, SERVICE]]"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: identical call shape with a valid Dimension succeeds and echoes
    # only the requested Dimension in every result entry.
    resp = sustainability.get_estimated_carbon_emissions_dimension_values(
        TimePeriod={"Start": start, "End": end}, Dimensions=["REGION"]
    )
    assert "Results" in resp and isinstance(resp["Results"], list), (
        f"expected a Results list in the positive-control response, got {resp!r}"
    )
    for entry in resp["Results"]:
        assert entry["Dimension"] == "REGION", (
            f"expected every result to echo Dimension='REGION', got {entry!r}"
        )


def _sustainability_client(ctx):
    """AWS Sustainability only accepts requests signed for us-east-1 regardless of the
    harness's shared target region; pin the region on this client only via ctx.client's
    region override, which leaves credential/endpoint wiring untouched on both targets."""
    return ctx.client("sustainability", region="us-east-1")


def _error(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
