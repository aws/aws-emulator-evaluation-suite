"""carbon-emissions-invalid-emissions-type-rejected."""
from __future__ import annotations

import datetime as dt

from behavioral_harness import tags

CHECK = "carbon-emissions-invalid-emissions-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["sustainability"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetEstimatedCarbonEmissions rejects an EmissionsTypes entry that is not one
    of the documented EmissionsType enum values, while the identical call with a
    valid EmissionsTypes value succeeds."""
    sustainability = _sustainability_client(ctx)
    start, end = _carbon_window(6)

    code, message = _client_error(
        lambda: sustainability.get_estimated_carbon_emissions(
            TimePeriod={"Start": start, "End": end}, EmissionsTypes=["NOT_A_REAL_EMISSIONS_TYPE"]
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = (
        "1 validation error detected: Value '[NOT_A_REAL_EMISSIONS_TYPE]' at 'emissionsTypes' "
        "failed to satisfy constraint: Member must satisfy constraint: [Member must satisfy "
        "enum value set: [TOTAL_SCOPE_1_CARBON_EMISSIONS, TOTAL_SCOPE_3_MBM_CARBON_EMISSIONS, "
        "TOTAL_SCOPE_3_LBM_CARBON_EMISSIONS, TOTAL_SCOPE_2_MBM_CARBON_EMISSIONS, "
        "TOTAL_SCOPE_2_LBM_CARBON_EMISSIONS, TOTAL_MBM_CARBON_EMISSIONS, TOTAL_LBM_CARBON_EMISSIONS]]"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: identical call shape with a valid EmissionsTypes value succeeds.
    resp = sustainability.get_estimated_carbon_emissions(
        TimePeriod={"Start": start, "End": end},
        EmissionsTypes=["TOTAL_SCOPE_1_CARBON_EMISSIONS"],
    )
    assert "Results" in resp and isinstance(resp["Results"], list), (
        f"expected a Results list from the identical call with a valid EmissionsTypes value, got {resp!r}"
    )


def _sustainability_client(ctx):
    """AWS Sustainability only accepts requests signed for us-east-1 regardless of the
    harness's shared target region; pin the region on this client only via ctx.client's
    region override, which leaves credential/endpoint wiring untouched on both targets."""
    return ctx.client("sustainability", region="us-east-1")


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
