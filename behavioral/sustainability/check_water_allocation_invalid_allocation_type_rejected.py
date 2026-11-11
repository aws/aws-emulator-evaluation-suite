"""water-allocation-invalid-allocation-type-rejected."""
from __future__ import annotations

from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "water-allocation-invalid-allocation-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["sustainability"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetEstimatedWaterAllocation rejects an AllocationTypes entry outside the
    WaterAllocationType enum with ValidationException, while the sole real enum value
    (TOTAL_WATER_WITHDRAWALS) in the same slot succeeds."""
    client = _sustainability_client(ctx)
    start, end = _water_window(ctx)

    code, message = _error(
        lambda: client.get_estimated_water_allocation(
            TimePeriod={"Start": start, "End": end}, AllocationTypes=["NOT_A_REAL_ALLOCATION_TYPE"]
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = (
        "1 validation error detected: Value '[NOT_A_REAL_ALLOCATION_TYPE]' at 'allocationTypes' "
        "failed to satisfy constraint: Member must satisfy constraint: [Member must satisfy enum "
        "value set: [TOTAL_WATER_WITHDRAWALS]]"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: the real enum value in the same slot succeeds.
    resp = client.get_estimated_water_allocation(
        TimePeriod={"Start": start, "End": end}, AllocationTypes=["TOTAL_WATER_WITHDRAWALS"]
    )
    for result in resp["Results"]:
        keys = set(result["AllocationValues"].keys())
        assert keys == {"TOTAL_WATER_WITHDRAWALS"}, f"expected {{'TOTAL_WATER_WITHDRAWALS'}}, got {keys!r}"


def _sustainability_client(ctx):
    """AWS Sustainability only accepts requests signed for us-east-1 regardless of the
    harness's shared target region; pin the region on this client only via ctx.client's
    region override, which leaves credential/endpoint wiring untouched on both targets."""
    return ctx.client("sustainability", region="us-east-1")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _year_floor(dt: datetime) -> datetime:
    return dt.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)


def _water_window(ctx):
    now = _utc_now()
    end = _year_floor(now).replace(year=_year_floor(now).year - 1)
    start = end.replace(year=end.year - 2)
    return start, end


def _error(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
