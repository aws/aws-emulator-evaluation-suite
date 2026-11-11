"""get-minute-usage-returns-expected-types."""
from __future__ import annotations

import datetime as _dt

from behavioral_harness import tags

CHECK = "get-minute-usage-returns-expected-types"
GROUP = "crud"
SERVICES = ["groundstation"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetMinuteUsage for the current month returns the documented numeric/boolean fields, and
    those fields are self-consistent with each other."""
    gs = ctx.client("groundstation")
    now = _dt.datetime.now(_dt.timezone.utc)

    resp = gs.get_minute_usage(month=now.month, year=now.year)

    is_reserved = resp["isReservedMinutesCustomer"]
    allocation = resp["totalReservedMinuteAllocation"]
    upcoming = resp["upcomingMinutesScheduled"]
    total_scheduled = resp["totalScheduledMinutes"]
    remaining = resp["estimatedMinutesRemaining"]

    assert isinstance(is_reserved, bool), (
        f"isReservedMinutesCustomer must be bool, got {type(is_reserved).__name__}: {is_reserved!r}"
    )
    assert isinstance(allocation, int), (
        f"totalReservedMinuteAllocation must be int, got {type(allocation).__name__}: {allocation!r}"
    )
    assert isinstance(upcoming, int), (
        f"upcomingMinutesScheduled must be int, got {type(upcoming).__name__}: {upcoming!r}"
    )
    assert isinstance(total_scheduled, int), (
        f"totalScheduledMinutes must be int, got {type(total_scheduled).__name__}: {total_scheduled!r}"
    )
    assert isinstance(remaining, int), (
        f"estimatedMinutesRemaining must be int, got {type(remaining).__name__}: {remaining!r}"
    )

    assert allocation >= 0, f"totalReservedMinuteAllocation must be non-negative, got {allocation}"
    assert remaining >= 0, f"estimatedMinutesRemaining must be non-negative, got {remaining}"
    assert remaining <= allocation, (
        f"estimatedMinutesRemaining ({remaining}) must not exceed "
        f"totalReservedMinuteAllocation ({allocation}); a customer cannot have more minutes "
        "remaining than were ever allocated"
    )
    assert total_scheduled >= upcoming, (
        f"totalScheduledMinutes ({total_scheduled}) must be >= upcomingMinutesScheduled "
        f"({upcoming}); upcoming minutes are a subset of this month's scheduled minutes"
    )
    if not is_reserved:
        assert allocation == 0, (
            "a customer with isReservedMinutesCustomer=False must report zero "
            f"totalReservedMinuteAllocation, got {allocation}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
