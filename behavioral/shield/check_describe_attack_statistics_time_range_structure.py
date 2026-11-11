"""describe-attack-statistics-time-range-structure."""
from __future__ import annotations

from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "describe-attack-statistics-time-range-structure"
GROUP = "read"
SERVICES = ["shield"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAttackStatistics is available to every account regardless of Shield Advanced
    subscription. Per the operation's own documentation, the returned TimeRange is exactly
    midnight UTC one year ago to midnight UTC today — not merely "about a year"."""
    shield = ctx.client("shield")
    resp = shield.describe_attack_statistics()
    time_range = resp["TimeRange"]
    from_dt = time_range["FromInclusive"]
    to_dt = time_range["ToExclusive"]

    today_midnight = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    assert to_dt == today_midnight, (
        f"expected ToExclusive to be midnight UTC today ({today_midnight.isoformat()}), "
        f"got {to_dt.isoformat()}"
    )
    assert from_dt.time() == today_midnight.time(), (
        f"expected FromInclusive to also land on a midnight-UTC boundary, got {from_dt.isoformat()}"
    )
    span_days = (to_dt - from_dt).days
    assert span_days in (365, 366), (
        f"expected FromInclusive exactly one year (365 or 366 days) before ToExclusive, "
        f"got {span_days} days ({from_dt.isoformat()} .. {to_dt.isoformat()})"
    )

    data_items = resp["DataItems"]
    assert isinstance(data_items, list), f"expected DataItems to be a list, got {data_items!r}"
    for item in data_items:
        attack_count = item["AttackCount"]
        assert isinstance(attack_count, int) and attack_count >= 0, (
            f"expected each DataItem's AttackCount to be a non-negative int, got {attack_count!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
