"""list-attacks-empty-for-time-range."""
from __future__ import annotations

from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "list-attacks-empty-for-time-range"
GROUP = "list"
SERVICES = ["shield"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAttacks over a time window that predates the account/Shield's existence returns an
    empty AttackSummaries list rather than erroring, whether or not Shield Advanced is subscribed."""
    shield = ctx.client("shield")
    start = datetime(2000, 1, 1, tzinfo=timezone.utc)
    end = datetime(2000, 1, 2, tzinfo=timezone.utc)
    resp = shield.list_attacks(
        StartTime={"FromInclusive": start, "ToExclusive": end},
        EndTime={"FromInclusive": start, "ToExclusive": end},
    )
    assert resp["AttackSummaries"] == [], f"expected no attacks in year 2000, got {resp['AttackSummaries']!r}"
    assert resp.get("NextToken") is None, (
        f"expected no pagination token for an empty result, got {resp.get('NextToken')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
