"""describe-service-updates-and-actions."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-service-updates-and-actions"
GROUP = 'discovery'
SERVICES = ['elasticache']

@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Service updates enumerate with a status, the ServiceUpdateStatus filter actually
    narrows the result to the requested status(es), and update actions filter by an
    unknown replication group returns none."""
    ec = ctx.client("elasticache")
    updates = ec.describe_service_updates()["ServiceUpdates"]
    assert updates, f"DescribeServiceUpdates returned no service updates: {updates!r}"
    for u in updates[:5]:
        assert u.get("ServiceUpdateName"), u
        assert u.get("ServiceUpdateStatus") in ("available", "cancelled", "expired"), u

    seen = {}
    for status in ("available", "cancelled", "expired"):
        filtered = ec.describe_service_updates(ServiceUpdateStatus=[status])[
            "ServiceUpdates"
        ]
        bad = [u for u in filtered if u.get("ServiceUpdateStatus") != status]
        assert not bad, (
            f"ServiceUpdateStatus=[{status!r}] returned entries with a different status: {bad}"
        )
        seen[status] = len(filtered)
    assert any(seen.values()), f"every ServiceUpdateStatus filter returned no updates: {seen}"

    actions = ec.describe_update_actions(
        ReplicationGroupIds=[ctx.unique_name("sim2real-behav-erg-none-")],
    )["UpdateActions"]
    assert actions == [], actions


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
