"""put-remove-permission-roundtrip."""
from __future__ import annotations

import json

from behavioral_harness import tags


CHECK = "put-remove-permission-roundtrip"
GROUP = 'permission'
SERVICES = ['events']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutPermission/RemovePermission round-trip is reflected in the bus policy."""
    ev = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")
    ev.create_event_bus(Name=bus, Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda n=bus: ev.delete_event_bus(Name=n))
    granted_principal = "111122223333"
    ev.put_permission(
        EventBusName=bus,
        Action="events:PutEvents",
        Principal=granted_principal,
        StatementId="stmt1",
    )
    desc = ev.describe_event_bus(Name=bus)
    policy = json.loads(desc.get("Policy") or "{}")
    statements = policy.get("Statement", [])
    stmt = next((s for s in statements if s.get("Sid") == "stmt1"), None)
    assert stmt is not None, f"expected statement 'stmt1' in policy, got: {policy}"
    assert stmt.get("Action") == "events:PutEvents", (
        f"expected granted statement's Action to be 'events:PutEvents', got: {stmt}"
    )
    assert granted_principal in json.dumps(stmt.get("Principal")), (
        f"expected granted statement's Principal to reference account "
        f"{granted_principal}, got: {stmt}"
    )

    ev.remove_permission(EventBusName=bus, StatementId="stmt1")
    desc2 = ev.describe_event_bus(Name=bus)
    policy2 = json.loads(desc2.get("Policy") or "{}")
    statements2 = policy2.get("Statement", [])
    assert not any(s.get("Sid") == "stmt1" for s in statements2), (
        f"expected statement 'stmt1' removed from policy, got: {policy2}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
