"""get-connection-status-without-session-returns-notconnected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "get-connection-status-without-session-returns-notconnected"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetConnectionStatus on a managed-node id with no registered agent echoes the Target and
    reports Status notconnected rather than an error."""
    ssm = ctx.client("ssm")
    fake_target = "i-" + uuid.uuid4().hex[:17]

    resp = ssm.get_connection_status(Target=fake_target)

    assert resp["Target"] == fake_target, (
        f"expected GetConnectionStatus to echo the requested target "
        f"{fake_target!r}, got {resp.get('Target')!r}"
    )
    assert resp["Status"] == "notconnected", (
        f"expected notconnected for a managed node with no active session, "
        f"got {resp['Status']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

