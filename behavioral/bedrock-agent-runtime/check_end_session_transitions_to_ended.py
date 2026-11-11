"""end-session-transitions-to-ended."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "end-session-transitions-to-ended"
GROUP = "state"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """EndSession moves an ACTIVE session to ENDED, and the transition is durable via GetSession."""
    client = ctx.client("bedrock-agent-runtime")
    session_id = client.create_session()["sessionId"]
    ctx.on_cleanup(lambda: client.delete_session(sessionIdentifier=session_id))

    ended = client.end_session(sessionIdentifier=session_id)
    assert ended["sessionStatus"] == "ENDED", f"expected ENDED, got {ended['sessionStatus']}"
    assert ended["sessionId"] == session_id, (
        f"expected sessionId {session_id}, got {ended['sessionId']}"
    )

    deadline = time.monotonic() + 15.0
    status = None
    while time.monotonic() < deadline:
        status = client.get_session(sessionIdentifier=session_id)["sessionStatus"]
        if status == "ENDED":
            break
        time.sleep(1.0)
    assert status == "ENDED", f"expected ENDED, last observed {status}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
