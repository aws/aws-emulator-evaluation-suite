"""session-lastupdatedat-changes-after-update."""
from __future__ import annotations

import time
from datetime import datetime

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "session-lastupdatedat-changes-after-update"
GROUP = "state"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSession advances lastUpdatedAt strictly past the value observed right after creation."""
    client = ctx.client("bedrock-agent-runtime")
    session_id = client.create_session()["sessionId"]

    def _cleanup():
        try:
            client.end_session(sessionIdentifier=session_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        try:
            client.delete_session(sessionIdentifier=session_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    initial = client.get_session(sessionIdentifier=session_id)
    initial_last_updated = initial["lastUpdatedAt"]
    assert isinstance(initial_last_updated, datetime)

    # lastUpdatedAt has second-resolution, so a single UpdateSession call issued immediately
    # after CreateSession can land in the same tick. Poll: retry UpdateSession (each call is a
    # legitimate, observable state change with a distinct metadata value) until GetSession
    # reports a lastUpdatedAt strictly past the initial observation, bounded by a timeout.
    tick = 0
    fetched = None
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
        tick += 1
        client.update_session(sessionIdentifier=session_id, sessionMetadata={"tick": str(tick)})
        fetched = client.get_session(sessionIdentifier=session_id)
        if fetched["lastUpdatedAt"] > initial_last_updated:
            break
        time.sleep(0.5)

    assert fetched is not None
    new_last_updated = fetched["lastUpdatedAt"]
    assert new_last_updated > initial_last_updated, (
        f"lastUpdatedAt did not advance after {tick} update(s): "
        f"{initial_last_updated} -> {new_last_updated}"
    )
    assert fetched["sessionMetadata"] == {"tick": str(tick)}
    assert fetched["createdAt"] == initial["createdAt"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
