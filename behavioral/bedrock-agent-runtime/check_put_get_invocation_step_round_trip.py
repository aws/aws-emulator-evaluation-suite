"""put-get-invocation-step-round-trip."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-get-invocation-step-round-trip"
GROUP = "data-plane"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutInvocationStep persists a text content block, and GetInvocationStep returns the exact
    same payload bytes back (session/invocation/step identifiers all round-trip correctly)."""
    client = ctx.client("bedrock-agent-runtime")

    session_id = client.create_session()["sessionId"]
    invocation_id = str(uuid.uuid4())
    client.create_invocation(sessionIdentifier=session_id, invocationId=invocation_id)

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

    step_id = str(uuid.uuid4())
    step_time = datetime.now(timezone.utc)
    text = "What is the weather forecast for Seattle tomorrow?"
    put_resp = client.put_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepId=step_id,
        invocationStepTime=step_time,
        payload={"contentBlocks": [{"text": text}]},
    )
    assert put_resp["invocationStepId"] == step_id, (
        f"expected PutInvocationStep to echo the client-supplied step id {step_id!r}, "
        f"got {put_resp['invocationStepId']!r}"
    )

    got = client.get_invocation_step(
        sessionIdentifier=session_id, invocationIdentifier=invocation_id, invocationStepId=step_id
    )
    step = got["invocationStep"]
    assert step["invocationStepId"] == step_id, (
        f"expected invocationStepId {step_id!r}, got {step['invocationStepId']!r}"
    )
    assert step["invocationId"] == invocation_id, (
        f"expected invocationId {invocation_id!r}, got {step['invocationId']!r}"
    )
    assert step["sessionId"] == session_id, (
        f"expected sessionId {session_id!r}, got {step['sessionId']!r}"
    )
    assert step["payload"]["contentBlocks"] == [{"text": text}], (
        f"expected payload contentBlocks {[{'text': text}]!r}, "
        f"got {step['payload']['contentBlocks']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
