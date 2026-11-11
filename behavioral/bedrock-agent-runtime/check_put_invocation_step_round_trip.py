"""put-invocation-step-round-trip."""
from __future__ import annotations

from datetime import datetime, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-invocation-step-round-trip"
GROUP = "data-plane"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutInvocationStep persists a text payload that GetInvocationStep returns byte-for-byte."""
    client = ctx.client("bedrock-agent-runtime")
    session_id = client.create_session(tags={"env": "test", "owner": "sim2real"})["sessionId"]

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

    invocation_id = client.create_invocation(sessionIdentifier=session_id)["invocationId"]

    step_text = "the quick brown fox jumps over the lazy dog"
    put = client.put_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepTime=datetime.now(timezone.utc),
        payload={"contentBlocks": [{"text": step_text}]},
    )
    step_id = put["invocationStepId"]

    fetched = client.get_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepId=step_id,
    )
    step = fetched["invocationStep"]
    assert step["invocationStepId"] == step_id, f"expected step id {step_id!r}, got {step['invocationStepId']!r}"
    assert step["invocationId"] == invocation_id, f"expected invocation id {invocation_id!r}, got {step['invocationId']!r}"
    assert step["sessionId"] == session_id, f"expected session id {session_id!r}, got {step['sessionId']!r}"
    assert step["payload"]["contentBlocks"] == [{"text": step_text}], (
        f"expected payload text {step_text!r}, got {step['payload']['contentBlocks']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
