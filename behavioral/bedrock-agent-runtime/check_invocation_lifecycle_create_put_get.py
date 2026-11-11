"""invocation-lifecycle-create-put-get."""
from __future__ import annotations

import datetime as dt

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invocation-lifecycle-create-put-get"
GROUP = "state-machine"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An invocation and its steps persist in a session and are retrievable after creation."""
    client = ctx.client("bedrock-agent-runtime")

    session_id = client.create_session(tags={"sim2real": CHECK})["sessionId"]
    ctx.on_cleanup(lambda: _safe_delete(client, session_id))

    created_inv = client.create_invocation(
        sessionIdentifier=session_id, description="sim2real behavioral check invocation"
    )
    invocation_id = created_inv["invocationId"]
    assert invocation_id, f"expected CreateInvocation to return a non-empty invocationId, got {invocation_id!r}"

    step_time = dt.datetime.now(dt.timezone.utc)
    put_step = client.put_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepTime=step_time,
        payload={"contentBlocks": [{"text": "the capital of France is Paris"}]},
    )
    step_id = put_step["invocationStepId"]

    got_step = client.get_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepId=step_id,
    )["invocationStep"]
    assert got_step["invocationId"] == invocation_id, (
        f"expected GetInvocationStep to scope to invocationId {invocation_id!r}, "
        f"got {got_step['invocationId']!r}"
    )
    assert got_step["invocationStepId"] == step_id, (
        f"expected GetInvocationStep to return invocationStepId {step_id!r}, "
        f"got {got_step['invocationStepId']!r}"
    )
    assert got_step["payload"]["contentBlocks"][0]["text"] == "the capital of France is Paris", (
        "expected GetInvocationStep to echo back the exact text payload written by PutInvocationStep, "
        f"got {got_step['payload']['contentBlocks'][0].get('text')!r}"
    )

    listed = client.list_invocations(sessionIdentifier=session_id)["invocationSummaries"]
    assert any(inv["invocationId"] == invocation_id for inv in listed), (
        f"expected invocationId {invocation_id!r} to appear in ListInvocations for session "
        f"{session_id!r}, got {[inv['invocationId'] for inv in listed]!r}"
    )


def _safe_delete(client, session_id: str) -> None:
    # DeleteSession rejects an ACTIVE session (ConflictException), so end it first.
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
