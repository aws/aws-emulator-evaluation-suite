"""put-invocation-step-round-trip-payload-integrity."""
from __future__ import annotations

import datetime
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-invocation-step-round-trip-payload-integrity"
GROUP = "data-plane"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutInvocationStep persists the exact payload (including multi-block ordering) for
    an invocation step, GetInvocationStep returns it byte-for-byte, and both steps show up
    in ListInvocationSteps for the session."""
    client = ctx.client("bedrock-agent-runtime")

    created = client.create_session()
    session_id = created["sessionId"]
    ctx.on_cleanup(lambda: _safe_delete_session(client, session_id))

    invocation_id = str(uuid.uuid4())
    client.create_invocation(sessionIdentifier=session_id, invocationId=invocation_id)

    step_1_id = str(uuid.uuid4())
    step_1_time = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    step_1_payload = {
        "contentBlocks": [
            {"text": "What is the account balance?"},
            {"text": "The account balance is $42.17."},
        ]
    }
    client.put_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepId=step_1_id,
        invocationStepTime=step_1_time,
        payload=step_1_payload,
    )

    step_2_id = str(uuid.uuid4())
    step_2_time = datetime.datetime(2024, 1, 1, 0, 0, 5, tzinfo=datetime.timezone.utc)
    step_2_payload = {"contentBlocks": [{"text": "Thanks, that answers my question."}]}
    client.put_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepId=step_2_id,
        invocationStepTime=step_2_time,
        payload=step_2_payload,
    )

    got_1 = client.get_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepId=step_1_id,
    )["invocationStep"]
    assert got_1["invocationId"] == invocation_id, (
        f"expected invocationId {invocation_id!r} on step 1, got {got_1.get('invocationId')!r}"
    )
    assert got_1["sessionId"] == session_id, (
        f"expected sessionId {session_id!r} on step 1, got {got_1.get('sessionId')!r}"
    )
    assert got_1["payload"] == step_1_payload, (
        f"expected step 1 payload {step_1_payload!r}, got {got_1.get('payload')!r}"
    )

    got_2 = client.get_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepId=step_2_id,
    )["invocationStep"]
    assert got_2["payload"] == step_2_payload, (
        f"expected step 2 payload {step_2_payload!r}, got {got_2.get('payload')!r}"
    )

    listed = client.list_invocation_steps(
        sessionIdentifier=session_id, invocationIdentifier=invocation_id
    )["invocationStepSummaries"]
    listed_ids = {s["invocationStepId"] for s in listed}
    expected_ids = {step_1_id, step_2_id}
    assert listed_ids == expected_ids, (
        f"expected ListInvocationSteps to return exactly {expected_ids!r}, got {listed_ids!r}"
    )


def _safe_delete_session(client, session_id: str) -> None:
    try:
        status = client.get_session(sessionIdentifier=session_id)["sessionStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    if status == "ACTIVE":
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
