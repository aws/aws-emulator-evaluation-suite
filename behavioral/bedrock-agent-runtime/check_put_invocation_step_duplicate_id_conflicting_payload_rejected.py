"""put-invocation-step-duplicate-id-conflicting-payload-rejected."""
from __future__ import annotations

import datetime
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-invocation-step-duplicate-id-conflicting-payload-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Re-using an invocationStepId with a different payload is rejected with
    ConflictException and the originally stored payload is left untouched; a brand-new
    invocationStepId in the same invocation still succeeds (positive control)."""
    client = ctx.client("bedrock-agent-runtime")

    created = client.create_session(tags={"env": "sim2real-check"})
    session_id = created["sessionId"]
    ctx.on_cleanup(lambda: _safe_delete_session(client, session_id))

    invocation_id = str(uuid.uuid4())
    client.create_invocation(sessionIdentifier=session_id, invocationId=invocation_id)

    step_id = str(uuid.uuid4())
    step_time = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    original_payload = {"contentBlocks": [{"text": "original content"}]}
    client.put_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepId=step_id,
        invocationStepTime=step_time,
        payload=original_payload,
    )

    conflicting_payload = {"contentBlocks": [{"text": "different content"}]}
    code, message = _error(
        lambda: client.put_invocation_step(
            sessionIdentifier=session_id,
            invocationIdentifier=invocation_id,
            invocationStepId=step_id,
            invocationStepTime=step_time,
            payload=conflicting_payload,
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected_message = (
        f"Combination of Invocation with ID {invocation_id} and Invcoation Step with ID {step_id} "
        f"already exists"
    )
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    unchanged = client.get_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepId=step_id,
    )["invocationStep"]
    assert unchanged["payload"] == original_payload, (
        f"expected stored payload to remain {original_payload!r}, got {unchanged['payload']!r}"
    )

    other_step_id = str(uuid.uuid4())
    client.put_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepId=other_step_id,
        invocationStepTime=step_time,
        payload=conflicting_payload,
    )
    other_step = client.get_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepId=other_step_id,
    )["invocationStep"]
    assert other_step["payload"] == conflicting_payload, (
        f"expected new step's payload to be {conflicting_payload!r}, got {other_step['payload']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected ConflictException, but the call SUCCEEDED and returned {result!r}")


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
