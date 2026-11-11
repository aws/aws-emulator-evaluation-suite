"""put-invocation-step-conflicting-content-rejected."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-invocation-step-conflicting-content-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Reusing an invocationStepId with a different payload gets ConflictException with the exact message
    and leaves the stored payload intact; a new invocationStepId still succeeds."""
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
    original_payload = {"contentBlocks": [{"text": "original-content"}]}
    first = client.put_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepId=step_id,
        invocationStepTime=step_time,
        payload=original_payload,
    )
    assert first["invocationStepId"] == step_id, (
        f"expected first put to echo invocationStepId={step_id!r}, got {first!r}"
    )

    conflicting_payload = {"contentBlocks": [{"text": "different-content"}]}
    code, message = _error(
        lambda: client.put_invocation_step(
            sessionIdentifier=session_id,
            invocationIdentifier=invocation_id,
            invocationStepId=step_id,
            invocationStepTime=step_time,
            payload=conflicting_payload,
        )
    )
    assert code == "ConflictException", (
        f"expected ConflictException re-using invocationStepId with different content, got {code!r}"
    )
    expected_message = (
        f"Combination of Invocation with ID {invocation_id} and Invcoation Step with ID {step_id} "
        f"already exists"
    )
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    # effect absent: the step still holds the ORIGINAL content, compared in full
    got = client.get_invocation_step(
        sessionIdentifier=session_id, invocationIdentifier=invocation_id, invocationStepId=step_id
    )
    assert got["invocationStep"]["payload"] == original_payload, (
        f"expected payload unchanged after rejected conflict, "
        f"expected={original_payload!r} actual={got['invocationStep']['payload']!r}"
    )

    # positive control: a brand new invocationStepId is accepted without conflict
    new_step_id = str(uuid.uuid4())
    new_payload = {"contentBlocks": [{"text": "new-content"}]}
    second = client.put_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepId=new_step_id,
        invocationStepTime=step_time,
        payload=new_payload,
    )
    assert second["invocationStepId"] == new_step_id, (
        f"expected positive-control put to echo invocationStepId={new_step_id!r}, got {second!r}"
    )
    got_new = client.get_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepId=new_step_id,
    )
    assert got_new["invocationStep"]["payload"] == new_payload, (
        f"expected new step's own payload, expected={new_payload!r} "
        f"actual={got_new['invocationStep']['payload']!r}"
    )


def _error(fn):
    """Call fn() and return its error (code, message); raise AssertionError if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the write to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
