"""put-invocation-step-idempotent-same-content."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-invocation-step-idempotent-same-content"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Retrying PutInvocationStep with the same invocationStepId and identical payload gets
    ConflictException with the exact message and leaves one step; a new step id makes two."""
    client = ctx.client("bedrock-agent-runtime")

    session_id = client.create_session()["sessionId"]
    invocation_id = client.create_invocation(sessionIdentifier=session_id)["invocationId"]

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
    payload = {"contentBlocks": [{"text": "idempotent-content"}]}

    first = client.put_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepId=step_id,
        invocationStepTime=step_time,
        payload=payload,
    )
    assert first["invocationStepId"] == step_id, (
        f"positive control did not echo back invocationStepId {step_id!r}; got {first!r}"
    )

    # retry with the identical id AND identical payload: still rejected as a conflict
    code, message = _error(
        lambda: client.put_invocation_step(
            sessionIdentifier=session_id,
            invocationIdentifier=invocation_id,
            invocationStepId=step_id,
            invocationStepTime=step_time,
            payload=payload,
        )
    )
    assert code == "ConflictException", (
        f"retrying invocationStepId {step_id!r} with byte-identical content was not rejected "
        f"with ConflictException; got {code!r}"
    )
    expected_message = (
        f"Combination of Invocation with ID {invocation_id} and Invcoation Step with ID {step_id} "
        f"already exists"
    )
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    listed = client.list_invocation_steps(
        sessionIdentifier=session_id, invocationIdentifier=invocation_id
    )
    matching = [
        s for s in listed["invocationStepSummaries"] if s["invocationStepId"] == step_id
    ]
    assert len(matching) == 1, (
        f"expected exactly one stored step for invocationStepId {step_id!r} after the "
        f"identical-content retry was rejected, got {matching!r}"
    )

    # positive control: a brand-new invocationStepId is accepted without conflict
    other_step_id = str(uuid.uuid4())
    second = client.put_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepId=other_step_id,
        invocationStepTime=step_time,
        payload=payload,
    )
    assert second["invocationStepId"] == other_step_id, (
        f"positive control did not echo back invocationStepId {other_step_id!r}; got {second!r}"
    )

    listed_again = client.list_invocation_steps(
        sessionIdentifier=session_id, invocationIdentifier=invocation_id
    )
    assert len(listed_again["invocationStepSummaries"]) == 2, (
        f"expected 2 stored steps after the positive-control retry with a new "
        f"invocationStepId, got {len(listed_again['invocationStepSummaries'])}: "
        f"{listed_again['invocationStepSummaries']!r}"
    )


def _error(fn):
    """Call fn() and return its error (code, message); raise AssertionError if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected the identical-content retry to be rejected, but it SUCCEEDED and "
        f"returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
