"""get-invocation-step-wrong-invocation-scope-rejected."""
from __future__ import annotations

from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-invocation-step-wrong-invocation-scope-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An invocationStepId is scoped to its own invocation: fetching it under a sibling invocation 404s."""
    client = ctx.client("bedrock-agent-runtime")
    session_id = client.create_session(tags={"simparity-check": CHECK})["sessionId"]
    ctx.on_cleanup(lambda: _safe_end_and_delete(ctx, session_id))

    invocation_a = client.create_invocation(sessionIdentifier=session_id)["invocationId"]
    invocation_b = client.create_invocation(sessionIdentifier=session_id)["invocationId"]
    assert invocation_a != invocation_b, (
        f"expected distinct invocation ids, got a={invocation_a!r} b={invocation_b!r}"
    )

    step_id = client.put_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_a,
        invocationStepTime=datetime.now(timezone.utc),
        payload={"contentBlocks": [{"text": "belongs to invocation A"}]},
    )["invocationStepId"]

    # break exactly one thing: look up A's step through sibling invocation B's scope
    code, message = _error(
        lambda: client.get_invocation_step(
            sessionIdentifier=session_id,
            invocationIdentifier=invocation_b,
            invocationStepId=step_id,
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for cross-invocation scope, got {code!r}"
    )
    expected_message = (
        f"Combination of Invocation with ID {invocation_b} and Invcoation Step with ID {step_id} "
        f"not found"
    )
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    # positive control: the step is still fetchable, unharmed, through its real invocation A
    fetched = client.get_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_a,
        invocationStepId=step_id,
    )["invocationStep"]
    actual_text = fetched["payload"]["contentBlocks"][0]["text"]
    assert actual_text == "belongs to invocation A", (
        f"expected step payload text 'belongs to invocation A', got {actual_text!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _safe_end_and_delete(ctx, session_id: str) -> None:
    client = ctx.client("bedrock-agent-runtime")
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
