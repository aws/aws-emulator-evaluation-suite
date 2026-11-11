"""duplicate-invocation-id-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicate-invocation-id-rejected"
GROUP = "server-side"
SERVICES = ["bedrock-agent-runtime"]


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected the duplicate CreateInvocation to be rejected, but it SUCCEEDED "
        f"and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateInvocation with an invocationId already in the session gets ConflictException "Invocation
    with ID <id> already exists" and adds nothing; a fresh id succeeds, leaving exactly 2 invocations."""
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

    fixed_invocation_id = str(uuid.uuid4())
    created = client.create_invocation(
        sessionIdentifier=session_id, invocationId=fixed_invocation_id
    )
    assert created["invocationId"] == fixed_invocation_id, (
        f"expected the positive control to echo invocationId {fixed_invocation_id!r}, "
        f"got {created['invocationId']!r}"
    )

    code, message = _error(
        lambda: client.create_invocation(
            sessionIdentifier=session_id, invocationId=fixed_invocation_id
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected_message = f"Invocation with ID {fixed_invocation_id} already exists"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: exactly one invocation with that id exists, not two.
    invocations = client.list_invocations(sessionIdentifier=session_id)["invocationSummaries"]
    matching = [inv for inv in invocations if inv["invocationId"] == fixed_invocation_id]
    assert len(matching) == 1, (
        f"expected exactly one invocation with id {fixed_invocation_id}, found "
        f"{len(matching)} (full list: {invocations})"
    )

    # Positive control: a fresh, distinct invocationId in the same session
    # is accepted normally.
    new_invocation_id = str(uuid.uuid4())
    created_2 = client.create_invocation(
        sessionIdentifier=session_id, invocationId=new_invocation_id
    )
    assert created_2["invocationId"] == new_invocation_id, (
        f"expected the fresh-id positive control to echo invocationId {new_invocation_id!r}, "
        f"got {created_2['invocationId']!r}"
    )

    invocations_after = client.list_invocations(sessionIdentifier=session_id)[
        "invocationSummaries"
    ]
    all_ids = {inv["invocationId"] for inv in invocations_after}
    assert {fixed_invocation_id, new_invocation_id} <= all_ids, (
        f"expected both {fixed_invocation_id!r} and {new_invocation_id!r} in the session's "
        f"invocation list, got {all_ids!r}"
    )
    assert len(invocations_after) == 2, (
        f"expected exactly 2 invocations total, found {len(invocations_after)}: {invocations_after}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
