"""create-invocation-duplicate-id-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-invocation-duplicate-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateInvocation with an invocationId already in the session gets ConflictException "Invocation
    with ID <id> already exists" and leaves one invocation for it; a fresh id still succeeds."""
    client = ctx.client("bedrock-agent-runtime")

    created = client.create_session(tags={"sim2real:managed": "true"})
    session_id = created["sessionId"]
    ctx.on_cleanup(lambda: _safe_delete_session(client, session_id))

    invocation_id = str(uuid.uuid4())
    first = client.create_invocation(
        sessionIdentifier=session_id, invocationId=invocation_id, description="first"
    )
    assert first["invocationId"] == invocation_id, (
        f"expected CreateInvocation to echo {invocation_id!r}, got {first['invocationId']!r}"
    )

    code, message = _error(
        lambda: client.create_invocation(
            sessionIdentifier=session_id, invocationId=invocation_id, description="second"
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected_message = f"Invocation with ID {invocation_id} already exists"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    summaries = client.list_invocations(sessionIdentifier=session_id)["invocationSummaries"]
    matching = [s for s in summaries if s["invocationId"] == invocation_id]
    assert len(matching) == 1, (
        f"expected exactly one invocation for {invocation_id!r}, found {len(matching)}: {summaries}"
    )

    other_invocation_id = str(uuid.uuid4())
    second = client.create_invocation(
        sessionIdentifier=session_id, invocationId=other_invocation_id
    )
    assert second["invocationId"] == other_invocation_id, (
        f"expected CreateInvocation to echo {other_invocation_id!r}, got {second['invocationId']!r}"
    )
    all_ids = {
        s["invocationId"]
        for s in client.list_invocations(sessionIdentifier=session_id)["invocationSummaries"]
    }
    assert all_ids == {invocation_id, other_invocation_id}, (
        f"expected exactly {{{invocation_id!r}, {other_invocation_id!r}}}, got {all_ids!r}"
    )


def _error(fn):
    """Call fn() and return its error (code, message); raise AssertionError if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
