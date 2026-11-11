"""list-invocations-scoped-to-session."""
from __future__ import annotations

import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-invocations-scoped-to-session"
GROUP = "data-plane"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListInvocations for a given session returns only that session's invocations, even
    when another session with its own invocations exists concurrently."""
    client = ctx.client("bedrock-agent-runtime")

    session_a = client.create_session()["sessionId"]
    ctx.on_cleanup(lambda: _safe_delete_session(client, session_a))
    session_b = client.create_session()["sessionId"]
    ctx.on_cleanup(lambda: _safe_delete_session(client, session_b))

    invocation_a1 = str(uuid.uuid4())
    invocation_a2 = str(uuid.uuid4())
    client.create_invocation(sessionIdentifier=session_a, invocationId=invocation_a1)
    client.create_invocation(sessionIdentifier=session_a, invocationId=invocation_a2)

    invocation_b1 = str(uuid.uuid4())
    client.create_invocation(sessionIdentifier=session_b, invocationId=invocation_b1)

    ids_a = {
        s["invocationId"]
        for s in client.list_invocations(sessionIdentifier=session_a)["invocationSummaries"]
    }
    ids_b = {
        s["invocationId"]
        for s in client.list_invocations(sessionIdentifier=session_b)["invocationSummaries"]
    }

    assert ids_a == {invocation_a1, invocation_a2}, (
        f"expected session_a's invocations to be exactly {{{invocation_a1}, {invocation_a2}}}, got {ids_a}"
    )
    assert ids_b == {invocation_b1}, (
        f"expected session_b's invocations to be exactly {{{invocation_b1}}}, got {ids_b}"
    )
    assert ids_a.isdisjoint(ids_b), (
        f"session_a's invocations {ids_a} leaked into session_b's {ids_b}"
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
