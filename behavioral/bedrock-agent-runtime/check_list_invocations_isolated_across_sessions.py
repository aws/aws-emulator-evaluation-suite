"""list-invocations-isolated-across-sessions."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-invocations-isolated-across-sessions"
GROUP = "data-plane"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListInvocations for session A never returns invocations created under sibling session B."""
    client = ctx.client("bedrock-agent-runtime")
    session_a = client.create_session()["sessionId"]
    session_b = client.create_session()["sessionId"]

    def _cleanup():
        for sid in (session_a, session_b):
            try:
                client.end_session(sessionIdentifier=sid)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
            try:
                client.delete_session(sessionIdentifier=sid)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise

    ctx.on_cleanup(_cleanup)

    invocation_a = client.create_invocation(sessionIdentifier=session_a)["invocationId"]
    invocation_b = client.create_invocation(sessionIdentifier=session_b)["invocationId"]

    listed_a = client.list_invocations(sessionIdentifier=session_a)
    ids_a = {s["invocationId"] for s in listed_a["invocationSummaries"]}
    assert invocation_a in ids_a, (
        f"invocation {invocation_a} created under session {session_a} is missing from "
        f"that session's ListInvocations: {ids_a}"
    )
    assert invocation_b not in ids_a, (
        f"invocation {invocation_b} created under sibling session {session_b} leaked into "
        f"ListInvocations for session {session_a}: {ids_a}"
    )

    listed_b = client.list_invocations(sessionIdentifier=session_b)
    ids_b = {s["invocationId"] for s in listed_b["invocationSummaries"]}
    assert invocation_b in ids_b, (
        f"invocation {invocation_b} created under session {session_b} is missing from "
        f"that session's ListInvocations: {ids_b}"
    )
    assert invocation_a not in ids_b, (
        f"invocation {invocation_a} created under sibling session {session_a} leaked into "
        f"ListInvocations for session {session_b}: {ids_b}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
