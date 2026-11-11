"""list-invocations-reflects-created."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-invocations-reflects-created"
GROUP = "data-plane"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two distinct CreateInvocation calls on a session both show up in ListInvocations."""
    client = ctx.client("bedrock-agent-runtime")
    session_id = client.create_session()["sessionId"]
    ctx.on_cleanup(lambda: _safe_end_and_delete(ctx, session_id))

    inv_a = client.create_invocation(sessionIdentifier=session_id, description="first invocation")["invocationId"]
    inv_b = client.create_invocation(sessionIdentifier=session_id, description="second invocation")["invocationId"]
    assert inv_a != inv_b, f"expected two distinct invocation ids, got the same id twice: {inv_a}"

    listed_ids = set()
    next_token = None
    for _ in range(20):
        kwargs = {"sessionIdentifier": session_id, "maxResults": 100}
        if next_token:
            kwargs["nextToken"] = next_token
        page = client.list_invocations(**kwargs)
        for summary in page["invocationSummaries"]:
            listed_ids.add(summary["invocationId"])
        next_token = page.get("nextToken")
        if not next_token:
            break

    assert {inv_a, inv_b} <= listed_ids, (
        f"expected both created invocations {inv_a!r} and {inv_b!r} to appear in "
        f"ListInvocations, got {listed_ids!r}"
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
