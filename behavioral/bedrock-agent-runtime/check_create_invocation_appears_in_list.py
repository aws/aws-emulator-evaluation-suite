"""create-invocation-appears-in-list."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-invocation-appears-in-list"
GROUP = "data-plane"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CreateInvocation call is durably reflected in ListInvocations for that session."""
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

    invocation_id = client.create_invocation(sessionIdentifier=session_id)["invocationId"]

    listed = client.list_invocations(sessionIdentifier=session_id)
    ids = [s["invocationId"] for s in listed["invocationSummaries"]]
    assert invocation_id in ids, f"expected {invocation_id} in ListInvocations, got {ids}"
    assert ids.count(invocation_id) == 1, (
        f"expected {invocation_id} to appear exactly once in ListInvocations, "
        f"appeared {ids.count(invocation_id)} times in {ids}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
