"""put-invocation-step-multiple-content-blocks."""
from __future__ import annotations

from datetime import datetime, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-invocation-step-multiple-content-blocks"
GROUP = "data-plane"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A multi-block payload (several text content blocks) round-trips in order via GetInvocationStep."""
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

    blocks = [{"text": "first block"}, {"text": "second block"}, {"text": "third block"}]
    put = client.put_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepTime=datetime.now(timezone.utc),
        payload={"contentBlocks": blocks},
    )
    step_id = put["invocationStepId"]

    fetched = client.get_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepId=step_id,
    )
    got_blocks = fetched["invocationStep"]["payload"]["contentBlocks"]
    assert got_blocks == blocks, (
        f"multi-block payload did not round-trip in order: sent {blocks}, got back {got_blocks}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
