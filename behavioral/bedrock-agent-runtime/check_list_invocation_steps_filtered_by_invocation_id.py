"""list-invocation-steps-filtered-by-invocation-id."""
from __future__ import annotations

from datetime import datetime, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-invocation-steps-filtered-by-invocation-id"
GROUP = "data-plane"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListInvocationSteps scoped to one invocationIdentifier excludes steps from a sibling invocation."""
    client = ctx.client("bedrock-agent-runtime")
    session_id = client.create_session(tags={"env": "sim2real"})["sessionId"]

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

    invocation_a = client.create_invocation(sessionIdentifier=session_id)["invocationId"]
    invocation_b = client.create_invocation(sessionIdentifier=session_id)["invocationId"]

    step_a = client.put_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_a,
        invocationStepTime=datetime.now(timezone.utc),
        payload={"contentBlocks": [{"text": "belongs-to-a"}]},
    )["invocationStepId"]
    client.put_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_b,
        invocationStepTime=datetime.now(timezone.utc),
        payload={"contentBlocks": [{"text": "belongs-to-b"}]},
    )

    listed = client.list_invocation_steps(
        sessionIdentifier=session_id, invocationIdentifier=invocation_a
    )
    summaries = listed["invocationStepSummaries"]
    assert len(summaries) == 1, (
        f"expected exactly 1 step scoped to invocation_a, got {len(summaries)}: {summaries}"
    )
    assert summaries[0]["invocationStepId"] == step_a, (
        f"expected step id {step_a!r}, got {summaries[0]['invocationStepId']!r}"
    )
    assert summaries[0]["invocationId"] == invocation_a, (
        f"expected invocationId {invocation_a!r}, got {summaries[0]['invocationId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
