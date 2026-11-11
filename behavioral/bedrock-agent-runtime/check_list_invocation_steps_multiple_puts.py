"""list-invocation-steps-multiple-puts."""
from __future__ import annotations

from datetime import datetime, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-invocation-steps-multiple-puts"
GROUP = "data-plane"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListInvocationSteps returns every step previously written via PutInvocationStep, no more, no less."""
    client = ctx.client("bedrock-agent-runtime")
    session_id = client.create_session(tags={"simparity-check": CHECK})["sessionId"]

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

    step_ids = set()
    for i in range(3):
        put = client.put_invocation_step(
            sessionIdentifier=session_id,
            invocationIdentifier=invocation_id,
            invocationStepTime=datetime.now(timezone.utc),
            payload={"contentBlocks": [{"text": f"step-{i}"}]},
        )
        step_ids.add(put["invocationStepId"])
    assert len(step_ids) == 3, f"expected 3 distinct server-generated invocationStepIds, got {step_ids}"

    listed = client.list_invocation_steps(sessionIdentifier=session_id)
    listed_ids = {s["invocationStepId"] for s in listed["invocationStepSummaries"]}
    assert listed_ids == step_ids, f"expected ListInvocationSteps to return exactly {step_ids}, got {listed_ids}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
