"""get-invocation-step-matches-specific-step-among-many."""
from __future__ import annotations

from datetime import datetime, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-invocation-step-matches-specific-step-among-many"
GROUP = "data-plane"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetInvocationStep returns exactly the payload for the requested step id, not a sibling's."""
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

    step_id_by_text = {}
    for label in ("alpha", "bravo", "charlie"):
        step_id = client.put_invocation_step(
            sessionIdentifier=session_id,
            invocationIdentifier=invocation_id,
            invocationStepTime=datetime.now(timezone.utc),
            payload={"contentBlocks": [{"text": label}]},
        )["invocationStepId"]
        step_id_by_text[label] = step_id
    ids = list(step_id_by_text.values())
    assert len(set(ids)) == 3, f"expected 3 distinct invocationStepIds, got {ids}"

    target_step_id = step_id_by_text["bravo"]
    fetched = client.get_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepId=target_step_id,
    )["invocationStep"]
    assert fetched["invocationStepId"] == target_step_id, (
        f"expected invocationStepId {target_step_id!r}, got {fetched['invocationStepId']!r}"
    )
    assert fetched["payload"]["contentBlocks"] == [{"text": "bravo"}], (
        f"expected the requested step's own payload [{{'text': 'bravo'}}], "
        f"got {fetched['payload']['contentBlocks']!r} (a sibling's payload would indicate GetInvocationStep "
        f"is not scoping by invocationStepId)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
