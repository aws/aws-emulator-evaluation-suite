"""invocation-step-timestamp-precision-preserved."""
from __future__ import annotations

import datetime

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "invocation-step-timestamp-precision-preserved"
GROUP = "server-side"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A sub-second (microsecond) timestamp supplied as invocationStepTime on
    PutInvocationStep survives exactly on GetInvocationStep instead of being
    truncated/rounded to whole seconds."""
    client = ctx.client("bedrock-agent-runtime")

    session_id = client.create_session(
        tags={"simparity-check": CHECK}
    )["sessionId"]

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

    # Fix the microsecond component to an obviously non-zero, non-round
    # value so truncation/rounding to whole seconds would be unmistakable.
    step_time = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=123456)

    put_resp = client.put_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepTime=step_time,
        payload={"contentBlocks": [{"text": "timestamp precision probe"}]},
    )
    step_id = put_resp["invocationStepId"]

    fetched = client.get_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepId=step_id,
    )
    returned_time = fetched["invocationStep"]["invocationStepTime"]

    assert returned_time.microsecond == 123456, (
        f"microsecond precision was not preserved: sent microsecond=123456, "
        f"got back {returned_time.microsecond} (full timestamp: {returned_time!r})"
    )
    assert returned_time == step_time, (
        f"round-tripped timestamp {returned_time!r} does not equal the timestamp sent {step_time!r}"
    )

    # Also visible through ListInvocationSteps summaries, which should agree.
    listed = client.list_invocation_steps(
        sessionIdentifier=session_id, invocationIdentifier=invocation_id
    )["invocationStepSummaries"]
    matching = [s for s in listed if s["invocationStepId"] == step_id]
    assert len(matching) == 1, (
        f"expected exactly one ListInvocationSteps summary for step {step_id!r}, "
        f"got {len(matching)}: {listed!r}"
    )
    assert matching[0]["invocationStepTime"] == step_time, (
        f"ListInvocationSteps summary for step {step_id!r} carries invocationStepTime "
        f"{matching[0]['invocationStepTime']!r}, expected {step_time!r} (microsecond precision lost)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
