"""put-invocation-step-payload-round-trip."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-invocation-step-payload-round-trip"
GROUP = "data-plane"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutInvocationStep persists the exact invocationStepTime supplied by the caller (not a
    server-substituted timestamp), and GetInvocationStep returns it back unchanged alongside
    the payload -- both fields round-trip together, not just the payload."""
    client = ctx.client("bedrock-agent-runtime")
    session_id = client.create_session(
        tags={"sim2real-check": "put-invocation-step-payload-round-trip"}
    )["sessionId"]
    ctx.on_cleanup(lambda: _safe_end_and_delete(ctx, session_id))

    invocation_id = client.create_invocation(sessionIdentifier=session_id)["invocationId"]

    # a deliberately distinctive, non-"now" timestamp so a server-substituted value would
    # be caught rather than accidentally matching
    step_time = datetime(2023, 6, 15, 8, 30, 45, tzinfo=timezone.utc) + timedelta(
        hours=3, minutes=17
    )
    payload = {"contentBlocks": [{"text": "payload for the timestamp round trip"}]}

    put = client.put_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepTime=step_time,
        payload=payload,
    )
    step_id = put["invocationStepId"]

    fetched = client.get_invocation_step(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        invocationStepId=step_id,
    )["invocationStep"]

    assert fetched["invocationStepTime"] == step_time, (
        f"invocationStepTime was not preserved as supplied: sent {step_time!r}, "
        f"got back {fetched['invocationStepTime']!r} (server-substituted timestamps "
        f"would diverge from this deliberately non-'now' value)"
    )
    assert fetched["payload"] == payload, (
        f"payload did not round-trip alongside the preserved timestamp: "
        f"sent {payload!r}, got back {fetched['payload']!r}"
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
