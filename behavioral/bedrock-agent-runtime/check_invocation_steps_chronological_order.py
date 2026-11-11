"""invocation-steps-chronological-order."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "invocation-steps-chronological-order"
GROUP = "ordering"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListInvocationSteps returns exactly the five written steps, each carrying the
    invocationStepTime it was written with; ordered by that time they match write order.
    """
    client = ctx.client("bedrock-agent-runtime")

    session_id = client.create_session()["sessionId"]

    def _end_and_delete() -> None:
        client.end_session(sessionIdentifier=session_id)
        client.delete_session(sessionIdentifier=session_id)

    ctx.on_cleanup(_end_and_delete)

    invocation_id = client.create_invocation(sessionIdentifier=session_id)["invocationId"]

    base_time = datetime.now(timezone.utc) - timedelta(minutes=5)
    submitted_ids = []
    submitted_times = []
    for i in range(5):
        step_id = str(uuid.uuid4())
        step_time = base_time + timedelta(seconds=i * 10)
        client.put_invocation_step(
            sessionIdentifier=session_id,
            invocationIdentifier=invocation_id,
            invocationStepId=step_id,
            invocationStepTime=step_time,
            payload={"contentBlocks": [{"text": f"step-{i}"}]},
        )
        submitted_ids.append(step_id)
        submitted_times.append(step_time)

    resp = client.list_invocation_steps(
        sessionIdentifier=session_id,
        invocationIdentifier=invocation_id,
        maxResults=100,
    )
    summaries = resp["invocationStepSummaries"]
    assert len(summaries) == 5, f"expected 5 invocation step summaries, got {len(summaries)}"

    returned_ids = [s["invocationStepId"] for s in summaries]
    assert set(returned_ids) == set(submitted_ids), (
        f"ListInvocationSteps did not return exactly the steps that were written: "
        f"expected {set(submitted_ids)}, got {set(returned_ids)}"
    )

    # invocationStepSummaries documents no order, so the summaries are sorted by the
    # invocationStepTime they carry; each id must keep the time it was written with.
    by_time = sorted(summaries, key=lambda s: s["invocationStepTime"])
    sorted_ids = [s["invocationStepId"] for s in by_time]
    sorted_times = [s["invocationStepTime"] for s in by_time]
    assert sorted_ids == submitted_ids, (
        "ordered by invocationStepTime, the steps must reproduce write order: "
        f"expected {submitted_ids}, got {sorted_ids}"
    )
    assert sorted_times == submitted_times, (
        f"expected invocationStepTime values {submitted_times}, got {sorted_times}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
