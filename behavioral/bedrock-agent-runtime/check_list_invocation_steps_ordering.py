"""list-invocation-steps-ordering."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-invocation-steps-ordering"
GROUP = "ordering"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListInvocationSteps scoped to one invocation returns exactly, and in a single consistent
    order, the steps written to that invocation -- with a sibling invocation's steps in the same
    session (interleaved in write time) excluded from both the membership and the ordering."""
    client = ctx.client("bedrock-agent-runtime")

    session_id = client.create_session()["sessionId"]
    invocation_a = str(uuid.uuid4())
    invocation_b = str(uuid.uuid4())
    client.create_invocation(sessionIdentifier=session_id, invocationId=invocation_a)
    client.create_invocation(sessionIdentifier=session_id, invocationId=invocation_b)

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

    base_time = datetime.now(timezone.utc) - timedelta(minutes=5)
    step_ids_a: list[str] = []
    step_times_a: list[datetime] = []
    for i in range(4):
        step_id = str(uuid.uuid4())
        step_time = base_time + timedelta(seconds=i * 10)
        client.put_invocation_step(
            sessionIdentifier=session_id,
            invocationIdentifier=invocation_a,
            invocationStepId=step_id,
            invocationStepTime=step_time,
            payload={"contentBlocks": [{"text": f"step-a-{i}"}]},
        )
        step_ids_a.append(step_id)
        step_times_a.append(step_time)

        # Interleave a write into the sibling invocation between A's writes, so a backend
        # that orders steps by a session-wide write sequence rather than a per-invocation
        # one would leak invocation_b's step into A's ordering.
        step_id_b = str(uuid.uuid4())
        client.put_invocation_step(
            sessionIdentifier=session_id,
            invocationIdentifier=invocation_b,
            invocationStepId=step_id_b,
            invocationStepTime=step_time + timedelta(seconds=1),
            payload={"contentBlocks": [{"text": f"step-b-{i}"}]},
        )

    listed_a = client.list_invocation_steps(
        sessionIdentifier=session_id, invocationIdentifier=invocation_a
    )
    summaries_a = listed_a["invocationStepSummaries"]
    returned_ids_a = [s["invocationStepId"] for s in summaries_a]
    assert set(returned_ids_a) == set(step_ids_a), (
        f"ListInvocationSteps did not return exactly invocation A's own steps: "
        f"expected {set(step_ids_a)}, got {set(returned_ids_a)}"
    )

    # Real AWS returns invocationStepTime monotonically -- but the direction (write order or
    # its mirror image) is a backend choice, not part of the contract; detect it from the
    # response itself rather than assuming one, and require it apply consistently.
    returned_times_a = [s["invocationStepTime"] for s in summaries_a]
    ascending = all(returned_times_a[i - 1] < returned_times_a[i] for i in range(1, len(returned_times_a)))
    descending = all(returned_times_a[i - 1] > returned_times_a[i] for i in range(1, len(returned_times_a)))
    assert ascending or descending, (
        f"invocationStepTime sequence for invocation A is not monotonic in either direction: "
        f"{returned_times_a}"
    )
    expected_ids = step_ids_a if ascending else list(reversed(step_ids_a))
    expected_times = step_times_a if ascending else list(reversed(step_times_a))
    assert returned_ids_a == expected_ids, (
        f"ListInvocationSteps order for invocation A does not reproduce a consistent "
        f"{'ascending' if ascending else 'descending'} write order: expected {expected_ids}, "
        f"got {returned_ids_a}"
    )
    assert returned_times_a == expected_times, (
        f"expected {'ascending' if ascending else 'descending'} invocationStepTime sequence "
        f"{expected_times}, got {returned_times_a}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
