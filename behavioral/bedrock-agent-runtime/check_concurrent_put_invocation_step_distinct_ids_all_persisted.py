"""concurrent-put-invocation-step-distinct-ids-all-persisted."""
from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-put-invocation-step-distinct-ids-all-persisted"
GROUP = "concurrency"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """N racing PutInvocationStep calls, each with its OWN distinct invocationStepId on the same
    invocation, all persist without loss: ListInvocationSteps afterward contains all N step ids
    with no duplicates and no drops."""
    client = ctx.client("bedrock-agent-runtime")

    session_id = client.create_session()["sessionId"]
    invocation_id = str(uuid.uuid4())
    client.create_invocation(sessionIdentifier=session_id, invocationId=invocation_id)

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

    racer_count = 10
    step_ids = [str(uuid.uuid4()) for _ in range(racer_count)]
    base_time = datetime.now(timezone.utc)

    def _racer(i):
        client.put_invocation_step(
            sessionIdentifier=session_id,
            invocationIdentifier=invocation_id,
            invocationStepId=step_ids[i],
            invocationStepTime=base_time + timedelta(seconds=i),
            payload={"contentBlocks": [{"text": f"concurrent-step-{i}"}]},
        )
        return step_ids[i]

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        list(pool.map(_racer, range(racer_count)))

    listed = client.list_invocation_steps(
        sessionIdentifier=session_id, invocationIdentifier=invocation_id
    )
    returned_ids = [s["invocationStepId"] for s in listed["invocationStepSummaries"]]
    assert sorted(returned_ids) == sorted(step_ids), (
        f"expected all {racer_count} distinct steps persisted, got {returned_ids}"
    )
    assert len(returned_ids) == len(set(returned_ids)), "duplicate step ids returned"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
