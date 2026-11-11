"""concurrent-put-invocation-step-unique-ids."""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-put-invocation-step-unique-ids"
GROUP = "concurrency"
SERVICES = ["bedrock-agent-runtime"]

_UUID_RE = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Concurrent PutInvocationStep calls without an invocationStepId each get a distinct generated UUID,
    and ListInvocationSteps returns exactly those ids."""
    client = ctx.client("bedrock-agent-runtime")
    session_id = client.create_session(tags={"sim2real-check": CHECK})["sessionId"]
    ctx.on_cleanup(lambda: _safe_end_and_delete(ctx, session_id))

    invocation_id = client.create_invocation(sessionIdentifier=session_id)["invocationId"]
    racer_count = 10

    def _racer(i: int) -> str:
        resp = client.put_invocation_step(
            sessionIdentifier=session_id,
            invocationIdentifier=invocation_id,
            invocationStepTime=datetime.now(timezone.utc),
            payload={"contentBlocks": [{"text": f"racer-{i}"}]},
        )
        return resp["invocationStepId"]

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        generated_ids = list(pool.map(_racer, range(racer_count)))

    assert len(generated_ids) == racer_count, (
        f"expected {racer_count} PutInvocationStep responses, got {len(generated_ids)}"
    )
    for gid in generated_ids:
        assert _UUID_RE.match(gid), f"generated invocationStepId {gid!r} is not a UUID"
    assert len(set(generated_ids)) == racer_count, (
        f"server generated a duplicate invocationStepId: {sorted(generated_ids)}"
    )

    listed = client.list_invocation_steps(
        sessionIdentifier=session_id, invocationIdentifier=invocation_id
    )
    listed_ids = {s["invocationStepId"] for s in listed["invocationStepSummaries"]}
    assert listed_ids == set(generated_ids), (
        f"ListInvocationSteps ids {sorted(listed_ids)} != generated ids {sorted(generated_ids)}"
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
