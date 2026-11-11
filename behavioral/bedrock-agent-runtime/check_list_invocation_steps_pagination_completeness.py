"""list-invocation-steps-pagination-completeness."""
from __future__ import annotations

import datetime
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-invocation-steps-pagination-completeness"
GROUP = "data-plane"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Paginating ListInvocationSteps with a small maxResults returns every step exactly
    once across all pages -- no duplicates, no omissions."""
    client = ctx.client("bedrock-agent-runtime")

    created = client.create_session()
    session_id = created["sessionId"]
    ctx.on_cleanup(lambda: _safe_delete_session(client, session_id))

    invocation_id = str(uuid.uuid4())
    client.create_invocation(sessionIdentifier=session_id, invocationId=invocation_id)

    step_ids = set()
    base_time = datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc)
    for i in range(5):
        step_id = str(uuid.uuid4())
        step_ids.add(step_id)
        client.put_invocation_step(
            sessionIdentifier=session_id,
            invocationIdentifier=invocation_id,
            invocationStepId=step_id,
            invocationStepTime=base_time + datetime.timedelta(seconds=i),
            payload={"contentBlocks": [{"text": f"step-{i}"}]},
        )

    seen: list[str] = []
    next_token = None
    while True:
        kwargs = {
            "sessionIdentifier": session_id,
            "invocationIdentifier": invocation_id,
            "maxResults": 2,
        }
        if next_token:
            kwargs["nextToken"] = next_token
        resp = client.list_invocation_steps(**kwargs)
        page = resp["invocationStepSummaries"]
        assert len(page) <= 2, f"page returned {len(page)} items, expected at most maxResults=2"
        for summary in page:
            seen.append(summary["invocationStepId"])
        next_token = resp.get("nextToken")
        if not next_token:
            break

    assert len(seen) == len(step_ids), f"expected {len(step_ids)} steps, saw {len(seen)}"
    assert set(seen) == step_ids, "pagination dropped or duplicated a step"


def _safe_delete_session(client, session_id: str) -> None:
    try:
        status = client.get_session(sessionIdentifier=session_id)["sessionStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    if status == "ACTIVE":
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
