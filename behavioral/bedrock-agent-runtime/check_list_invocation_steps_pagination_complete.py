"""list-invocation-steps-pagination-complete."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-invocation-steps-pagination-complete"
GROUP = "data-plane"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListInvocationSteps, paginated one item at a time via nextToken, surfaces every step exactly once."""
    client = ctx.client("bedrock-agent-runtime")
    session_id = client.create_session(tags={"simparity-check": CHECK})["sessionId"]
    ctx.on_cleanup(lambda: _safe_end_and_delete(ctx, session_id))

    invocation_id = client.create_invocation(sessionIdentifier=session_id)["invocationId"]

    base_time = datetime.now(timezone.utc)
    created_ids = set()
    for i in range(3):
        put = client.put_invocation_step(
            sessionIdentifier=session_id,
            invocationIdentifier=invocation_id,
            invocationStepTime=base_time + timedelta(seconds=i),
            payload={"contentBlocks": [{"text": f"step-{i}"}]},
        )
        created_ids.add(put["invocationStepId"])
    assert len(created_ids) == 3, "expected 3 distinct server-generated invocationStepIds"

    seen_list = []
    next_token = None
    for _ in range(20):
        kwargs = {
            "sessionIdentifier": session_id,
            "invocationIdentifier": invocation_id,
            "maxResults": 1,
        }
        if next_token:
            kwargs["nextToken"] = next_token
        page = client.list_invocation_steps(**kwargs)
        summaries = page["invocationStepSummaries"]
        assert len(summaries) <= 1, f"expected at most maxResults=1 summary per page, got {len(summaries)}"
        for summary in summaries:
            seen_list.append(summary["invocationStepId"])
        next_token = page.get("nextToken")
        if not next_token:
            break

    assert len(seen_list) == len(created_ids), (
        f"expected exactly {len(created_ids)} step(s) across all pages with no duplicates, saw {len(seen_list)}"
    )
    assert set(seen_list) == created_ids, (
        f"paginated steps {set(seen_list)} did not match created steps {created_ids}"
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
