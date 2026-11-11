"""list-invocations-pagination-with-next-token."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-invocations-pagination-with-next-token"
GROUP = "data-plane"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paging ListInvocations one item at a time via nextToken eventually surfaces every invocation once."""
    client = ctx.client("bedrock-agent-runtime")
    session_id = client.create_session()["sessionId"]

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

    expected_ids = {
        client.create_invocation(sessionIdentifier=session_id)["invocationId"] for _ in range(3)
    }
    assert len(expected_ids) == 3, f"expected 3 distinct invocation ids, got {expected_ids}"

    collected = []
    next_token = None
    pages = 0
    while True:
        kwargs = {"sessionIdentifier": session_id, "maxResults": 1}
        if next_token:
            kwargs["nextToken"] = next_token
        page = client.list_invocations(**kwargs)
        pages += 1
        assert len(page["invocationSummaries"]) <= 1, (
            f"maxResults=1 but page {pages} returned {len(page['invocationSummaries'])} summaries"
        )
        collected.extend(s["invocationId"] for s in page["invocationSummaries"])
        next_token = page.get("nextToken")
        if not next_token or pages > 10:
            break

    assert set(collected) == expected_ids, f"expected {expected_ids}, collected {set(collected)}"
    assert len(collected) == len(expected_ids), "an invocation id was returned more than once"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
