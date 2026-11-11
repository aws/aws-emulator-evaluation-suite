"""list-assistants-pagination-covers-all-created."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-assistants-pagination-covers-all-created"
GROUP = "lifecycle"
SERVICES = ["wisdom"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAssistants with a small maxResults paginates via nextToken and the union of all pages
    contains every assistant created for this check exactly once (no duplicates, no drops)."""
    wisdom = ctx.client("wisdom")
    created_ids = []
    for _ in range(3):
        assistant = wisdom.create_assistant(
            name=ctx.unique_name("sim2real-behav-page-"), type="AGENT", tags={"sim2real-behav": "true"}
        )["assistant"]
        created_ids.append(assistant["assistantId"])
        ctx.on_cleanup(
            lambda aid=assistant["assistantId"]: _safe_delete(lambda: wisdom.delete_assistant(assistantId=aid))
        )

    seen_ids = []
    token = None
    pages = 0
    while True:
        kwargs = {"maxResults": 1}
        if token:
            kwargs["nextToken"] = token
        resp = wisdom.list_assistants(**kwargs)
        page_ids = [a["assistantId"] for a in resp.get("assistantSummaries", [])]
        assert len(page_ids) <= 1, f"maxResults=1 page returned {len(page_ids)} items"
        seen_ids.extend(page_ids)
        token = resp.get("nextToken")
        pages += 1
        if not token or pages > 2000:
            break

    assert len(seen_ids) == len(set(seen_ids)), "pagination returned a duplicate assistantId across pages"
    for aid in created_ids:
        assert aid in seen_ids, f"assistant {aid} missing from paginated ListAssistants output"


def _safe_delete(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
