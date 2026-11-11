"""quick-response-search-finds-created."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "quick-response-search-finds-created"
GROUP = "data-plane"
SERVICES = ["wisdom"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SearchQuickResponses with a CONTAINS query on name finds the just-created quick response by id and
    name once the knowledge base's search index is ready.
    """
    wisdom = ctx.client("wisdom")
    kb = wisdom.create_knowledge_base(
        name=ctx.unique_name("sim2real-kb-"),
        knowledgeBaseType="QUICK_RESPONSES",
        tags={"team": "support", "stage": "sim2real-behav"},
    )["knowledgeBase"]
    kb_id = kb["knowledgeBaseId"]
    ctx.on_cleanup(lambda: wisdom.delete_knowledge_base(knowledgeBaseId=kb_id))

    unique_token = uuid.uuid4().hex[:12]
    name = f"sim2real-qr-{unique_token}"[:40]
    qr = wisdom.create_quick_response(
        knowledgeBaseId=kb_id,
        name=name,
        content={"content": "search me please"},
        tags={"team": "support", "stage": "sim2real-behav"},
    )["quickResponse"]
    qr_id = qr["quickResponseId"]
    ctx.on_cleanup(lambda: wisdom.delete_quick_response(knowledgeBaseId=kb_id, quickResponseId=qr_id))

    _poll_until(
        lambda: wisdom.get_quick_response(knowledgeBaseId=kb_id, quickResponseId=qr_id)["quickResponse"],
        lambda q: q["status"] == "CREATED",
        timeout_s=60.0,
    )

    def _search():
        try:
            return wisdom.search_quick_responses(
                knowledgeBaseId=kb_id,
                searchExpression={
                    "queries": [{"name": "name", "values": [unique_token], "operator": "CONTAINS"}]
                },
            )["results"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return []  # search index still warming up right after KB/QR creation
            raise

    found = _poll_until(_search, lambda results: len(results) >= 1, timeout_s=90.0)
    assert any(r["quickResponseId"] == qr_id and r["name"] == name for r in found), (
        f"expected search results to include quickResponseId={qr_id!r} name={name!r}, "
        f"got {found!r}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
