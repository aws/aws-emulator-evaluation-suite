"""quick-response-search-finds-created."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "quick-response-search-finds-created"
GROUP = "data-plane"
SERVICES = ["qconnect"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SearchQuickResponses finds a newly created quick response by an exact-name query."""
    qc = ctx.client("qconnect")
    kb_id = _create_active_knowledge_base(ctx, qc, "QUICK_RESPONSES")

    name = ctx.unique_name("sim2real-qc-qr-searchable-")
    qr_id = qc.create_quick_response(
        knowledgeBaseId=kb_id,
        name=name,
        content={"content": "Your order has shipped!"},
        tags={"sim2real": "true"},
    )["quickResponse"]["quickResponseId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: qc.delete_quick_response(knowledgeBaseId=kb_id, quickResponseId=qr_id))
    )
    status = _poll_until(
        lambda: qc.get_quick_response(knowledgeBaseId=kb_id, quickResponseId=qr_id)["quickResponse"]["status"],
        lambda s: s in ("CREATED", "CREATE_FAILED"),
        timeout_s=60.0,
        desc=f"quick response {qr_id} to leave CREATE_IN_PROGRESS",
    )
    assert status == "CREATED", f"expected quick response {qr_id} to reach CREATED, got {status}"

    def _search_hits():
        try:
            resp = qc.search_quick_responses(
                knowledgeBaseId=kb_id,
                searchExpression={
                    "queries": [{"name": "name", "values": [name], "operator": "CONTAINS"}],
                },
            )
        except ClientError:
            return set()
        return {r["quickResponseId"] for r in resp["results"]}

    hits = _poll_until(
        _search_hits, lambda h: qr_id in h, timeout_s=90.0, interval_s=3.0, desc=f"search index to surface {qr_id}"
    )
    assert qr_id in hits, f"expected quick response {qr_id} in search results, got {hits}"


def _create_active_knowledge_base(ctx, qc, kb_type: str) -> str:
    name = ctx.unique_name("sim2real-qc-kb-")
    kb_id = qc.create_knowledge_base(name=name, knowledgeBaseType=kb_type, tags={"sim2real": "true"})[
        "knowledgeBase"
    ]["knowledgeBaseId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: qc.delete_knowledge_base(knowledgeBaseId=kb_id)))
    status = _poll_until(
        lambda: qc.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]["status"],
        lambda s: s in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
        desc=f"knowledge base {kb_id} to leave CREATE_IN_PROGRESS",
    )
    assert status == "ACTIVE", f"expected knowledge base {kb_id} to reach ACTIVE, got {status}"
    return kb_id


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, desc="condition"):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value) and time.monotonic() < deadline:
        time.sleep(interval_s)
        value = probe()
    if not predicate(value):
        raise AssertionError(f"timed out after {timeout_s}s waiting for {desc}, last value: {value!r}")
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
