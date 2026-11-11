"""quick-response-create-created-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "quick-response-create-created-lifecycle"
GROUP = "state"
SERVICES = ["wisdom"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateQuickResponse transitions to CREATED and GetQuickResponse reflects the persisted content."""
    wisdom = ctx.client("wisdom")
    kb = wisdom.create_knowledge_base(
        name=ctx.unique_name("sim2real-kb-"),
        knowledgeBaseType="QUICK_RESPONSES",
        tags={"team": "support", "stage": "sim2real-behav"},
    )["knowledgeBase"]
    kb_id = kb["knowledgeBaseId"]
    ctx.on_cleanup(lambda: wisdom.delete_knowledge_base(knowledgeBaseId=kb_id))

    qr_name = ctx.unique_name("sim2real-qr-")[:40]
    created = wisdom.create_quick_response(
        knowledgeBaseId=kb_id,
        name=qr_name,
        content={"content": "Thanks for calling, how can I help?"},
        tags={"team": "support", "stage": "sim2real-behav"},
    )["quickResponse"]
    qr_id = created["quickResponseId"]
    ctx.on_cleanup(lambda: wisdom.delete_quick_response(knowledgeBaseId=kb_id, quickResponseId=qr_id))

    final = _poll_until(
        lambda: wisdom.get_quick_response(knowledgeBaseId=kb_id, quickResponseId=qr_id)["quickResponse"],
        lambda q: q["status"] in ("CREATED", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert final["status"] == "CREATED", f"expected status CREATED, got {final['status']!r}"
    assert final["name"] == qr_name, f"expected name {qr_name!r}, got {final['name']!r}"
    assert final["contents"]["plainText"]["content"] == "Thanks for calling, how can I help?", (
        f"expected persisted content unchanged, got {final['contents']['plainText']['content']!r}"
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
