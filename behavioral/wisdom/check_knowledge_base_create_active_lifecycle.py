"""knowledge-base-create-active-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "knowledge-base-create-active-lifecycle"
GROUP = "state"
SERVICES = ["wisdom"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateKnowledgeBase transitions to ACTIVE and GetKnowledgeBase reflects the fields that were set."""
    wisdom = ctx.client("wisdom")
    name = ctx.unique_name("sim2real-kb-")
    created = wisdom.create_knowledge_base(
        name=name,
        knowledgeBaseType="CUSTOM",
        description="behavioral check kb",
        tags={"stage": "sim2real-behav"},
    )["knowledgeBase"]
    kb_id = created["knowledgeBaseId"]
    ctx.on_cleanup(lambda: wisdom.delete_knowledge_base(knowledgeBaseId=kb_id))

    final = _poll_until(
        lambda: wisdom.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"],
        lambda k: k["status"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert final["status"] == "ACTIVE", f"expected ACTIVE, got {final['status']!r}"
    assert final["name"] == name, f"expected name {name!r}, got {final['name']!r}"
    assert final["knowledgeBaseType"] == "CUSTOM", (
        f"expected knowledgeBaseType CUSTOM, got {final['knowledgeBaseType']!r}"
    )
    assert final["description"] == "behavioral check kb", (
        f"expected description 'behavioral check kb', got {final['description']!r}"
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
