"""knowledge-base-custom-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "knowledge-base-custom-lifecycle"
GROUP = "lifecycle"
SERVICES = ["qconnect"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateKnowledgeBase (CUSTOM) reaches ACTIVE and DeleteKnowledgeBase removes it (GetKnowledgeBase 404s)."""
    qc = ctx.client("qconnect")
    name = ctx.unique_name("sim2real-qc-kb-")
    kb_id = qc.create_knowledge_base(
        name=name, knowledgeBaseType="CUSTOM", tags={"sim2real-owner": "behavioral-suite"}
    )["knowledgeBase"]["knowledgeBaseId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: qc.delete_knowledge_base(knowledgeBaseId=kb_id)))

    status = _poll_until(
        lambda: qc.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]["status"],
        lambda s: s in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert status == "ACTIVE", f"knowledge base did not reach ACTIVE, got {status}"

    qc.delete_knowledge_base(knowledgeBaseId=kb_id)

    def _get_refusal():
        try:
            qc.get_knowledge_base(knowledgeBaseId=kb_id)
            return None
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")

    code, message = _poll_until(_get_refusal, lambda r: r is not None, timeout_s=60.0)
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "Knowledge Base does not exist.", f"unexpected message {message!r}"

    try:
        qc.delete_knowledge_base(knowledgeBaseId=kb_id)
        raise AssertionError("expected second delete of an already-deleted knowledge base to fail")
    except ClientError as exc:
        second_delete_code = exc.response["Error"]["Code"]
        second_delete_message = exc.response["Error"].get("Message")
    assert second_delete_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException on double-delete, got {second_delete_code}"
    )
    assert second_delete_message == "Knowledge Base does not exist.", (
        f"unexpected message {second_delete_message!r}"
    )


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last saw {value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
