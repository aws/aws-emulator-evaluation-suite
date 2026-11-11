"""delete-knowledge-base-with-active-association-succeeds."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-knowledge-base-with-active-association-succeeds"
GROUP = "state"
SERVICES = ["qconnect"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteKnowledgeBase succeeds even while an assistant association still references it
    (no referential-integrity block at delete time); the knowledge base still transitions to
    not-found, and the assistant itself is unaffected."""
    qc = ctx.client("qconnect")
    assistant_id = _create_active_assistant(ctx, qc)
    kb_id = _create_active_knowledge_base(ctx, qc, "CUSTOM")

    association_id = qc.create_assistant_association(
        assistantId=assistant_id,
        associationType="KNOWLEDGE_BASE",
        association={"knowledgeBaseId": kb_id},
    )["assistantAssociation"]["assistantAssociationId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: qc.delete_assistant_association(
                assistantId=assistant_id, assistantAssociationId=association_id
            )
        )
    )

    # empirically, DeleteKnowledgeBase does not enforce referential integrity against a live
    # assistant association -- the call succeeds immediately
    qc.delete_knowledge_base(knowledgeBaseId=kb_id)

    def _get_code():
        try:
            qc.get_knowledge_base(knowledgeBaseId=kb_id)
            return None
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")

    final_code = _poll_until(_get_code, lambda c: c is not None, timeout_s=60.0)
    assert final_code == ("ResourceNotFoundException", "Knowledge Base does not exist."), f"expected ResourceNotFoundException, got {final_code}"

    # the assistant itself, and the (now dangling) association, must remain reachable
    assistant_status = qc.get_assistant(assistantId=assistant_id)["assistant"]["status"]
    assert assistant_status == "ACTIVE", f"assistant must remain ACTIVE, got {assistant_status}"


def _create_active_assistant(ctx, qc) -> str:
    name = ctx.unique_name("sim2real-qc-asst-")
    assistant_id = qc.create_assistant(name=name, type="AGENT")["assistant"]["assistantId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: qc.delete_assistant(assistantId=assistant_id)))
    status = _poll_until(
        lambda: qc.get_assistant(assistantId=assistant_id)["assistant"]["status"],
        lambda s: s in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert status == "ACTIVE", f"assistant prerequisite did not reach ACTIVE, got {status}"
    return assistant_id


def _create_active_knowledge_base(ctx, qc, kb_type: str) -> str:
    name = ctx.unique_name("sim2real-qc-kb-")
    kb_id = qc.create_knowledge_base(name=name, knowledgeBaseType=kb_type)["knowledgeBase"]["knowledgeBaseId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: qc.delete_knowledge_base(knowledgeBaseId=kb_id)))
    status = _poll_until(
        lambda: qc.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]["status"],
        lambda s: s in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert status == "ACTIVE", f"knowledge base prerequisite did not reach ACTIVE, got {status}"
    return kb_id


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
            raise TimeoutError(f"_poll_until timed out after {timeout_s}s, last value: {value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
