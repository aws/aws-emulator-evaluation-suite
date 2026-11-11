"""delete-knowledge-base-with-active-association-succeeds."""
from __future__ import annotations

import time

from behavioral_harness import tags


CHECK = "delete-knowledge-base-with-active-association-succeeds"
GROUP = "state-machine"
SERVICES = ["wisdom"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteKnowledgeBase succeeds while an AssistantAssociation still references the knowledge
    base (no ConflictException); the knowledge base is then reported gone and a second delete
    fails ResourceNotFoundException."""
    wisdom = ctx.client("wisdom")
    assistant = wisdom.create_assistant(
        name=ctx.unique_name("sim2real-behav-asst-"),
        type="AGENT",
        tags={"team": "support", "stage": "sim2real-behav"},
    )["assistant"]
    assistant_id = assistant["assistantId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: wisdom.delete_assistant(assistantId=assistant_id)))
    _poll_until(
        lambda: wisdom.get_assistant(assistantId=assistant_id)["assistant"],
        lambda a: a["status"] == "ACTIVE",
        timeout_s=60.0,
    )

    kb = wisdom.create_knowledge_base(
        name=ctx.unique_name("sim2real-behav-kb-"),
        knowledgeBaseType="CUSTOM",
        tags={"team": "support", "stage": "sim2real-behav"},
    )["knowledgeBase"]
    kb_id = kb["knowledgeBaseId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: wisdom.delete_knowledge_base(knowledgeBaseId=kb_id)))
    _poll_until(
        lambda: wisdom.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"],
        lambda k: k["status"] == "ACTIVE",
        timeout_s=60.0,
    )

    assoc = wisdom.create_assistant_association(
        assistantId=assistant_id,
        associationType="KNOWLEDGE_BASE",
        association={"knowledgeBaseId": kb_id},
        tags={"team": "support", "stage": "sim2real-behav"},
    )["assistantAssociation"]
    assoc_id = assoc["assistantAssociationId"]
    ctx.on_cleanup(
        lambda: _safe_delete(
            lambda: wisdom.delete_assistant_association(assistantId=assistant_id, assistantAssociationId=assoc_id)
        )
    )

    # confirm the association is genuinely active before deleting the referenced knowledge base
    reread_assoc_id = wisdom.get_assistant_association(
        assistantId=assistant_id, assistantAssociationId=assoc_id
    )["assistantAssociation"]["assistantAssociationId"]
    assert reread_assoc_id == assoc_id, f"expected assistantAssociationId {assoc_id!r}, got {reread_assoc_id!r}"

    # DeleteKnowledgeBase succeeds even though an assistant association still references this KB
    wisdom.delete_knowledge_base(knowledgeBaseId=kb_id)

    def _kb_gone():
        from botocore.exceptions import ClientError

        try:
            wisdom.get_knowledge_base(knowledgeBaseId=kb_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return True
            raise
        return False

    ok = _poll_bool(_kb_gone, timeout_s=60.0)
    assert ok, "knowledge base was never reported as deleted"

    # a mutation against the dead id must also fail, not just a read -- proves the id is
    # genuinely retired rather than merely absent from GetKnowledgeBase's own read path
    second_delete_code, second_delete_message = _error(lambda: wisdom.delete_knowledge_base(knowledgeBaseId=kb_id))
    assert second_delete_code == "ResourceNotFoundException", (
        f"expected a second delete_knowledge_base on the dead id to fail ResourceNotFoundException, "
        f"got {second_delete_code!r}"
    )
    assert second_delete_message == "Knowledge Base does not exist.", (
        f"expected the knowledge-base not-found message, got {second_delete_message!r}"
    )

    # delete the dangling association (it may already be gone)
    _safe_delete(
        lambda: wisdom.delete_assistant_association(assistantId=assistant_id, assistantAssociationId=assoc_id)
    )


# ===== helpers =====
def _safe_delete(fn):
    """Run a delete; an already-deleted resource is clean, any other error raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """Return the (code, message) of the ClientError fn() raises; a success fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _poll_bool(probe, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if probe():
            return True
        time.sleep(interval_s)
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
