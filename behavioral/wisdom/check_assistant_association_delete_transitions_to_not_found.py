"""assistant-association-delete-transitions-to-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assistant-association-delete-transitions-to-not-found"
GROUP = "lifecycle"
SERVICES = ["wisdom"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DeleteAssistantAssociation, GetAssistantAssociation eventually raises
    ResourceNotFoundException and the association drops out of ListAssistantAssociations."""
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
    )["assistantAssociation"]
    assoc_id = assoc["assistantAssociationId"]

    # positive control: the association is visible before deletion
    before = wisdom.get_assistant_association(assistantId=assistant_id, assistantAssociationId=assoc_id)[
        "assistantAssociation"
    ]
    assert before["assistantAssociationId"] == assoc_id, (
        f"expected positive control to return {assoc_id!r}, got {before['assistantAssociationId']!r}"
    )

    wisdom.delete_assistant_association(assistantId=assistant_id, assistantAssociationId=assoc_id)

    def _assoc_gone():
        try:
            wisdom.get_assistant_association(assistantId=assistant_id, assistantAssociationId=assoc_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return True
            raise
        return False

    ok = _poll_bool(_assoc_gone, timeout_s=60.0)
    assert ok, "GetAssistantAssociation never returned ResourceNotFoundException after delete"
    get_code, get_message = _error(
        lambda: wisdom.get_assistant_association(assistantId=assistant_id, assistantAssociationId=assoc_id)
    )
    assert get_code == "ResourceNotFoundException", (
        f"expected GetAssistantAssociation on the deleted id to raise ResourceNotFoundException, got {get_code!r}"
    )
    assert get_message == "Assistant Association does not exist.", (
        f"expected the association not-found message, got {get_message!r}"
    )

    listed_after = wisdom.list_assistant_associations(assistantId=assistant_id)["assistantAssociationSummaries"]
    listed_after_ids = [a["assistantAssociationId"] for a in listed_after]
    assert assoc_id not in listed_after_ids, (
        f"expected {assoc_id!r} to be excluded from ListAssistantAssociations after delete, "
        f"found it among {listed_after_ids!r}"
    )

    # a mutation on the dead id must also fail, not silently no-op
    redelete_code, redelete_message = _error(
        lambda: wisdom.delete_assistant_association(assistantId=assistant_id, assistantAssociationId=assoc_id)
    )
    assert redelete_code == "ResourceNotFoundException", (
        f"expected re-deleting an already-deleted association to raise ResourceNotFoundException, "
        f"got {redelete_code!r}"
    )
    assert redelete_message == "Assistant Association does not exist.", (
        f"expected the association not-found message on re-delete, got {redelete_message!r}"
    )


def _safe_delete(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
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
