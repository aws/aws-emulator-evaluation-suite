"""assistant-association-multiple-distinct-knowledge-bases-allowed."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "assistant-association-multiple-distinct-knowledge-bases-allowed"
GROUP = "state-machine"
SERVICES = ["wisdom"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An assistant takes associations to two distinct knowledge bases, both listed; repeating one fails
    with ConflictException and the exact duplicate message, leaving the list unchanged, and once deleted
    that knowledge base can be associated again.
    """
    wisdom = ctx.client("wisdom")
    assistant = wisdom.create_assistant(name=ctx.unique_name("sim2real-behav-asst-"), type="AGENT")["assistant"]
    assistant_id = assistant["assistantId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: wisdom.delete_assistant(assistantId=assistant_id)))
    _poll_until(
        lambda: wisdom.get_assistant(assistantId=assistant_id)["assistant"],
        lambda a: a["status"] == "ACTIVE",
        timeout_s=60.0,
    )

    kb1 = wisdom.create_knowledge_base(name=ctx.unique_name("sim2real-behav-kb1-"), knowledgeBaseType="CUSTOM")[
        "knowledgeBase"
    ]
    kb1_id = kb1["knowledgeBaseId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: wisdom.delete_knowledge_base(knowledgeBaseId=kb1_id)))
    _poll_until(
        lambda: wisdom.get_knowledge_base(knowledgeBaseId=kb1_id)["knowledgeBase"],
        lambda k: k["status"] == "ACTIVE",
        timeout_s=60.0,
    )

    kb2 = wisdom.create_knowledge_base(name=ctx.unique_name("sim2real-behav-kb2-"), knowledgeBaseType="CUSTOM")[
        "knowledgeBase"
    ]
    kb2_id = kb2["knowledgeBaseId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: wisdom.delete_knowledge_base(knowledgeBaseId=kb2_id)))
    _poll_until(
        lambda: wisdom.get_knowledge_base(knowledgeBaseId=kb2_id)["knowledgeBase"],
        lambda k: k["status"] == "ACTIVE",
        timeout_s=60.0,
    )

    assoc1 = wisdom.create_assistant_association(
        assistantId=assistant_id, associationType="KNOWLEDGE_BASE", association={"knowledgeBaseId": kb1_id}
    )["assistantAssociation"]
    assoc1_id = assoc1["assistantAssociationId"]
    ctx.on_cleanup(
        lambda: _safe_delete(
            lambda: wisdom.delete_assistant_association(assistantId=assistant_id, assistantAssociationId=assoc1_id)
        )
    )

    # a second association to a DIFFERENT knowledge base succeeds
    assoc2 = wisdom.create_assistant_association(
        assistantId=assistant_id, associationType="KNOWLEDGE_BASE", association={"knowledgeBaseId": kb2_id}
    )["assistantAssociation"]
    assoc2_id = assoc2["assistantAssociationId"]
    ctx.on_cleanup(
        lambda: _safe_delete(
            lambda: wisdom.delete_assistant_association(assistantId=assistant_id, assistantAssociationId=assoc2_id)
        )
    )

    listed_ids = {
        a["assistantAssociationId"]
        for a in wisdom.list_assistant_associations(assistantId=assistant_id)["assistantAssociationSummaries"]
    }
    assert listed_ids == {assoc1_id, assoc2_id}, f"expected both associations listed, got {listed_ids!r}"

    # re-associating the SAME knowledge base a second time is rejected as an exact duplicate
    code, message = _error(
        lambda: wisdom.create_assistant_association(
            assistantId=assistant_id, associationType="KNOWLEDGE_BASE", association={"knowledgeBaseId": kb1_id}
        )
    )
    assert code == "ConflictException", f"expected ConflictException for exact-duplicate KB association, got {code!r}"
    assert message == "Association already exists for these two resources", (
        f"expected the duplicate-association refusal message, got {message!r}"
    )

    # effect absent: the rejected duplicate did not sneak a third association into the list
    listed_after_conflict = {
        a["assistantAssociationId"]
        for a in wisdom.list_assistant_associations(assistantId=assistant_id)["assistantAssociationSummaries"]
    }
    assert listed_after_conflict == {assoc1_id, assoc2_id}, (
        f"a rejected duplicate association changed the list: {listed_after_conflict!r}"
    )

    # restore: remove the original kb1 association, then the identical call now succeeds --
    # proving the ConflictException was about the existing association, not about kb1 itself
    wisdom.delete_assistant_association(assistantId=assistant_id, assistantAssociationId=assoc1_id)
    gone = _poll_bool(
        lambda: _is_not_found(
            lambda: wisdom.get_assistant_association(assistantId=assistant_id, assistantAssociationId=assoc1_id)
        ),
        timeout_s=60.0,
    )
    assert gone, "GetAssistantAssociation never returned ResourceNotFoundException after deleting assoc1"

    assoc1_retry = wisdom.create_assistant_association(
        assistantId=assistant_id, associationType="KNOWLEDGE_BASE", association={"knowledgeBaseId": kb1_id}
    )["assistantAssociation"]
    assoc1_retry_id = assoc1_retry["assistantAssociationId"]
    ctx.on_cleanup(
        lambda: _safe_delete(
            lambda: wisdom.delete_assistant_association(
                assistantId=assistant_id, assistantAssociationId=assoc1_retry_id
            )
        )
    )
    listed_final = {
        a["assistantAssociationId"]
        for a in wisdom.list_assistant_associations(assistantId=assistant_id)["assistantAssociationSummaries"]
    }
    assert listed_final == {assoc1_retry_id, assoc2_id}, (
        f"expected kb1 to be re-associable once the original association was deleted, got {listed_final!r}"
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


def _is_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        return False
    except ClientError as err:
        return err.response["Error"]["Code"] == "ResourceNotFoundException"


def _poll_bool(probe, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if probe():
            return True
        time.sleep(interval_s)
    return False


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
