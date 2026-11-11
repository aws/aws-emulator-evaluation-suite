"""duplicate-assistant-association-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicate-assistant-association-rejected"
GROUP = "state"
SERVICES = ["qconnect"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateAssistantAssociation for the same assistant and knowledge base fails with
    ConflictException ("Association already exists for these two resources") while the first
    exists; after the first is deleted, the identical call creates a new association."""
    qc = ctx.client("qconnect")
    assistant_id = _create_active_assistant(ctx, qc)
    kb_id = _create_active_knowledge_base(ctx, qc, "CUSTOM")

    first = qc.create_assistant_association(
        assistantId=assistant_id,
        associationType="KNOWLEDGE_BASE",
        association={"knowledgeBaseId": kb_id},
    )["assistantAssociation"]
    association_id = first["assistantAssociationId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: qc.delete_assistant_association(
                assistantId=assistant_id, assistantAssociationId=association_id
            )
        )
    )

    code, message = _client_error(
        lambda: qc.create_assistant_association(
            assistantId=assistant_id,
            associationType="KNOWLEDGE_BASE",
            association={"knowledgeBaseId": kb_id},
        )
    )
    assert code == "ConflictException", repr(code)
    assert message == "Association already exists for these two resources", f"unexpected message {message!r}"

    associations = qc.list_assistant_associations(assistantId=assistant_id)["assistantAssociationSummaries"]
    ids = {a["assistantAssociationId"] for a in associations}
    assert ids == {association_id}, f"expected exactly the original association {association_id} to survive, found {ids}"

    # restore: deleting the blocking association lifts the conflict, and the identical
    # call succeeds again -- the rejection is specific to the live duplicate, not a
    # blanket refusal of a second CreateAssistantAssociation on this assistant
    qc.delete_assistant_association(assistantId=assistant_id, assistantAssociationId=association_id)
    remaining = _poll_until(
        lambda: {
            a["assistantAssociationId"]
            for a in qc.list_assistant_associations(assistantId=assistant_id)["assistantAssociationSummaries"]
        },
        lambda ids_now: association_id not in ids_now,
        timeout_s=60.0,
    )
    assert association_id not in remaining, f"expected {association_id} gone after delete, found {remaining}"

    restored = qc.create_assistant_association(
        assistantId=assistant_id,
        associationType="KNOWLEDGE_BASE",
        association={"knowledgeBaseId": kb_id},
    )["assistantAssociation"]
    restored_id = restored["assistantAssociationId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: qc.delete_assistant_association(
                assistantId=assistant_id, assistantAssociationId=restored_id
            )
        )
    )
    assert restored_id != association_id, "expected a freshly minted association id after restore"

    final_ids = {
        a["assistantAssociationId"]
        for a in qc.list_assistant_associations(assistantId=assistant_id)["assistantAssociationSummaries"]
    }
    assert final_ids == {restored_id}, f"expected exactly the restored association {restored_id}, found {final_ids}"


def _create_active_assistant(ctx, qc) -> str:
    name = ctx.unique_name("sim2real-qc-asst-")
    assistant_id = qc.create_assistant(name=name, type="AGENT")["assistant"]["assistantId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: qc.delete_assistant(assistantId=assistant_id)))
    status = _poll_until(
        lambda: qc.get_assistant(assistantId=assistant_id)["assistant"]["status"],
        lambda s: s in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert status == "ACTIVE", f"expected assistant {assistant_id} to become ACTIVE, got {status}"
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
    assert status == "ACTIVE", f"expected knowledge base {kb_id} to become ACTIVE, got {status}"
    return kb_id


def _client_error(fn):
    """Call fn(); return the (code, message) it is refused with. An unexpected success raises,
    so a target that accepts what AWS refuses reads as an acceptance, not a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
            raise TimeoutError(f"condition not met within {timeout_s}s; last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
