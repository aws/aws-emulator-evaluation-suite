"""assistant-association-client-token-idempotent-conflict-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assistant-association-client-token-idempotent-conflict-rejected"
GROUP = "idempotency"
SERVICES = ["wisdom"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAssistantAssociation reusing a clientToken with identical parameters returns the original
    association; with a different knowledgeBaseId it fails with ConflictException and the exact
    message, and only the original association is listed.
    """
    wisdom = ctx.client("wisdom")
    assistant = wisdom.create_assistant(name=ctx.unique_name("sim2real-asst-"), type="AGENT")["assistant"]
    assistant_id = assistant["assistantId"]
    ctx.on_cleanup(lambda: wisdom.delete_assistant(assistantId=assistant_id))

    kb1 = wisdom.create_knowledge_base(name=ctx.unique_name("sim2real-kb1-"), knowledgeBaseType="CUSTOM")[
        "knowledgeBase"
    ]
    kb1_id = kb1["knowledgeBaseId"]
    ctx.on_cleanup(lambda: wisdom.delete_knowledge_base(knowledgeBaseId=kb1_id))
    kb2 = wisdom.create_knowledge_base(name=ctx.unique_name("sim2real-kb2-"), knowledgeBaseType="CUSTOM")[
        "knowledgeBase"
    ]
    kb2_id = kb2["knowledgeBaseId"]
    ctx.on_cleanup(lambda: wisdom.delete_knowledge_base(knowledgeBaseId=kb2_id))

    token = ctx.unique_name("sim2real-assoc-token-")
    first = wisdom.create_assistant_association(
        assistantId=assistant_id,
        associationType="KNOWLEDGE_BASE",
        association={"knowledgeBaseId": kb1_id},
        clientToken=token,
    )["assistantAssociation"]
    assoc_id = first["assistantAssociationId"]
    ctx.on_cleanup(
        lambda: wisdom.delete_assistant_association(assistantId=assistant_id, assistantAssociationId=assoc_id)
    )

    # positive control: same token + identical params is idempotent
    repeat = wisdom.create_assistant_association(
        assistantId=assistant_id,
        associationType="KNOWLEDGE_BASE",
        association={"knowledgeBaseId": kb1_id},
        clientToken=token,
    )["assistantAssociation"]
    assert repeat["assistantAssociationId"] == assoc_id, (
        f"expected clientToken reuse with identical params to return the original association "
        f"{assoc_id!r} idempotently, got {repeat['assistantAssociationId']!r}"
    )

    # break exactly one thing: reuse the token with a different knowledgeBaseId
    code, message = _error(
        lambda: wisdom.create_assistant_association(
            assistantId=assistant_id,
            associationType="KNOWLEDGE_BASE",
            association={"knowledgeBaseId": kb2_id},
            clientToken=token,
        )
    )
    assert code == "ConflictException", f"expected ConflictException for clientToken reused with a different knowledgeBaseId, got {code!r}"
    assert message == "Idempotency conflict", f"expected the idempotency-conflict message, got {message!r}"

    # effect absent: the assistant still has exactly one association, unchanged
    listed = wisdom.list_assistant_associations(assistantId=assistant_id)["assistantAssociationSummaries"]
    assert len(listed) == 1, f"expected exactly 1 association after the rejected reuse, got {len(listed)}: {listed!r}"
    assert listed[0]["assistantAssociationId"] == assoc_id, (
        f"expected the sole listed association to still be the original {assoc_id!r}, got {listed[0]['assistantAssociationId']!r}"
    )


def _error(fn):
    """Return the (code, message) of the ClientError fn() raises; a success fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
