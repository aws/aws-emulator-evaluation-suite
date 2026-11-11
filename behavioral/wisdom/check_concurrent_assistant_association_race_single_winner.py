"""concurrent-assistant-association-race-single-winner."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-assistant-association-race-single-winner"
GROUP = "concurrency"
SERVICES = ["wisdom"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Of two concurrent CreateAssistantAssociation calls for the same knowledge base, exactly one
    succeeds and the other fails with ConflictException and the exact duplicate message; only the
    winner's association is listed.
    """
    wisdom = ctx.client("wisdom")
    assistant = wisdom.create_assistant(
        name=ctx.unique_name("sim2real-asst-"), type="AGENT", tags={"sim2real": "true"}
    )["assistant"]
    assistant_id = assistant["assistantId"]
    ctx.on_cleanup(lambda: wisdom.delete_assistant(assistantId=assistant_id))

    kb = wisdom.create_knowledge_base(
        name=ctx.unique_name("sim2real-kb-"), knowledgeBaseType="CUSTOM", tags={"sim2real": "true"}
    )[
        "knowledgeBase"
    ]
    kb_id = kb["knowledgeBaseId"]
    ctx.on_cleanup(lambda: wisdom.delete_knowledge_base(knowledgeBaseId=kb_id))

    def _race(_):
        try:
            resp = wisdom.create_assistant_association(
                assistantId=assistant_id,
                associationType="KNOWLEDGE_BASE",
                association={"knowledgeBaseId": kb_id},
            )
            return ("ok", resp["assistantAssociation"]["assistantAssociationId"])
        except ClientError as e:
            return ("error", e.response["Error"]["Code"], e.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(_race, [0, 1]))

    winners = [r for r in results if r[0] == "ok"]
    losers = [r for r in results if r[0] == "error"]
    assert len(winners) == 1, f"expected exactly one winner, got {results!r}"
    assert len(losers) == 1, f"expected exactly one loser, got {results!r}"
    assert losers[0][1] == "ConflictException", f"expected ConflictException, got {results!r}"
    assert losers[0][2] == "Association already exists for these two resources", (
        f"unexpected ConflictException message, got {results!r}"
    )

    winner_assoc_id = winners[0][1]
    ctx.on_cleanup(
        lambda: wisdom.delete_assistant_association(
            assistantId=assistant_id, assistantAssociationId=winner_assoc_id
        )
    )

    listed = wisdom.list_assistant_associations(assistantId=assistant_id)[
        "assistantAssociationSummaries"
    ]
    assert len(listed) == 1, f"expected exactly 1 surviving association, got {listed!r}"
    assert listed[0]["assistantAssociationId"] == winner_assoc_id, (
        f"expected surviving association to be the race winner {winner_assoc_id!r}, "
        f"got {listed[0]['assistantAssociationId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
