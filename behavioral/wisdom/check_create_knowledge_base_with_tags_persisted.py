"""create-knowledge-base-with-tags-persisted."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-knowledge-base-with-tags-persisted"
GROUP = "lifecycle"
SERVICES = ["wisdom"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags supplied inline on CreateKnowledgeBase are persisted and visible both on
    GetKnowledgeBase.tags and via ListTagsForResource."""
    wisdom = ctx.client("wisdom")
    name = ctx.unique_name("sim2real-behav-kb-")
    created = wisdom.create_knowledge_base(
        name=name, knowledgeBaseType="CUSTOM", tags={"team": "support", "stage": "sim2real-behav"}
    )["knowledgeBase"]
    kb_id = created["knowledgeBaseId"]
    kb_arn = created["knowledgeBaseArn"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: wisdom.delete_knowledge_base(knowledgeBaseId=kb_id)))

    expected_tags = {"team": "support", "stage": "sim2real-behav"}
    assert created.get("tags") == expected_tags, f"expected {expected_tags}, CreateKnowledgeBase returned {created.get('tags')!r}"

    reread = wisdom.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]
    assert reread.get("tags") == expected_tags, f"expected {expected_tags}, GetKnowledgeBase returned {reread.get('tags')!r}"

    via_list_tags = wisdom.list_tags_for_resource(resourceArn=kb_arn)["tags"]
    assert via_list_tags == expected_tags, f"expected {expected_tags}, ListTagsForResource returned {via_list_tags!r}"


def _safe_delete(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
