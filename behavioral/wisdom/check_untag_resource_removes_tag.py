"""untag-resource-removes-tag."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "untag-resource-removes-tag"
GROUP = "tagging"
SERVICES = ["wisdom"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes exactly the named tag key, leaving other tags on the resource
    untouched."""
    wisdom = ctx.client("wisdom")
    kb = wisdom.create_knowledge_base(
        name=ctx.unique_name("sim2real-behav-kb-"),
        knowledgeBaseType="CUSTOM",
        tags={"keep": "yes", "remove": "please"},
    )["knowledgeBase"]
    kb_id = kb["knowledgeBaseId"]
    kb_arn = kb["knowledgeBaseArn"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: wisdom.delete_knowledge_base(knowledgeBaseId=kb_id)))

    before = wisdom.list_tags_for_resource(resourceArn=kb_arn)["tags"]
    assert before == {"keep": "yes", "remove": "please"}, f"before={before!r}"

    wisdom.untag_resource(resourceArn=kb_arn, tagKeys=["remove"])

    after = wisdom.list_tags_for_resource(resourceArn=kb_arn)["tags"]
    assert after == {"keep": "yes"}, f"after={after!r}, expected only 'keep' to survive untag"


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
