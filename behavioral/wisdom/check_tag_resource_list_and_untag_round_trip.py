"""tag-resource-list-and-untag-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-list-and-untag-round-trip"
GROUP = "tagging"
SERVICES = ["wisdom"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource / ListTagsForResource / UntagResource form a consistent round trip on a Wisdom
    assistant."""
    wisdom = ctx.client("wisdom")
    assistant = wisdom.create_assistant(name=ctx.unique_name("sim2real-asst-"), type="AGENT")["assistant"]
    assistant_id = assistant["assistantId"]
    assistant_arn = assistant["assistantArn"]
    ctx.on_cleanup(lambda: wisdom.delete_assistant(assistantId=assistant_id))

    before = wisdom.list_tags_for_resource(resourceArn=assistant_arn)["tags"]
    assert before == {}, f"expected a freshly created assistant to have no tags, got {before!r}"

    wisdom.tag_resource(resourceArn=assistant_arn, tags={"env": "sim2real-behavioral"})
    tags = wisdom.list_tags_for_resource(resourceArn=assistant_arn)["tags"]
    assert tags == {"env": "sim2real-behavioral"}, f"expected the applied tag, got {tags!r}"

    wisdom.untag_resource(resourceArn=assistant_arn, tagKeys=["env"])
    after = wisdom.list_tags_for_resource(resourceArn=assistant_arn)["tags"]
    assert after == {}, f"expected untag_resource to remove the tag, but list_tags_for_resource returned {after!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
