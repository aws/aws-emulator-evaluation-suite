"""tag-resource-list-reflects-and-untag-removes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-list-reflects-and-untag-removes"
GROUP = "tagging"
SERVICES = ["chatbot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource on a custom action is reflected by ListTagsForResource, and
    UntagResource removes exactly the requested keys, leaving the rest untouched."""
    chatbot = ctx.client("chatbot")
    arn = chatbot.create_custom_action(
        ActionName=ctx.unique_name("sim2real-ca-"),
        Definition={"CommandText": "echo tagged"},
    )["CustomActionArn"]
    ctx.on_cleanup(lambda: chatbot.delete_custom_action(CustomActionArn=arn))

    initial_tags = chatbot.list_tags_for_resource(ResourceARN=arn)["Tags"]
    assert initial_tags == [], f"expected no tags on a freshly created resource, got {initial_tags!r}"

    chatbot.tag_resource(
        ResourceARN=arn,
        Tags=[
            {"TagKey": "env", "TagValue": "sim2real"},
            {"TagKey": "team", "TagValue": "platform"},
        ],
    )
    tags = {t["TagKey"]: t["TagValue"] for t in chatbot.list_tags_for_resource(ResourceARN=arn)["Tags"]}
    assert tags == {"env": "sim2real", "team": "platform"}, (
        f"expected {{'env': 'sim2real', 'team': 'platform'}} after TagResource, got {tags!r}"
    )

    chatbot.untag_resource(ResourceARN=arn, TagKeys=["env"])
    tags2 = {t["TagKey"]: t["TagValue"] for t in chatbot.list_tags_for_resource(ResourceARN=arn)["Tags"]}
    assert tags2 == {"team": "platform"}, (
        f"expected only {{'team': 'platform'}} to remain after untagging 'env', got {tags2!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
