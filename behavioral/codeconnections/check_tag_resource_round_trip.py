"""tag-resource-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-round-trip"
GROUP = "tags"
SERVICES = ["codeconnections"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/ListTagsForResource/UntagResource round-trip on a connection: tags
    accumulate, a specific untag removes only that key, and the last untag empties it."""
    cc = ctx.client("codeconnections")
    name = ctx.unique_name("sim2real-conn-")[:32]
    arn = cc.create_connection(ConnectionName=name, ProviderType="GitHub")["ConnectionArn"]
    ctx.on_cleanup(lambda: cc.delete_connection(ConnectionArn=arn))

    cc.tag_resource(
        ResourceArn=arn,
        Tags=[{"Key": "team", "Value": "payments"}, {"Key": "env", "Value": "test"}],
    )
    tags = {t["Key"]: t["Value"] for t in cc.list_tags_for_resource(ResourceArn=arn)["Tags"]}
    assert tags == {"team": "payments", "env": "test"}, f"expected both tags to accumulate, got {tags}"

    cc.untag_resource(ResourceArn=arn, TagKeys=["env"])
    tags = {t["Key"]: t["Value"] for t in cc.list_tags_for_resource(ResourceArn=arn)["Tags"]}
    assert tags == {"team": "payments"}, f"expected only 'env' removed, got {tags}"

    cc.untag_resource(ResourceArn=arn, TagKeys=["team"])
    tags = {t["Key"]: t["Value"] for t in cc.list_tags_for_resource(ResourceArn=arn)["Tags"]}
    assert tags == {}, f"expected last untag to empty the tag set, got {tags}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
