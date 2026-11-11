"""tag-resource-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-lifecycle"
GROUP = "state"
SERVICES = ["gamelift"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource attaches tags to a GameLift resource that are visible via
    ListTagsForResource, and UntagResource removes exactly the requested keys
    while leaving the rest intact."""
    gl = ctx.client("gamelift")
    name = ctx.unique_name("sim2real-tag-alias-")
    alias = gl.create_alias(
        Name=name,
        RoutingStrategy={"Type": "TERMINAL", "Message": "tagging target"},
    )["Alias"]
    alias_arn = alias["AliasArn"]
    ctx.on_cleanup(lambda: gl.delete_alias(AliasId=alias["AliasId"]))

    gl.tag_resource(
        ResourceARN=alias_arn,
        Tags=[{"Key": "env", "Value": "sim2real"}, {"Key": "owner", "Value": "behavioral"}],
    )

    tags = {t["Key"]: t["Value"] for t in gl.list_tags_for_resource(ResourceARN=alias_arn)["Tags"]}
    assert tags == {"env": "sim2real", "owner": "behavioral"}, (
        f"expected tags {{'env': 'sim2real', 'owner': 'behavioral'}} after TagResource, got {tags}"
    )

    gl.untag_resource(ResourceARN=alias_arn, TagKeys=["owner"])

    tags_after = {
        t["Key"]: t["Value"] for t in gl.list_tags_for_resource(ResourceARN=alias_arn)["Tags"]
    }
    assert tags_after == {"env": "sim2real"}, (
        f"expected only {{'env': 'sim2real'}} to remain after UntagResource(['owner']), got {tags_after}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
