"""tag-resource-and-list."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-and-list"
GROUP = 'tags'
SERVICES = ['xray']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource attaches tags to a group ARN and ListTagsForResource reflects them."""
    xr = ctx.client("xray")
    name = ctx.unique_name("sim2real-behav-xray-grp-")[:32].rstrip("-")
    resp = xr.create_group(GroupName=name, FilterExpression='service("default")')
    ctx.on_cleanup(lambda: xr.delete_group(GroupName=name))
    arn = resp["Group"]["GroupARN"]

    xr.tag_resource(
        ResourceARN=arn, Tags=[{"Key": "env", "Value": "test"}, {"Key": "team", "Value": "obs"}]
    )

    tags = xr.list_tags_for_resource(ResourceARN=arn)["Tags"]
    tag_map = {t["Key"]: t["Value"] for t in tags}
    assert tag_map.get("env") == "test", tag_map
    assert tag_map.get("team") == "obs", tag_map


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
