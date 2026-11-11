"""untag-resource-removes-tag."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-removes-tag"
GROUP = 'tags'
SERVICES = ['xray']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes only the specified keys, leaving other tags intact."""
    xr = ctx.client("xray")
    name = ctx.unique_name("sim2real-behav-xray-grp-")[:32].rstrip("-")
    resp = xr.create_group(GroupName=name, FilterExpression='service("default")')
    ctx.on_cleanup(lambda: xr.delete_group(GroupName=name))
    arn = resp["Group"]["GroupARN"]

    xr.tag_resource(
        ResourceARN=arn, Tags=[{"Key": "keep", "Value": "1"}, {"Key": "drop", "Value": "2"}]
    )
    xr.untag_resource(ResourceARN=arn, TagKeys=["drop"])

    tags = xr.list_tags_for_resource(ResourceARN=arn)["Tags"]
    tag_map = {t["Key"]: t["Value"] for t in tags}
    assert "drop" not in tag_map, tag_map
    assert tag_map.get("keep") == "1", tag_map


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
