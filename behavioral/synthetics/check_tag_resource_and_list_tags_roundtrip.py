"""tag-resource-and-list-tags-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-and-list-tags-roundtrip"
GROUP = "state"
SERVICES = ["synthetics"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource persists tags that are then visible via ListTagsForResource, and GetGroup."""
    synth = ctx.client("synthetics")
    group_name = ctx.unique_name("sim2real-group-")
    group_arn = synth.create_group(Name=group_name)["Group"]["Arn"]
    ctx.on_cleanup(lambda: synth.delete_group(GroupIdentifier=group_name))

    synth.tag_resource(ResourceArn=group_arn, Tags={"team": "sim2real", "env": "test"})

    tags = synth.list_tags_for_resource(ResourceArn=group_arn)["Tags"]
    expected = {"team": "sim2real", "env": "test"}
    assert tags == expected, f"ListTagsForResource expected {expected}, got {tags}"

    group_tags = synth.get_group(GroupIdentifier=group_name)["Group"]["Tags"]
    assert group_tags == expected, f"GetGroup expected {expected}, got {group_tags}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
