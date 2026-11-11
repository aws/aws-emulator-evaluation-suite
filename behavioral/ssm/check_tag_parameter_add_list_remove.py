"""tag-parameter-add-list-remove."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-parameter-add-list-remove"
GROUP = 'state-machine'
SERVICES = ['ssm']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddTagsToResource / ListTagsForResource / RemoveTagsFromResource round-trip on a parameter."""

    ssm = ctx.client("ssm")

    def _param_name(suffix=""):
        # SSM requires a leading '/' for any hierarchical (slash-containing) name.
        return "/" + ctx.unique_name("sim2real-behav-" + suffix)

    def _track_parameter(name):
        ctx.on_cleanup(lambda: ssm.delete_parameter(Name=name))
        return name

    name = _param_name("probe-param-tags-")
    _track_parameter(name)
    ssm.put_parameter(Name=name, Value="v1", Type="String")

    ssm.add_tags_to_resource(
        ResourceType="Parameter",
        ResourceId=name,
        Tags=[{"Key": "env", "Value": "test"}],
    )

    tags = ssm.list_tags_for_resource(ResourceType="Parameter", ResourceId=name)["TagList"]
    tag_map = {t["Key"]: t["Value"] for t in tags}
    assert tag_map.get("env") == "test", f"expected tag env=test, got {tag_map}"

    ssm.remove_tags_from_resource(ResourceType="Parameter", ResourceId=name, TagKeys=["env"])

    tags_after = ssm.list_tags_for_resource(ResourceType="Parameter", ResourceId=name)["TagList"]
    assert all(t["Key"] != "env" for t in tags_after), "tag should have been removed"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
