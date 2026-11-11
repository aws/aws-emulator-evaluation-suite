"""untag-resource-removes-only-specified-key."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-removes-only-specified-key"
GROUP = "state"
SERVICES = ["synthetics"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes exactly the requested tag keys and leaves the rest intact."""
    synth = ctx.client("synthetics")
    group_name = ctx.unique_name("sim2real-group-")
    group_arn = synth.create_group(Name=group_name, Tags={"team": "sim2real", "env": "test"})["Group"]["Arn"]
    ctx.on_cleanup(lambda: synth.delete_group(GroupIdentifier=group_name))

    synth.untag_resource(ResourceArn=group_arn, TagKeys=["env"])

    tags = synth.list_tags_for_resource(ResourceArn=group_arn)["Tags"]
    assert "env" not in tags, f"'env' tag key still present: {tags}"
    assert tags.get("team") == "sim2real", f"unrelated tag 'team' was unexpectedly modified: {tags}"
    assert tags == {"team": "sim2real"}, f"expected only 'team' to remain after untag, got {tags}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
