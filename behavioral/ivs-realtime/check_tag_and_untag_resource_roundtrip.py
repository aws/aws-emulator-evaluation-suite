"""tag-and-untag-resource-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-and-untag-resource-roundtrip"
GROUP = "tagging"
SERVICES = ["ivs-realtime"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/ListTagsForResource/UntagResource round-trip on a Stage."""
    ivs = ctx.client("ivs-realtime")
    arn = ivs.create_stage(name=ctx.unique_name("sim2real-stage-"))["stage"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_stage(arn=arn))

    ivs.tag_resource(resourceArn=arn, tags={"env": "sim2real", "owner": "behavioral"})
    tags = ivs.list_tags_for_resource(resourceArn=arn)["tags"]
    expected_after_tag = {"env": "sim2real", "owner": "behavioral"}
    assert tags == expected_after_tag, f"expected {expected_after_tag}, got {tags}"

    ivs.untag_resource(resourceArn=arn, tagKeys=["owner"])
    tags = ivs.list_tags_for_resource(resourceArn=arn)["tags"]
    expected_after_untag = {"env": "sim2real"}
    assert tags == expected_after_untag, f"expected {expected_after_untag}, got {tags}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
