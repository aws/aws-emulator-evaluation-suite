"""tag-untag-resource-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-untag-resource-round-trip"
GROUP = "tagging"
SERVICES = ["appstream"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource makes tags visible via ListTagsForResource; UntagResource removes only the named key, leaving other tags on the resource untouched."""
    appstream = ctx.client("appstream")

    stack_name = ctx.unique_name("sim2real-appstream-stack-")
    arn = appstream.create_stack(Name=stack_name)["Stack"]["Arn"]
    ctx.on_cleanup(lambda: appstream.delete_stack(Name=stack_name))

    appstream.tag_resource(
        ResourceArn=arn,
        Tags={"sim2real-key": "sim2real-value", "sim2real-keep": "sim2real-keep-value"},
    )

    tags = appstream.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags.get("sim2real-key") == "sim2real-value", (
        f"expected sim2real-key=sim2real-value after TagResource, got {tags.get('sim2real-key')!r}"
    )
    assert tags.get("sim2real-keep") == "sim2real-keep-value", (
        f"expected sim2real-keep=sim2real-keep-value after TagResource, got {tags.get('sim2real-keep')!r}"
    )

    appstream.untag_resource(ResourceArn=arn, TagKeys=["sim2real-key"])

    tags_after = appstream.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert "sim2real-key" not in tags_after, (
        f"expected sim2real-key removed by UntagResource, still present in {tags_after}"
    )
    assert tags_after.get("sim2real-keep") == "sim2real-keep-value", (
        f"expected sim2real-keep untouched by UntagResource, got {tags_after.get('sim2real-keep')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
