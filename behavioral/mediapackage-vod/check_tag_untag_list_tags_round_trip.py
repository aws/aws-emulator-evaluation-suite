"""tag-untag-list-tags-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-untag-list-tags-round-trip"
GROUP = "state"
SERVICES = ["mediapackage-vod"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/UntagResource/ListTagsForResource round-trip on a packaging group: tags added
    are visible, and removing one tag leaves only the other."""
    mpv = ctx.client("mediapackage-vod")
    group_id = ctx.unique_name("sim2real-mpvod-group-")
    created = mpv.create_packaging_group(Id=group_id)
    arn = created["Arn"]
    ctx.on_cleanup(lambda: mpv.delete_packaging_group(Id=group_id))

    mpv.tag_resource(ResourceArn=arn, Tags={"env": "sim2real", "owner": "behavioral-suite"})
    current_tags = mpv.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert current_tags.get("env") == "sim2real", f"expected env=sim2real, got tags={current_tags!r}"
    assert current_tags.get("owner") == "behavioral-suite", (
        f"expected owner=behavioral-suite, got tags={current_tags!r}"
    )

    mpv.untag_resource(ResourceArn=arn, TagKeys=["owner"])
    tags_after = mpv.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags_after.get("env") == "sim2real", f"expected env=sim2real to survive untag, got tags={tags_after!r}"
    assert "owner" not in tags_after, f"expected owner removed by UntagResource, got tags={tags_after!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
