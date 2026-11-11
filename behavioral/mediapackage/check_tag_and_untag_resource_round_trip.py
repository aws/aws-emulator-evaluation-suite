"""tag-and-untag-resource-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-and-untag-resource-round-trip"
GROUP = "state"
SERVICES = ["mediapackage"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource adds tags visible via ListTagsForResource; UntagResource removes
    exactly the specified keys without disturbing other tags."""
    mp = ctx.client("mediapackage")

    cid = ctx.unique_name("sim2real-mp-tagrt-")
    created = mp.create_channel(Id=cid, Tags={"keep": "yes"})
    ctx.on_cleanup(lambda: mp.delete_channel(Id=cid))
    arn = created["Arn"]

    mp.tag_resource(ResourceArn=arn, Tags={"stage": "one"})
    tags = mp.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags.get("stage") == "one", f"expected TagResource to set stage=one, got {tags.get('stage')!r}"
    assert tags.get("keep") == "yes", f"TagResource must not disturb tags set at creation, got {tags.get('keep')!r}"

    mp.untag_resource(ResourceArn=arn, TagKeys=["stage"])
    tags_after = mp.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert "stage" not in tags_after, f"UntagResource must remove 'stage', still present: {tags_after}"
    assert tags_after.get("keep") == "yes", "untagging one key must not remove unrelated tags"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
