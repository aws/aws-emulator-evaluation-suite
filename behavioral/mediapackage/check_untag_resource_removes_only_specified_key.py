"""untag-resource-removes-only-specified-key."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-removes-only-specified-key"
GROUP = "state"
SERVICES = ["mediapackage"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes exactly the requested tag keys and leaves every other tag on
    the resource untouched."""
    mp = ctx.client("mediapackage")
    channel_id = ctx.unique_name("sim2real-mp-ch-")
    created = mp.create_channel(
        Id=channel_id, Tags={"keep-a": "1", "keep-b": "2", "remove-me": "3"}
    )
    ctx.on_cleanup(lambda: mp.delete_channel(Id=channel_id))
    arn = created["Arn"]

    mp.untag_resource(ResourceArn=arn, TagKeys=["remove-me"])

    tags = mp.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert "remove-me" not in tags, f"expected 'remove-me' removed, still present in {tags!r}"
    assert tags["keep-a"] == "1", f"expected keep-a=1 preserved, got {tags.get('keep-a')!r}"
    assert tags["keep-b"] == "2", f"expected keep-b=2 preserved, got {tags.get('keep-b')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
