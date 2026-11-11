"""tag-resource-persists-tags."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-persists-tags"
GROUP = "state"
SERVICES = ["mediapackage"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource adds tags to a Channel's ARN and ListTagsForResource (and DescribeChannel's
    embedded Tags) reflect exactly the tags that were added, merged with tags set at creation."""
    mp = ctx.client("mediapackage")
    channel_id = ctx.unique_name("sim2real-mp-ch-")
    created = mp.create_channel(Id=channel_id, Tags={"created-by": "sim2real"})
    ctx.on_cleanup(lambda: mp.delete_channel(Id=channel_id))
    arn = created["Arn"]

    mp.tag_resource(ResourceArn=arn, Tags={"env": "test", "owner": "behavioral-check"})

    expected = {"created-by": "sim2real", "env": "test", "owner": "behavioral-check"}

    tags = mp.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags["created-by"] == "sim2real", f"expected created-by=sim2real, got {tags!r}"
    assert tags["env"] == "test", f"expected env=test, got {tags!r}"
    assert tags["owner"] == "behavioral-check", f"expected owner=behavioral-check, got {tags!r}"
    assert tags == expected, f"ListTagsForResource must reflect exactly {expected}, got {tags!r}"

    described = mp.describe_channel(Id=channel_id)
    assert described["Tags"]["env"] == "test", f"expected env=test, got {described['Tags']!r}"
    assert described["Tags"]["owner"] == "behavioral-check", (
        f"expected owner=behavioral-check, got {described['Tags']!r}"
    )
    assert described["Tags"] == expected, (
        f"DescribeChannel embedded Tags must reflect exactly {expected}, got {described['Tags']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
