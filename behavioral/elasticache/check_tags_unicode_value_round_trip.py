"""tags-unicode-value-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tags-unicode-value-round-trip"
GROUP = "server-side"
SERVICES = ["elasticache"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddTagsToResource/ListTagsForResource round-trip a tag key/value containing unicode
    characters and embedded (non-leading/trailing) whitespace byte-identical."""
    ec = ctx.client("elasticache")
    name = ctx.unique_name("sim2real-tags-")
    create_resp = ec.create_cache_parameter_group(
        CacheParameterGroupName=name,
        CacheParameterGroupFamily="redis7",
        Description="unicode tag round-trip fidelity check",
    )
    arn = create_resp["CacheParameterGroup"]["ARN"]
    ctx.on_cleanup(lambda: ec.delete_cache_parameter_group(CacheParameterGroupName=name))

    tag_key = "проект:ключ üñïçödé"
    tag_value = "值 with embedded   multiple  spaces and ünïcode 日本語 text"

    ec.add_tags_to_resource(ResourceName=arn, Tags=[{"Key": tag_key, "Value": tag_value}])

    tags = ec.list_tags_for_resource(ResourceName=arn)["TagList"]
    matches = [t for t in tags if t["Key"] == tag_key]
    assert len(matches) == 1, f"expected exactly one tag with the unicode key, got {tags!r}"
    assert matches[0]["Value"] == tag_value, (
        f"tag value mangled on round-trip: {matches[0]['Value']!r} != {tag_value!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
