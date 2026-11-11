"""tag-resource-unicode-round-trip."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "tag-resource-unicode-round-trip"
GROUP = "representation"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode tag keys and values survive TagResource and are returned unchanged
    by ListTagsForResource."""
    s3tables = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx)

    tags = {
        "\u00e9quipe": "\u5317\u4eac-\u30c1\u30fc\u30e0",
        "owner-\u00fcml\u00e4ut": "\u00e7\u00e0f\u00e9-\u0645\u0631\u062d\u0628\u0627",
    }
    s3tables.tag_resource(resourceArn=bucket_arn, tags=tags)
    ctx.on_cleanup(
        lambda: s3tables.untag_resource(resourceArn=bucket_arn, tagKeys=list(tags.keys()))
    )

    got = s3tables.list_tags_for_resource(resourceArn=bucket_arn)["tags"]
    assert len(got) == len(tags), f"expected {len(tags)} tags, ListTagsForResource returned {got!r}"
    for key, value in tags.items():
        assert got[key] == value, f"tag {key!r} round-tripped as {got.get(key)!r}, expected {value!r}"


def _create_table_bucket(ctx: Any) -> str:
    s3tables = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-tags-")
    arn = s3tables.create_table_bucket(name=name)["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=arn))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
