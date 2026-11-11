"""tag-resource-and-list-tags-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-and-list-tags-round-trip"
GROUP = "server-side"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags applied via TagResource are returned unchanged (key/value byte-equality) by
    ListTagsForResource."""
    s3t = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx)

    tags = {"sim2real-env": "behavioral", "sim2real-purpose": "tag-round-trip"}
    s3t.tag_resource(resourceArn=bucket_arn, tags=tags)

    got = s3t.list_tags_for_resource(resourceArn=bucket_arn)["tags"]
    assert got == tags, f"list_tags_for_resource returned {got!r}, expected {tags!r}"


def _create_table_bucket(ctx):
    s3t = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-")
    arn = s3t.create_table_bucket(name=name)["arn"]
    ctx.on_cleanup(lambda: s3t.delete_table_bucket(tableBucketARN=arn))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
