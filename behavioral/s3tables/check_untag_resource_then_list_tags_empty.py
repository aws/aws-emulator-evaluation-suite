"""untag-resource-then-list-tags-empty."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-then-list-tags-empty"
GROUP = "state-machine"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes a tag so a subsequent ListTagsForResource no longer
    includes it."""
    s3t = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx)

    tags = {"sim2real-team": "behavioral", "sim2real-keep": "yes"}
    s3t.tag_resource(resourceArn=bucket_arn, tags=tags)

    before = s3t.list_tags_for_resource(resourceArn=bucket_arn)["tags"]
    assert before == tags, f"expected tags {tags} right after TagResource, got {before}"

    s3t.untag_resource(resourceArn=bucket_arn, tagKeys=["sim2real-team"])

    after = s3t.list_tags_for_resource(resourceArn=bucket_arn)["tags"]
    assert "sim2real-team" not in after, f"expected 'sim2real-team' removed, still present in {after}"
    assert after == {"sim2real-keep": "yes"}, f"expected only {{'sim2real-keep': 'yes'}} to remain, got {after}"


def _create_table_bucket(ctx):
    s3t = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-")
    arn = s3t.create_table_bucket(name=name)["arn"]
    ctx.on_cleanup(lambda: s3t.delete_table_bucket(tableBucketARN=arn))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
