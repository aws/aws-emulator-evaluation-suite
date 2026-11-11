"""untag-resource-removes-tag-from-list."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-removes-tag-from-list"
GROUP = "state-machine"
SERVICES = ["s3vectors"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After UntagResource removes a key, ListTagsForResource no longer includes
    that key, confirming actual removal rather than soft-deletion or caching."""
    s3v = ctx.client("s3vectors")
    bucket_name = ctx.unique_name("sim2real-s3vec-")
    bucket_arn = s3v.create_vector_bucket(vectorBucketName=bucket_name)["vectorBucketArn"]
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))

    s3v.tag_resource(resourceArn=bucket_arn, tags={"keep-me": "1", "remove-me": "1"})
    tags_before = s3v.list_tags_for_resource(resourceArn=bucket_arn)["tags"]
    assert tags_before.get("keep-me") == "1", f"expected keep-me=1 before untag, got {tags_before.get('keep-me')!r}"
    assert tags_before.get("remove-me") == "1", f"expected remove-me=1 before untag, got {tags_before.get('remove-me')!r}"
    assert len(tags_before) == 2, f"expected 2 tags before untag, got {len(tags_before)}: {tags_before!r}"

    s3v.untag_resource(resourceArn=bucket_arn, tagKeys=["remove-me"])

    tags_after = s3v.list_tags_for_resource(resourceArn=bucket_arn)["tags"]
    assert "remove-me" not in tags_after, "removed tag key still present in ListTagsForResource"
    assert tags_after.get("keep-me") == "1", "unrelated tag key was unexpectedly affected"
    assert len(tags_after) == 1, f"expected exactly 1 tag after untag, got {len(tags_after)}: {tags_after!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
