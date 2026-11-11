"""tag-value-empty-string-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-value-empty-string-preserved"
GROUP = "server-side"
SERVICES = ["s3vectors"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource with an empty-string tag value stores and returns the empty string via
    ListTagsForResource -- the key must be present with value '', not absent entirely."""
    s3v = ctx.client("s3vectors")
    bucket_name = ctx.unique_name("sim2real-s3v-")
    s3v.create_vector_bucket(vectorBucketName=bucket_name)
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))
    bucket_arn = s3v.get_vector_bucket(vectorBucketName=bucket_name)["vectorBucket"]["vectorBucketArn"]

    s3v.tag_resource(resourceArn=bucket_arn, tags={"Owner": "", "Team": "platform"})

    tags = s3v.list_tags_for_resource(resourceArn=bucket_arn)["tags"]
    assert "Owner" in tags, "empty-string tag value was dropped instead of stored"
    assert tags["Owner"] == "", f"expected empty-string tag value, got {tags['Owner']!r}"
    # sanity: a normal sibling tag round-trips correctly too
    assert tags["Team"] == "platform", f"expected 'platform', got {tags['Team']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
