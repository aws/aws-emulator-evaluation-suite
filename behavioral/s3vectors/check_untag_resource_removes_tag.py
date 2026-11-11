"""untag-resource-removes-tag."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-removes-tag"
GROUP = "state-machine"
SERVICES = ["s3vectors"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes exactly the requested tag key, leaving other tags intact."""
    s3v = ctx.client("s3vectors")

    bucket_name = ctx.unique_name("sim2real-s3v-")
    bucket_arn = s3v.create_vector_bucket(vectorBucketName=bucket_name)["vectorBucketArn"]
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))

    s3v.tag_resource(resourceArn=bucket_arn, tags={"purpose": "behavioral-check", "keep": "yes"})
    tags_before = s3v.list_tags_for_resource(resourceArn=bucket_arn)["tags"]
    assert tags_before.get("purpose") == "behavioral-check", f"expected purpose=behavioral-check, got {tags_before!r}"
    assert tags_before.get("keep") == "yes", f"expected keep=yes, got {tags_before!r}"
    assert len(tags_before) == 2, f"expected exactly 2 tags before untag, got {tags_before!r}"

    s3v.untag_resource(resourceArn=bucket_arn, tagKeys=["purpose"])

    tags_after = s3v.list_tags_for_resource(resourceArn=bucket_arn)["tags"]
    assert "purpose" not in tags_after, f"removed tag key still present: {tags_after!r}"
    assert tags_after.get("keep") == "yes", f"expected unrelated tag keep=yes to survive, got {tags_after!r}"
    assert len(tags_after) == 1, f"expected exactly 1 tag after untag, got {tags_after!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
