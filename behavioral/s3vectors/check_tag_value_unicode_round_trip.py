"""tag-value-unicode-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-value-unicode-round-trip"
GROUP = "representation"
SERVICES = ["s3vectors"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag key/value containing unicode characters written via TagResource
    is returned unchanged by ListTagsForResource."""
    s3v = ctx.client("s3vectors")
    bucket_name = ctx.unique_name("sim2real-s3vec-tag-")
    created = s3v.create_vector_bucket(vectorBucketName=bucket_name)
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))
    bucket_arn = created["vectorBucketArn"]

    tags = {
        "环境-Ünïcödé": "生产环境-café-北京",
        "Zweck": "Prüfung-テスト",
    }
    s3v.tag_resource(resourceArn=bucket_arn, tags=tags)
    ctx.on_cleanup(
        lambda: s3v.untag_resource(resourceArn=bucket_arn, tagKeys=list(tags.keys()))
    )

    fetched = s3v.list_tags_for_resource(resourceArn=bucket_arn)["tags"]
    for key, value in tags.items():
        assert key in fetched, f"tag key {key!r} missing from ListTagsForResource"
        assert fetched[key] == value, (
            f"tag value mismatch for {key!r}: {fetched[key]!r} != {value!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
