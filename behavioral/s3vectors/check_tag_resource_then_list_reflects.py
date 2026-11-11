"""tag-resource-then-list-reflects."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-then-list-reflects"
GROUP = "data-plane"
SERVICES = ["s3vectors"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource attaches key/value tags on a vector index that appear verbatim in ListTagsForResource."""
    s3v = ctx.client("s3vectors")

    bucket_name = ctx.unique_name("sim2real-s3v-")
    index_name = ctx.unique_name("sim2real-idx-")
    s3v.create_vector_bucket(vectorBucketName=bucket_name)
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))
    index_arn = s3v.create_index(
        vectorBucketName=bucket_name,
        indexName=index_name,
        dataType="float32",
        dimension=4,
        distanceMetric="cosine",
    )["indexArn"]
    ctx.on_cleanup(lambda: s3v.delete_index(vectorBucketName=bucket_name, indexName=index_name))

    s3v.tag_resource(resourceArn=index_arn, tags={"team": "search-infra", "stage": "behavioral"})

    resource_tags = s3v.list_tags_for_resource(resourceArn=index_arn)["tags"]
    assert resource_tags.get("team") == "search-infra", (
        f"expected tag team=search-infra, got {resource_tags.get('team')!r}"
    )
    assert resource_tags.get("stage") == "behavioral", (
        f"expected tag stage=behavioral, got {resource_tags.get('stage')!r}"
    )
    assert len(resource_tags) == 2, f"expected exactly 2 tags, got {resource_tags!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
