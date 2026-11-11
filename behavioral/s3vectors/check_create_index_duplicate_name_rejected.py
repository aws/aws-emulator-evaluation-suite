"""create-index-duplicate-name-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-index-duplicate-name-rejected"
GROUP = "error-semantics"
SERVICES = ["s3vectors"]

MSG_CONFLICT = "An index with the specified name already exists"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateIndex with a name already used in the vector bucket is ConflictException with the exact
    message and leaves the original index (dimension 8) unchanged, while a create with a distinct name
    succeeds."""
    s3v = ctx.client("s3vectors")
    bucket_name = ctx.unique_name("sim2real-s3vec-b-")
    s3v.create_vector_bucket(
        vectorBucketName=bucket_name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))

    index_name = ctx.unique_name("sim2real-idx-")
    s3v.create_index(
        vectorBucketName=bucket_name,
        indexName=index_name,
        dataType="float32",
        dimension=8,
        distanceMetric="cosine",
    )
    ctx.on_cleanup(lambda: s3v.delete_index(vectorBucketName=bucket_name, indexName=index_name))

    # Break exactly one thing: try to recreate the SAME index name, in the SAME
    # bucket, with a DIFFERENT dimension (would silently change the schema if
    # accepted).
    code, code_msg = _error(
        lambda: s3v.create_index(
            vectorBucketName=bucket_name,
            indexName=index_name,
            dataType="float32",
            dimension=16,
            distanceMetric="cosine",
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    assert code_msg == MSG_CONFLICT, f"unexpected {code!r} message {code_msg!r}"

    # Effect absent: the original index configuration (dimension=8) must be
    # unchanged -- not overwritten with dimension=16.
    got = s3v.get_index(vectorBucketName=bucket_name, indexName=index_name)
    assert got["index"]["dimension"] == 8, (
        f"original index dimension was overwritten: {got['index']['dimension']}"
    )

    # Positive control: creating an index with a DIFFERENT name in the same
    # bucket succeeds normally.
    other_name = ctx.unique_name("sim2real-idx-ok-")
    s3v.create_index(
        vectorBucketName=bucket_name,
        indexName=other_name,
        dataType="float32",
        dimension=8,
        distanceMetric="cosine",
    )
    ctx.on_cleanup(lambda: s3v.delete_index(vectorBucketName=bucket_name, indexName=other_name))
    other = s3v.get_index(vectorBucketName=bucket_name, indexName=other_name)
    assert other["index"]["indexName"] == other_name, (
        f"sibling index with a distinct name was not created: {other['index']!r}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
