"""delete-vector-bucket-with-index-conflict-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-vector-bucket-with-index-conflict-rejected"
GROUP = "e2e"
SERVICES = ["s3vectors"]

MSG_BUCKET_NOT_EMPTY = "The specified vector bucket is not empty"
MSG_BUCKET_NOT_FOUND = "The specified vector bucket could not be found"


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteVectorBucket is rejected while the bucket still contains a
    vector index, the bucket remains fully intact, and deleting the index
    first then the bucket succeeds (state-conflict boundary in the lifecycle)."""
    s3v = ctx.client("s3vectors")

    bucket_name = ctx.unique_name("sim2real-s3v-b-")
    index_name = ctx.unique_name("sim2real-s3v-i-")

    s3v.create_vector_bucket(vectorBucketName=bucket_name)
    bucket_deleted = {"done": False}
    ctx.on_cleanup(
        lambda: None if bucket_deleted["done"] else s3v.delete_vector_bucket(vectorBucketName=bucket_name)
    )

    s3v.create_index(
        vectorBucketName=bucket_name,
        indexName=index_name,
        dataType="float32",
        dimension=4,
        distanceMetric="euclidean",
    )
    index_deleted = {"done": False}
    ctx.on_cleanup(
        lambda: None
        if index_deleted["done"]
        else s3v.delete_index(vectorBucketName=bucket_name, indexName=index_name)
    )

    # (a) breaking exactly one precondition: bucket still has a live index
    code, code_msg = _error(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))
    assert code == "ConflictException", f"expected ConflictException while an index is live, got {code!r}"
    assert code_msg == MSG_BUCKET_NOT_EMPTY, f"unexpected {code!r} message {code_msg!r}"

    # (b) effect absent: the bucket is still fully present and usable
    bucket = s3v.get_vector_bucket(vectorBucketName=bucket_name)["vectorBucket"]
    assert bucket["vectorBucketName"] == bucket_name, (
        f"rejected delete must leave the bucket intact, expected {bucket_name!r} got {bucket['vectorBucketName']!r}"
    )
    index = s3v.get_index(vectorBucketName=bucket_name, indexName=index_name)["index"]
    assert index["indexName"] == index_name, (
        f"rejected delete must leave the index intact, expected {index_name!r} got {index['indexName']!r}"
    )

    # (c) positive control: delete the index, then the bucket delete succeeds
    s3v.delete_index(vectorBucketName=bucket_name, indexName=index_name)
    index_deleted["done"] = True

    s3v.delete_vector_bucket(vectorBucketName=bucket_name)
    bucket_deleted["done"] = True

    not_found_code, not_found_code_msg = _error(lambda: s3v.get_vector_bucket(vectorBucketName=bucket_name))
    assert not_found_code == "NotFoundException", (
        f"expected NotFoundException once the bucket is actually deleted, got {not_found_code!r}"
    )
    assert not_found_code_msg == MSG_BUCKET_NOT_FOUND, f"unexpected {not_found_code!r} message {not_found_code_msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
