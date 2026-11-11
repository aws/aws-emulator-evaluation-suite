"""delete-vector-bucket-with-indexes-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-vector-bucket-with-indexes-rejected"
GROUP = "error-semantics"
SERVICES = ["s3vectors"]

MSG_BUCKET_NOT_EMPTY = "The specified vector bucket is not empty"
MSG_BUCKET_NOT_FOUND = "The specified vector bucket could not be found"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteVectorBucket is rejected while the bucket still contains indexes."""
    s3v = ctx.client("s3vectors")

    bucket_name = ctx.unique_name("sim2real-s3v-")
    index_name = ctx.unique_name("sim2real-idx-")
    s3v.create_vector_bucket(
        vectorBucketName=bucket_name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3v"},
    )
    ctx.on_cleanup(lambda: _safe_delete(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name)))
    s3v.create_index(
        vectorBucketName=bucket_name,
        indexName=index_name,
        dataType="float32",
        dimension=4,
        distanceMetric="cosine",
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3v"},
    )
    ctx.on_cleanup(lambda: _safe_delete(lambda: s3v.delete_index(vectorBucketName=bucket_name, indexName=index_name)))

    code, code_msg = _error(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    assert code_msg == MSG_BUCKET_NOT_EMPTY, f"unexpected {code!r} message {code_msg!r}"

    # effect absent: the bucket and its index both still exist after the rejected delete
    still_there = s3v.get_vector_bucket(vectorBucketName=bucket_name)["vectorBucket"]
    assert still_there["vectorBucketName"] == bucket_name, (
        f"bucket {bucket_name!r} should still exist after the rejected delete, got {still_there!r}"
    )
    index_still_there = s3v.get_index(vectorBucketName=bucket_name, indexName=index_name)["index"]
    assert index_still_there["indexName"] == index_name, (
        f"index {index_name!r} should still exist after the rejected bucket delete, "
        f"got {index_still_there!r}"
    )

    # positive control: deleting the index first allows the bucket delete to succeed
    s3v.delete_index(vectorBucketName=bucket_name, indexName=index_name)
    s3v.delete_vector_bucket(vectorBucketName=bucket_name)
    code_after, code_after_msg = _error(lambda: s3v.get_vector_bucket(vectorBucketName=bucket_name))
    assert code_after == "NotFoundException", f"expected NotFoundException, got {code_after!r}"
    assert code_after_msg == MSG_BUCKET_NOT_FOUND, f"unexpected {code_after!r} message {code_after_msg!r}"


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe_delete(fn):
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
