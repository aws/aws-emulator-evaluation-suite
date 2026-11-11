"""list-vectors-nonexistent-index-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-vectors-nonexistent-index-not-found"
GROUP = "error-semantics"
SERVICES = ["s3vectors"]

MSG_INDEX_NOT_FOUND = "The specified index could not be found"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListVectors against a nonexistent index name returns NotFoundException, not an empty page."""
    s3v = ctx.client("s3vectors")

    bucket_name = ctx.unique_name("sim2real-s3v-")
    s3v.create_vector_bucket(vectorBucketName=bucket_name)
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))

    ghost_index = ctx.unique_name("sim2real-idx-ghost-")
    code, code_msg = _error(lambda: s3v.list_vectors(vectorBucketName=bucket_name, indexName=ghost_index))
    assert code == "NotFoundException", f"expected NotFoundException for a ghost index, got {code!r}"
    assert code_msg == MSG_INDEX_NOT_FOUND, f"unexpected {code!r} message {code_msg!r}"

    # positive control: a real index in the same bucket lists its vectors normally
    real_index = ctx.unique_name("sim2real-idx-")
    s3v.create_index(
        vectorBucketName=bucket_name,
        indexName=real_index,
        dataType="float32",
        dimension=4,
        distanceMetric="cosine",
    )
    ctx.on_cleanup(lambda: s3v.delete_index(vectorBucketName=bucket_name, indexName=real_index))
    s3v.put_vectors(
        vectorBucketName=bucket_name,
        indexName=real_index,
        vectors=[{"key": "v1", "data": {"float32": [0.1, 0.2, 0.3, 0.4]}}],
    )
    listed = s3v.list_vectors(vectorBucketName=bucket_name, indexName=real_index)["vectors"]
    assert any(v["key"] == "v1" for v in listed), f"expected key 'v1' in {listed!r}"


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
