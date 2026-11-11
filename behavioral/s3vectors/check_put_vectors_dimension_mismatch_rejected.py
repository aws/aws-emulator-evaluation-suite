"""put-vectors-dimension-mismatch-rejected."""
from __future__ import annotations

import struct

from behavioral_harness import tags

CHECK = "put-vectors-dimension-mismatch-rejected"
GROUP = "error-semantics"
SERVICES = ["s3vectors"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutVectors with a vector shorter than the index dimension fails with ValidationException and the
    exact length message, and the vector is never stored, while a well-formed vector is stored and
    read back with its exact float32 values."""
    s3v = ctx.client("s3vectors")
    bucket_name = ctx.unique_name("sim2real-s3vec-b-")
    s3v.create_vector_bucket(
        vectorBucketName=bucket_name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3vec"},
    )
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))

    index_name = ctx.unique_name("sim2real-idx-")
    s3v.create_index(
        vectorBucketName=bucket_name,
        indexName=index_name,
        dataType="float32",
        dimension=8,
        distanceMetric="cosine",
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3vec"},
    )
    ctx.on_cleanup(lambda: s3v.delete_index(vectorBucketName=bucket_name, indexName=index_name))

    good_key = "vec-good"
    bad_key = "vec-bad-dim"
    good_values = [0.1] * 8
    # dataType=float32: values are stored (and returned) at float32 precision,
    # so compare against the float32-rounded expectation, not the python double.
    expected_good = [_as_float32(v) for v in good_values]

    # Positive control first: a correctly-dimensioned vector is accepted.
    s3v.put_vectors(
        vectorBucketName=bucket_name,
        indexName=index_name,
        vectors=[{"key": good_key, "data": {"float32": good_values}}],
    )
    ctx.on_cleanup(
        lambda: s3v.delete_vectors(vectorBucketName=bucket_name, indexName=index_name, keys=[good_key])
    )

    # Break exactly one thing: submit a vector with 4 components against an
    # 8-dimensional index.
    err = _error(
        lambda: s3v.put_vectors(
            vectorBucketName=bucket_name,
            indexName=index_name,
            vectors=[{"key": bad_key, "data": {"float32": [0.2, 0.3, 0.4, 0.5]}}],
        )
    )
    assert err["Code"] == "ValidationException", f"expected ValidationException, got {err!r}"
    assert err.get("Message") == f"Invalid record for key '{bad_key}': vector must have length 8, but has length 4", (
        f"expected the exact dimension-mismatch message, got {err.get('Message')!r}"
    )

    # Effect absent: the mismatched vector was never written. GetVectors treats
    # an absent key like a batch-get miss -- it succeeds and simply omits the
    # key from the result, it does not raise NotFoundException per-key.
    absent_resp = s3v.get_vectors(
        vectorBucketName=bucket_name,
        indexName=index_name,
        keys=[bad_key],
        returnData=True,
    )
    assert absent_resp.get("vectors", []) == [], "mismatched-dimension vector was written despite rejection"


    # Positive control: the well-formed vector is retrievable with its data intact.
    good_resp = s3v.get_vectors(
        vectorBucketName=bucket_name,
        indexName=index_name,
        keys=[good_key],
        returnData=True,
    )
    assert len(good_resp["vectors"]) == 1
    assert good_resp["vectors"][0]["key"] == good_key
    assert [_as_float32(v) for v in good_resp["vectors"][0]["data"]["float32"]] == expected_good


def _as_float32(value: float) -> float:
    return struct.unpack("<f", struct.pack("<f", value))[0]


def _error(fn) -> dict:
    """Call fn() and return the botocore error (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
