"""vector-embedding-float-precision-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "vector-embedding-float-precision-preserved"
GROUP = "representation"
SERVICES = ["s3vectors"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Float32 values that are exact binary fractions come back from GetVectors exactly as written, so
    the service adds no re-quantization, truncation or lower-precision cast."""
    s3v = ctx.client("s3vectors")

    bucket_name = ctx.unique_name("sim2real-s3v-b-")
    index_name = ctx.unique_name("sim2real-s3v-i-")
    dimension = 16

    s3v.create_vector_bucket(
        vectorBucketName=bucket_name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))

    s3v.create_index(
        vectorBucketName=bucket_name,
        indexName=index_name,
        dataType="float32",
        dimension=dimension,
        distanceMetric="euclidean",
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: s3v.delete_index(vectorBucketName=bucket_name, indexName=index_name))

    exact_values = [
        0.5, -0.25, 1.75, -3.125, 0.0, 2.5, -0.0625, 7.0,
        -1.0, 0.375, 4.5, -2.75, 0.03125, 15.0, -0.5, 1.0,
    ]
    assert len(exact_values) == dimension, (
        f"fixture bug: {len(exact_values)} values declared for dimension {dimension}"
    )

    s3v.put_vectors(
        vectorBucketName=bucket_name,
        indexName=index_name,
        vectors=[{"key": "precise-vec", "data": {"float32": exact_values}, "metadata": {}}],
    )

    got = s3v.get_vectors(
        vectorBucketName=bucket_name,
        indexName=index_name,
        keys=["precise-vec"],
        returnData=True,
    )
    vectors = got["vectors"]
    assert len(vectors) == 1, f"expected 1 vector for key 'precise-vec', got {len(vectors)}"
    returned = vectors[0]["data"]["float32"]
    assert len(returned) == dimension, f"expected {dimension} components, got {len(returned)}: {returned!r}"
    for expected, actual in zip(exact_values, returned):
        assert actual == expected, f"expected {expected!r}, got {actual!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
