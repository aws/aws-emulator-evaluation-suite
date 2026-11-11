"""vector-metadata-empty-vs-absent-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "vector-metadata-empty-vs-absent-preserved"
GROUP = "representation"
SERVICES = ["s3vectors"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A vector put with metadata {} and a vector put without metadata both come back from GetVectors
    with a metadata key equal to {}: the service normalizes absent metadata to an empty document."""
    s3v = ctx.client("s3vectors")

    bucket_name = ctx.unique_name("sim2real-s3v-b-")
    index_name = ctx.unique_name("sim2real-s3v-i-")

    s3v.create_vector_bucket(vectorBucketName=bucket_name)
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))

    s3v.create_index(
        vectorBucketName=bucket_name,
        indexName=index_name,
        dataType="float32",
        dimension=4,
        distanceMetric="cosine",
    )
    ctx.on_cleanup(lambda: s3v.delete_index(vectorBucketName=bucket_name, indexName=index_name))

    s3v.put_vectors(
        vectorBucketName=bucket_name,
        indexName=index_name,
        vectors=[
            {
                "key": "vec-empty-metadata",
                "data": {"float32": [0.5, 0.5, 0.5, 0.5]},
                "metadata": {},
            },
            {
                "key": "vec-absent-metadata",
                "data": {"float32": [0.25, 0.25, 0.25, 0.25]},
                # no "metadata" key at all
            },
        ],
    )

    got = s3v.get_vectors(
        vectorBucketName=bucket_name,
        indexName=index_name,
        keys=["vec-empty-metadata", "vec-absent-metadata"],
        returnMetadata=True,
    )
    by_key = {v["key"]: v for v in got["vectors"]}
    assert set(by_key) == {"vec-empty-metadata", "vec-absent-metadata"}, (
        f"expected both keys back, got {sorted(by_key)!r}"
    )

    empty_vec = by_key["vec-empty-metadata"]
    absent_vec = by_key["vec-absent-metadata"]

    # explicit empty map round-trips as an actual empty document
    assert empty_vec.get("metadata") == {}, f"empty_meta={empty_vec.get('metadata')!r}"
    # Metadata never supplied at write time is normalized to an empty document too: S3 Vectors
    # keeps no absent-vs-empty distinction, so the "metadata" key is present and equals {}.
    assert "metadata" in absent_vec, f"absent_vec missing metadata key entirely: {sorted(absent_vec.keys())!r}"
    assert absent_vec["metadata"] == {}, f"absent_meta={absent_vec['metadata']!r}"
    assert absent_vec["metadata"] == empty_vec["metadata"], (
        f"absent-at-write metadata {absent_vec['metadata']!r} != "
        f"explicit-empty metadata {empty_vec['metadata']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
