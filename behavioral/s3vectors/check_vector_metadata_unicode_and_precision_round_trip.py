"""vector-metadata-unicode-and-precision-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "vector-metadata-unicode-and-precision-round-trip"
GROUP = "representation"
SERVICES = ["s3vectors"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Vector metadata containing unicode strings and high-precision floats
    is preserved exactly (decimal/string equality) when read back via
    GetVectors."""
    s3v = ctx.client("s3vectors")
    bucket_name = ctx.unique_name("sim2real-s3vec-md-")
    index_name = ctx.unique_name("sim2real-s3vec-mdi-")

    s3v.create_vector_bucket(
        vectorBucketName=bucket_name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3vec-md"},
    )
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))
    s3v.create_index(
        vectorBucketName=bucket_name,
        indexName=index_name,
        dataType="float32",
        dimension=3,
        distanceMetric="euclidean",
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3vec-md"},
    )
    ctx.on_cleanup(
        lambda: s3v.delete_index(vectorBucketName=bucket_name, indexName=index_name)
    )

    metadata = {
        "label": "café-北京-Ünïcödé-résumé",
        "precise_score": 0.1234567890123456,
        "pi_estimate": 3.14159265358979,
        "is_active": True,
        "tags": ["日本語", "café", "北京"],
    }

    s3v.put_vectors(
        vectorBucketName=bucket_name,
        indexName=index_name,
        vectors=[
            {
                "key": "metadata-vector",
                "data": {"float32": [0.5, 0.25, 0.125]},
                "metadata": metadata,
            }
        ],
    )

    fetched = s3v.get_vectors(
        vectorBucketName=bucket_name,
        indexName=index_name,
        keys=["metadata-vector"],
        returnMetadata=True,
    )["vectors"]
    assert len(fetched) == 1, f"expected 1 vector, got {len(fetched)}: {fetched!r}"
    got_metadata = fetched[0]["metadata"]

    assert got_metadata["label"] == metadata["label"], (
        f"unicode label mismatch: {got_metadata['label']!r} != {metadata['label']!r}"
    )
    assert got_metadata["precise_score"] == metadata["precise_score"], (
        f"precision loss: {got_metadata['precise_score']!r} != {metadata['precise_score']!r}"
    )
    assert got_metadata["pi_estimate"] == metadata["pi_estimate"], (
        f"precision loss: {got_metadata['pi_estimate']!r} != {metadata['pi_estimate']!r}"
    )
    assert got_metadata["is_active"] == metadata["is_active"], (
        f"bool metadata mismatch: {got_metadata['is_active']!r} != {metadata['is_active']!r}"
    )
    assert got_metadata["tags"] == metadata["tags"], (
        f"list metadata mismatch: {got_metadata['tags']!r} != {metadata['tags']!r}"
    )



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
