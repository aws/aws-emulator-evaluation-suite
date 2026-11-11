"""vector-metadata-unicode-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "vector-metadata-unicode-round-trip"
GROUP = "representation"
SERVICES = ["s3vectors"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Unicode strings written into vector metadata via PutVectors come back
    byte-identical (no mangling/normalization) via GetVectors."""
    s3v = ctx.client("s3vectors")

    bucket_name = ctx.unique_name("sim2real-s3v-b-")
    index_name = ctx.unique_name("sim2real-s3v-i-")

    s3v.create_vector_bucket(
        vectorBucketName=bucket_name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3v-b"},
    )
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))

    s3v.create_index(
        vectorBucketName=bucket_name,
        indexName=index_name,
        dataType="float32",
        dimension=4,
        distanceMetric="cosine",
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3v-i"},
    )
    ctx.on_cleanup(lambda: s3v.delete_index(vectorBucketName=bucket_name, indexName=index_name))

    unicode_metadata = {
        "title": "日本語テスト \U0001F389",
        "note": "Ünïcödé \u2014 em-dash, quotes \u201csmart\u201d",
        "mixed": "Z\u00fcrich \u5317\u4eac \U0001F600 caf\u00e9",
        "arabic": "\u0645\u0631\u062d\u0628\u0627",
    }

    s3v.put_vectors(
        vectorBucketName=bucket_name,
        indexName=index_name,
        vectors=[
            {
                "key": "unicode-vec",
                "data": {"float32": [0.5, -0.25, 0.75, -0.5]},
                "metadata": unicode_metadata,
            }
        ],
    )

    got = s3v.get_vectors(
        vectorBucketName=bucket_name,
        indexName=index_name,
        keys=["unicode-vec"],
        returnMetadata=True,
    )
    vectors = got["vectors"]
    assert len(vectors) == 1, f"expected exactly 1 vector, got {len(vectors)}: {vectors!r}"
    assert vectors[0]["key"] == "unicode-vec", f"expected key 'unicode-vec', got {vectors[0]['key']!r}"
    assert vectors[0]["metadata"] == unicode_metadata, (
        f"unicode metadata mangled on round-trip: expected {unicode_metadata!r}, got {vectors[0]['metadata']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
