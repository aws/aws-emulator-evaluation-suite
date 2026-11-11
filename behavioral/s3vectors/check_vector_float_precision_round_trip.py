"""vector-float-precision-round-trip."""
from __future__ import annotations

import math
import struct

from behavioral_harness import tags

CHECK = "vector-float-precision-round-trip"
GROUP = "server-side"
SERVICES = ["s3vectors"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """High-precision components written with PutVectors come back from GetVectors with the exact float32
    bit pattern of each input, so the service adds no rounding beyond the float32 cast of the index."""
    s3v = ctx.client("s3vectors")
    bucket_name = ctx.unique_name("sim2real-s3vec-b-")
    s3v.create_vector_bucket(
        vectorBucketName=bucket_name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))

    index_name = ctx.unique_name("sim2real-idx-")
    dimension = 6
    s3v.create_index(
        vectorBucketName=bucket_name,
        indexName=index_name,
        dataType="float32",
        dimension=dimension,
        distanceMetric="euclidean",
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: s3v.delete_index(vectorBucketName=bucket_name, indexName=index_name))

    key = "vec-precision"
    # High-precision python doubles that do NOT land exactly on float32
    # boundaries -- if the wire round-trip introduces any *extra* rounding
    # beyond the single cast to float32, the bit pattern below will drift.
    raw_values = [
        math.pi,
        -math.e,
        1.0000001192092896,  # one ULP above 1.0f in float32
        -0.00003051757812501,
        123456.789012345,
        1.0 / 3.0,
    ]
    assert len(raw_values) == dimension, (
        f"fixture bug: {len(raw_values)} raw values declared for dimension {dimension}"
    )
    expected = [_as_float32(v) for v in raw_values]

    s3v.put_vectors(
        vectorBucketName=bucket_name,
        indexName=index_name,
        vectors=[{"key": key, "data": {"float32": raw_values}}],
    )
    ctx.on_cleanup(
        lambda: s3v.delete_vectors(vectorBucketName=bucket_name, indexName=index_name, keys=[key])
    )

    resp = s3v.get_vectors(
        vectorBucketName=bucket_name,
        indexName=index_name,
        keys=[key],
        returnData=True,
    )
    assert len(resp["vectors"]) == 1, f"expected 1 vector for key {key!r}, got {len(resp['vectors'])}"
    got = list(resp["vectors"][0]["data"]["float32"])
    assert len(got) == dimension, f"expected {dimension} components, got {len(got)}: {got!r}"

    for i, (expected_value, got_value) in enumerate(zip(expected, got)):
        expected_bits = struct.pack("<f", expected_value)
        got_bits = struct.pack("<f", got_value)
        assert got_bits == expected_bits, (
            f"component {i}: bit-pattern mismatch, expected float32 {expected_value!r} "
            f"({expected_bits.hex()}), got {got_value!r} ({got_bits.hex()})"
        )


def _as_float32(value: float) -> float:
    return struct.unpack("<f", struct.pack("<f", value))[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
