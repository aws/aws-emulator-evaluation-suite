"""e2e-put-query-delete-removes-from-results."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "e2e-put-query-delete-removes-from-results"
GROUP = "e2e"
SERVICES = ["s3vectors"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Full lifecycle: create bucket/index, put vectors, confirm they're
    queryable, delete one, and observe that a subsequent QueryVectors no
    longer returns it -- before tearing everything down."""
    s3v = ctx.client("s3vectors")
    bucket_name = ctx.unique_name("sim2real-s3vec-e2e-")
    index_name = ctx.unique_name("sim2real-s3vec-e2ei-")

    s3v.create_vector_bucket(
        vectorBucketName=bucket_name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3vec-e2e"},
    )
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))

    s3v.create_index(
        vectorBucketName=bucket_name,
        indexName=index_name,
        dataType="float32",
        dimension=3,
        distanceMetric="euclidean",
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3vec-e2e"},
    )
    ctx.on_cleanup(
        lambda: s3v.delete_index(vectorBucketName=bucket_name, indexName=index_name)
    )

    s3v.put_vectors(
        vectorBucketName=bucket_name,
        indexName=index_name,
        vectors=[
            {"key": "alpha", "data": {"float32": [1.0, 0.0, 0.0]}},
            {"key": "beta", "data": {"float32": [0.0, 1.0, 0.0]}},
            {"key": "gamma", "data": {"float32": [0.0, 0.0, 1.0]}},
        ],
    )

    def _query_keys() -> set[str]:
        res = s3v.query_vectors(
            vectorBucketName=bucket_name,
            indexName=index_name,
            topK=10,
            queryVector={"float32": [1.0, 0.0, 0.0]},
        )
        return {v["key"] for v in res.get("vectors", [])}

    keys = _poll_until(
        lambda: _query_keys(),
        lambda ks: {"alpha", "beta", "gamma"} == ks,
        timeout_s=30.0,
        description="all 3 puts queryable, nothing extra",
    )
    assert keys == {"alpha", "beta", "gamma"}, f"expected exactly 3 keys queryable, got {keys}"

    s3v.delete_vectors(
        vectorBucketName=bucket_name, indexName=index_name, keys=["alpha"]
    )

    remaining = _poll_until(
        lambda: _query_keys(),
        lambda ks: ks == {"beta", "gamma"},
        timeout_s=30.0,
        description="'alpha' gone from QueryVectors, 'beta'/'gamma' unaffected",
    )
    assert "alpha" not in remaining, "deleted vector 'alpha' still appears in QueryVectors results"
    assert remaining == {"beta", "gamma"}, f"undeleted vectors missing from results: {remaining}"


def _poll_until(probe, predicate, *, timeout_s: float = 30.0, interval_s: float = 2.0, description: str = "condition") -> Any:
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s, last observed: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
