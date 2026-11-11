"""list-vectors-pagination-order-is-stable."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-vectors-pagination-order-is-stable"
GROUP = "ordering"
SERVICES = ["s3vectors"]

_DIM = 8
_COUNT = 25


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Paginating ListVectors across multiple NextToken calls returns each inserted
    vector exactly once, and the same order is reproduced across independent full
    pagination passes (stable, non-overlapping pagination)."""
    s3v = ctx.client("s3vectors")
    bucket_name = ctx.unique_name("sim2real-s3vec-")
    index_name = ctx.unique_name("sim2real-idx-")

    s3v.create_vector_bucket(
        vectorBucketName=bucket_name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))
    s3v.create_index(
        vectorBucketName=bucket_name,
        indexName=index_name,
        dataType="float32",
        dimension=_DIM,
        distanceMetric="cosine",
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: s3v.delete_index(vectorBucketName=bucket_name, indexName=index_name))

    expected_keys = {f"vec-{i:03d}" for i in range(_COUNT)}
    vectors = [
        {"key": key, "data": {"float32": [float(i + 1)] * _DIM}}
        for i, key in enumerate(sorted(expected_keys))
    ]
    # 25 vectors fits comfortably under the 500-item PutVectors batch limit.
    s3v.put_vectors(vectorBucketName=bucket_name, indexName=index_name, vectors=vectors)

    # Newly-written vectors can take a moment to become listable; poll (bounded)
    # for the full set to settle before comparing pagination order.
    pass_one: list[str] = []
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        pass_one = _collect_all_keys(s3v, bucket_name, index_name, page_size=5)
        if len(pass_one) >= _COUNT:
            break
        time.sleep(2.0)

    assert len(pass_one) == _COUNT, f"expected {_COUNT} vectors to become listable, got {len(pass_one)}"
    assert set(pass_one) == expected_keys, "pagination missed or fabricated vectors"
    assert len(set(pass_one)) == _COUNT, "pagination returned duplicate keys within one pass"

    pass_two = _collect_all_keys(s3v, bucket_name, index_name, page_size=5)
    assert len(pass_two) == _COUNT, f"second pass returned {len(pass_two)} vectors, expected {_COUNT}"
    assert pass_one == pass_two, "ListVectors pagination order is not stable across independent passes"


def _collect_all_keys(s3v, bucket_name: str, index_name: str, page_size: int) -> list[str]:
    keys: list[str] = []
    token = None
    while True:
        kwargs = {
            "vectorBucketName": bucket_name,
            "indexName": index_name,
            "maxResults": page_size,
        }
        if token:
            kwargs["nextToken"] = token
        resp = s3v.list_vectors(**kwargs)
        keys.extend(v["key"] for v in resp["vectors"])
        token = resp.get("nextToken")
        if not token:
            break
    return keys


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
