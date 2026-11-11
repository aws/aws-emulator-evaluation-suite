"""e2e-vector-lifecycle-flow."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "e2e-vector-lifecycle-flow"
GROUP = "e2e"
SERVICES = ["s3vectors"]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never met within {timeout_s}s, last observed: {last!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """End-to-end flow: create bucket -> create index -> put vectors -> query
    returns them -> delete vectors -> query returns empty -> teardown, with
    each transition asserted by its observable consequence."""
    s3v = ctx.client("s3vectors")

    bucket_name = ctx.unique_name("sim2real-s3v-b-")
    index_name = ctx.unique_name("sim2real-s3v-i-")
    dimension = 4
    resource_tags = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3v"}

    # create bucket -> bucket is discoverable
    s3v.create_vector_bucket(vectorBucketName=bucket_name, tags=resource_tags)
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))
    bucket = s3v.get_vector_bucket(vectorBucketName=bucket_name)["vectorBucket"]
    assert bucket["vectorBucketName"] == bucket_name, (
        f"expected GetVectorBucket to echo {bucket_name!r}, got {bucket['vectorBucketName']!r}"
    )

    # create index -> index is discoverable and empty
    s3v.create_index(
        vectorBucketName=bucket_name,
        indexName=index_name,
        dataType="float32",
        dimension=dimension,
        distanceMetric="euclidean",
        tags=resource_tags,
    )
    ctx.on_cleanup(lambda: s3v.delete_index(vectorBucketName=bucket_name, indexName=index_name))
    listed_empty = s3v.list_vectors(vectorBucketName=bucket_name, indexName=index_name)
    assert listed_empty["vectors"] == [], (
        f"expected a freshly created index to list zero vectors, got {listed_empty['vectors']!r}"
    )

    # put vectors -> query returns them
    keys = ["lifecycle-a", "lifecycle-b", "lifecycle-c"]
    vectors_in = [
        {"key": keys[0], "data": {"float32": [1.0, 0.0, 0.0, 0.0]}},
        {"key": keys[1], "data": {"float32": [0.0, 1.0, 0.0, 0.0]}},
        {"key": keys[2], "data": {"float32": [0.0, 0.0, 1.0, 0.0]}},
    ]
    s3v.put_vectors(vectorBucketName=bucket_name, indexName=index_name, vectors=vectors_in)

    def _query():
        return s3v.query_vectors(
            vectorBucketName=bucket_name,
            indexName=index_name,
            topK=10,
            queryVector={"float32": [1.0, 0.0, 0.0, 0.0]},
        )

    result = _poll_until(
        _query,
        lambda r: {v["key"] for v in r["vectors"]} == set(keys),
        timeout_s=60.0,
        interval_s=2.0,
    )
    found_keys = {v["key"] for v in result["vectors"]}
    assert found_keys == set(keys), f"expected QueryVectors to surface {set(keys)!r}, got {found_keys!r}"

    # delete vectors -> query returns empty, and an independent exact-key read agrees
    s3v.delete_vectors(vectorBucketName=bucket_name, indexName=index_name, keys=keys)

    empty_result = _poll_until(
        _query,
        lambda r: r["vectors"] == [],
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert empty_result["vectors"] == [], (
        f"expected QueryVectors to surface nothing after DeleteVectors, got {empty_result['vectors']!r}"
    )

    surviving = s3v.get_vectors(vectorBucketName=bucket_name, indexName=index_name, keys=keys)["vectors"]
    assert surviving == [], (
        f"expected GetVectors on the deleted keys to return nothing, got {surviving!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
