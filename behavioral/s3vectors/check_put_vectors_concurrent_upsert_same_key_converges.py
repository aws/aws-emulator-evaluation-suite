"""put-vectors-concurrent-upsert-same-key-converges."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "put-vectors-concurrent-upsert-same-key-converges"
GROUP = "concurrency"
SERVICES = ["s3vectors"]


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
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
    """Racing PutVectors writers on one key converge to exactly one surviving vector whose data and
    metadata both come from the same writer: an upsert under contention never mixes two writes."""
    s3v = ctx.client("s3vectors")

    bucket_name = ctx.unique_name("sim2real-s3v-b-")
    index_name = ctx.unique_name("sim2real-s3v-i-")
    dimension = 4
    race_key = "race-key"
    num_writers = 8

    s3v.create_vector_bucket(
        vectorBucketName=bucket_name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3v-b"},
    )
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))

    s3v.create_index(
        vectorBucketName=bucket_name,
        indexName=index_name,
        dataType="float32",
        dimension=dimension,
        distanceMetric="euclidean",
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3v-i"},
    )
    ctx.on_cleanup(lambda: s3v.delete_index(vectorBucketName=bucket_name, indexName=index_name))

    def _write(writer_id: int) -> None:
        value = float(writer_id + 1)
        s3v.put_vectors(
            vectorBucketName=bucket_name,
            indexName=index_name,
            vectors=[
                {
                    "key": race_key,
                    "data": {"float32": [value] * dimension},
                    "metadata": {"writer": writer_id},
                }
            ],
        )

    with ThreadPoolExecutor(max_workers=num_writers) as pool:
        list(pool.map(_write, range(num_writers)))

    def _probe():
        return s3v.get_vectors(
            vectorBucketName=bucket_name,
            indexName=index_name,
            keys=[race_key],
            returnData=True,
            returnMetadata=True,
        )

    def _has_settled(resp) -> bool:
        # Poll only for the post-race shape (exactly one surviving vector); whether the survivor is
        # one whole write is asserted below, so a merged record fails at once instead of timing out.
        return len(resp.get("vectors", [])) == 1

    got = _poll_until(_probe, _has_settled, timeout_s=30.0, interval_s=1.0)

    vectors = got["vectors"]
    assert len(vectors) == 1, f"the race must converge to exactly one surviving vector, got {vectors!r}"

    winner = vectors[0]
    winner_id = winner["metadata"]["writer"]
    assert 0 <= winner_id < num_writers, f"winner metadata.writer {winner_id!r} is not one of this race's writer ids 0..{num_writers - 1}"
    expected_value = float(winner_id + 1)
    assert winner["data"]["float32"] == [expected_value] * dimension, (
        f"surviving vector's data {winner['data']['float32']!r} must belong to the SAME write as its "
        f"metadata (writer {winner_id}, expected {[expected_value] * dimension!r}) -- "
        "no cross-write corruption under concurrent upserts"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
