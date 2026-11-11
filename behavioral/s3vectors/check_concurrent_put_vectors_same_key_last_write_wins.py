"""concurrent-put-vectors-same-key-last-write-wins."""
from __future__ import annotations

import concurrent.futures

from behavioral_harness import tags

CHECK = "concurrent-put-vectors-same-key-last-write-wins"
GROUP = "concurrency"
SERVICES = ["s3vectors"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two concurrent PutVectors calls writing the same key resolve to exactly one complete write, never a merge."""
    s3v = ctx.client("s3vectors")

    bucket_name = ctx.unique_name("sim2real-s3v-")
    index_name = ctx.unique_name("sim2real-idx-")
    s3v.create_vector_bucket(vectorBucketName=bucket_name)
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))
    s3v.create_index(
        vectorBucketName=bucket_name,
        indexName=index_name,
        dataType="float32",
        dimension=4,
        distanceMetric="euclidean",
    )
    ctx.on_cleanup(lambda: s3v.delete_index(vectorBucketName=bucket_name, indexName=index_name))

    key = "race-key"
    payload_a = {"data": [1.0, 2.0, 3.0, 4.0], "metadata": {"writer": "A"}}
    payload_b = {"data": [5.0, 6.0, 7.0, 8.0], "metadata": {"writer": "B"}}

    def write(payload):
        s3v.put_vectors(
            vectorBucketName=bucket_name,
            indexName=index_name,
            vectors=[
                {
                    "key": key,
                    "data": {"float32": payload["data"]},
                    "metadata": payload["metadata"],
                }
            ],
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(write, payload_a), pool.submit(write, payload_b)]
        for f in futures:
            f.result()

    fetched = s3v.get_vectors(
        vectorBucketName=bucket_name,
        indexName=index_name,
        keys=[key],
        returnData=True,
        returnMetadata=True,
    )["vectors"]
    assert len(fetched) == 1, f"expected exactly one surviving vector for key {key!r}, got {fetched!r}"

    got = fetched[0]
    got_data = list(got["data"]["float32"])
    got_meta = got["metadata"]

    matches_a = got_data == payload_a["data"] and got_meta == payload_a["metadata"]
    matches_b = got_data == payload_b["data"] and got_meta == payload_b["metadata"]
    assert matches_a or matches_b, f"corrupted merge: data={got_data} metadata={got_meta}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
