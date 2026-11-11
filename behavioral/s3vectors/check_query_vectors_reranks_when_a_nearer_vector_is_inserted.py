"""query-vectors-reranks-when-a-nearer-vector-is-inserted."""

# After DeleteVectors, a query whose topK exceeds the surviving population returns the earlier
# ranking at once, while a query with topK <= population returns topK - 1 results: the deleted
# vector keeps one approximate-nearest-neighbour candidate slot until the index purges it.

from __future__ import annotations

import struct
import time
from typing import Any

from behavioral_harness import tags

CHECK = "query-vectors-reranks-when-a-nearer-vector-is-inserted"
GROUP = "ordering"
SERVICES = ["s3vectors"]

_DIMENSION = 3
# Query at the origin; four incumbents at x = 2..5, then an interloper at x = 1 that is strictly
# nearer than every incumbent. Distances are 2,3,4,5 and then 1 -- gaps of 1.0.
_QUERY = [0.0, 0.0, 0.0]
_INCUMBENT_X = (2.0, 3.0, 4.0, 5.0)
_INTERLOPER_X = 1.0
_INTERLOPER_KEY = "vec-interloper"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """QueryVectors ranks from live index state: a strictly nearer vector inserted later becomes top-1
    and shifts the earlier ranking down intact; after it is deleted an oversized query returns the
    original ranking, and every topK up to the population returns the ranking's prefix one short."""
    s3v = ctx.client("s3vectors")
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account, "STS returned no account id; the check cannot attribute its resources"

    bucket = ctx.unique_name("sim2real-s3v-rerank-")
    s3v.create_vector_bucket(
        vectorBucketName=bucket,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket))

    index = ctx.unique_name("sim2real-s3v-rerank-idx-")
    s3v.create_index(
        vectorBucketName=bucket,
        indexName=index,
        dataType="float32",
        dimension=_DIMENSION,
        distanceMetric="euclidean",
    )
    ctx.on_cleanup(lambda: s3v.delete_index(vectorBucketName=bucket, indexName=index))

    query = [_as_float32(v) for v in _QUERY]
    incumbents = {
        f"vec-x{int(x)}": [_as_float32(x), 0.0, 0.0] for x in _INCUMBENT_X
    }
    assert len(incumbents) == len(_INCUMBENT_X), "incumbent keys collided"
    assert _INTERLOPER_KEY not in incumbents, "the interloper must be a distinct key"
    assert all(x > _INTERLOPER_X for x in _INCUMBENT_X), (
        f"the interloper at x={_INTERLOPER_X} must be strictly nearer the origin than every "
        f"incumbent {_INCUMBENT_X}, or 'it becomes the new top-1' is not a property of the data"
    )

    s3v.put_vectors(
        vectorBucketName=bucket,
        indexName=index,
        vectors=[
            {"key": key, "data": {"float32": list(vec)}} for key, vec in incumbents.items()
        ],
    )
    ctx.on_cleanup(
        lambda: s3v.delete_vectors(
            vectorBucketName=bucket, indexName=index, keys=sorted(incumbents)
        )
    )

    def _rank(top_k: int) -> dict[str, Any]:
        return s3v.query_vectors(
            vectorBucketName=bucket,
            indexName=index,
            topK=top_k,
            queryVector={"float32": list(query)},
            returnDistance=True,
        )

    # --- Baseline. Bounded retry, reason: newly written vectors are not instantly queryable; the
    # poll waits for the COUNT only, so the ORDER is asserted outside it and fails loudly.
    baseline = _poll_until(
        lambda: _rank(len(incumbents)),
        lambda r: len(r["vectors"]) == len(incumbents),
        timeout_s=60.0,
        interval_s=2.0,
        description=f"all {len(incumbents)} incumbents became queryable",
    )
    baseline_order = [v["key"] for v in baseline["vectors"]]
    assert set(baseline_order) == set(incumbents), (
        f"baseline query returned {sorted(baseline_order)}, expected {sorted(incumbents)}"
    )
    _assert_non_decreasing(baseline["vectors"], "baseline")

    # The baseline order comes from the target and is cross-checked against the recomputed
    # euclidean ranking, so a target that is wrong from the first query is still caught.
    recomputed = [
        key
        for _d, key in sorted(
            (_euclidean_distance(query, vec), key) for key, vec in incumbents.items()
        )
    ]
    assert baseline_order == recomputed, (
        f"baseline ranking {baseline_order} does not match the pure-Python euclidean recomputation "
        f"{recomputed}"
    )

    # --- Prefix consistency: a smaller topK must be the strict PREFIX of the larger answer, not a
    # differently-computed subset. Both k values derive from the population.
    for top_k in (1, len(incumbents) // 2):
        resp = _rank(top_k)
        keys = [v["key"] for v in resp["vectors"]]
        assert len(keys) == top_k, (
            f"topK={top_k} returned {len(keys)} results ({keys}), expected exactly {top_k}"
        )
        assert keys == baseline_order[:top_k], (
            f"topK={top_k} returned {keys}, expected the first {top_k} of the topK="
            f"{len(incumbents)} answer {baseline_order}"
        )

    # --- The mutation: insert a strictly nearer vector.
    s3v.put_vectors(
        vectorBucketName=bucket,
        indexName=index,
        vectors=[
            {
                "key": _INTERLOPER_KEY,
                "data": {"float32": [_as_float32(_INTERLOPER_X), 0.0, 0.0]},
            }
        ],
    )
    ctx.on_cleanup(
        lambda: s3v.delete_vectors(
            vectorBucketName=bucket, indexName=index, keys=[_INTERLOPER_KEY]
        )
    )

    grown_keys = {_INTERLOPER_KEY, *incumbents}
    grown = _poll_until(
        lambda: _rank(len(incumbents) + 1),
        lambda r: {v["key"] for v in r["vectors"]} == grown_keys,
        timeout_s=60.0,
        interval_s=2.0,
        description=f"the interloper {_INTERLOPER_KEY} became queryable alongside every incumbent",
    )
    grown_order = [v["key"] for v in grown["vectors"]]
    _assert_non_decreasing(grown["vectors"], "after insert")

    # The expected ranking is the target's own earlier answer with the new vector prepended.
    assert grown_order == [_INTERLOPER_KEY, *baseline_order], (
        f"after inserting a strictly nearer vector the ranking is {grown_order}, expected "
        f"{[_INTERLOPER_KEY, *baseline_order]} -- the new vector must become top-1 and the "
        "previous ranking must survive intact beneath it"
    )

    # A query with a different topK can answer with stale state for a moment after another topK
    # has converged, so each read after a mutation polls for its exact expected answer.
    top_one_now = _poll_until(
        lambda: [v["key"] for v in _rank(1)["vectors"]],
        lambda ks: ks == [_INTERLOPER_KEY],
        timeout_s=60.0,
        interval_s=2.0,
        description="topK=1 settled on the interloper after it was inserted",
    )
    assert top_one_now == [_INTERLOPER_KEY], (
        f"topK=1 still answers {top_one_now} after a strictly nearer vector was inserted; "
        f"expected [{_INTERLOPER_KEY!r}]"
    )
    truncated = _poll_until(
        lambda: [v["key"] for v in _rank(len(incumbents))["vectors"]],
        lambda ks: ks == grown_order[: len(incumbents)],
        timeout_s=60.0,
        interval_s=2.0,
        description=f"topK={len(incumbents)} settled on the first {len(incumbents)} of the grown ranking",
    )
    assert truncated == grown_order[: len(incumbents)], (
        f"topK={len(incumbents)} returned {truncated}, expected the first {len(incumbents)} of "
        f"the grown ranking {grown_order}"
    )

    # --- The restore: delete the interloper and demand the EARLIER ranking back, element for
    # element. A target that caches a result set, or that stores insertion order, cannot produce
    # both this and the leg above.
    s3v.delete_vectors(vectorBucketName=bucket, indexName=index, keys=[_INTERLOPER_KEY])
    # The predicate demands the full expected set, not mere absence of the interloper: an empty
    # result also satisfies absence and can appear for a moment right after the delete.
    restored = _poll_until(
        lambda: _rank(len(incumbents) + 1),
        lambda r: {v["key"] for v in r["vectors"]} == set(baseline_order),
        timeout_s=60.0,
        interval_s=2.0,
        description=(
            f"the deleted interloper {_INTERLOPER_KEY} left the query results and all "
            f"{len(incumbents)} incumbents remained present"
        ),
    )
    restored_order = [v["key"] for v in restored["vectors"]]
    _assert_non_decreasing(restored["vectors"], "after delete")
    assert restored_order == baseline_order, (
        f"after deleting the interloper the ranking is {restored_order}, expected the original "
        f"{baseline_order} exactly"
    )
    # For topK <= population the deleted vector still takes one candidate slot, so every topK in
    # range returns exactly topK - 1 results, a correctly ordered prefix of the restored ranking.
    for top_k in range(1, len(incumbents) + 1):
        resp = _rank(top_k)
        keys = [v["key"] for v in resp["vectors"]]
        expected = baseline_order[: top_k - 1]
        assert keys == expected, (
            f"topK={top_k} returned {keys} shortly after deleting the interloper; expected "
            f"exactly {expected} ({top_k - 1} elements) -- real AWS keeps the deleted vector "
            f"occupying one candidate slot until the ANN graph purges it, so a topK<=population "
            f"query is short by exactly one until that happens"
        )


def _as_float32(value: float) -> float:
    return struct.unpack("<f", struct.pack("<f", float(value)))[0]


def _euclidean_distance(a: list[float], b: list[float]) -> float:
    return sum((x - y) ** 2 for x, y in zip(a, b, strict=True)) ** 0.5


def _assert_non_decreasing(vectors: list[dict], phase: str) -> None:
    distances = [v["distance"] for v in vectors]
    offenders = [i for i in range(len(distances) - 1) if distances[i] > distances[i + 1]]
    assert not offenders, (
        f"{phase}: QueryVectors returned distances {distances} for keys "
        f"{[v['key'] for v in vectors]}; order breaks at position {offenders[0]}"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str) -> Any:
    """Bounded retry that RAISES on deadline miss -- never returns its last value."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not reached within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
