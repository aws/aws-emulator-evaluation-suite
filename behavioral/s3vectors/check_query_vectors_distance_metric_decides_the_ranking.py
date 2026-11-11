"""query-vectors-distance-metric-decides-the-ranking."""

# Over 3 well-separated vectors QueryVectors returns the exact ranking for each index's
# distanceMetric. Only ORDER is asserted, never a distance VALUE: the returned distance is
# quantised and not reproducible by exact arithmetic on the inputs.

from __future__ import annotations

import math
import struct
import time
from typing import Any

from behavioral_harness import tags

CHECK = "query-vectors-distance-metric-decides-the-ranking"
GROUP = "ordering"
SERVICES = ["s3vectors"]

_DIMENSION = 3

# The query vector, and three candidates hand-built so that COSINE and EUCLIDEAN produce
# DIFFERENT rankings of the SAME set — they disagree in every position, including first:
#
#   candidate            cosine distance   euclidean distance
#   far-same-direction   0.000000          9.000000
#   near-off-axis        0.042174          0.300000
#   orthogonal           1.000000          1.414214
#
#   cosine order    : far-same-direction, near-off-axis, orthogonal
#   euclidean order : near-off-axis,      orthogonal,    far-same-direction
#
# Neither expected order is written down here: both are RECOMPUTED below from these vectors
# in pure Python, so the expected values are not hard-coded and an emulator
# that stores vectors and returns them in insertion order — or that implements one metric for
# both enum values — cannot pass both legs.
_QUERY = [1.0, 0.0, 0.0]
_CANDIDATES = {
    "far-same-direction": [10.0, 0.0, 0.0],
    "near-off-axis": [1.0, 0.3, 0.0],
    "orthogonal": [0.0, 0.0, 1.0],
}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The index's `distanceMetric` decides the ORDER QueryVectors returns: two indexes over one vector
    set, differing only in cosine vs euclidean, each return the ranking recomputed locally for THEIR
    metric, and those two rankings differ.
    """
    s3v = ctx.client("s3vectors")
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account, "STS returned no account id; the check cannot attribute its resources"

    bucket = ctx.unique_name("sim2real-s3v-metric-")
    s3v.create_vector_bucket(
        vectorBucketName=bucket,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    # Registered FIRST so LIFO teardown deletes it LAST — DeleteVectorBucket is refused while
    # the bucket still holds indexes.
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket))

    query_f32 = [_as_float32(v) for v in _QUERY]
    candidates_f32 = {k: [_as_float32(v) for v in vec] for k, vec in _CANDIDATES.items()}

    expected = {
        "cosine": _ranked_keys(query_f32, candidates_f32, _cosine_distance),
        "euclidean": _ranked_keys(query_f32, candidates_f32, _euclidean_distance),
    }

    observed: dict[str, list[str]] = {}
    for metric in ("cosine", "euclidean"):
        index = ctx.unique_name(f"sim2real-s3v-{metric[:3]}-")
        s3v.create_index(
            vectorBucketName=bucket,
            indexName=index,
            dataType="float32",
            dimension=_DIMENSION,
            distanceMetric=metric,
        )
        ctx.on_cleanup(
            lambda b=bucket, n=index: s3v.delete_index(vectorBucketName=b, indexName=n)
        )

        s3v.put_vectors(
            vectorBucketName=bucket,
            indexName=index,
            vectors=[
                {"key": key, "data": {"float32": list(vec)}}
                for key, vec in candidates_f32.items()
            ],
        )
        ctx.on_cleanup(
            lambda b=bucket, n=index: s3v.delete_vectors(
                vectorBucketName=b, indexName=n, keys=sorted(candidates_f32)
            )
        )

        # GetIndex, not the CreateIndex response: the metric the ranking is judged against must
        # be the one the SERVICE says the index carries.
        stored_metric = s3v.get_index(vectorBucketName=bucket, indexName=index)["index"][
            "distanceMetric"
        ]
        assert stored_metric == metric, (
            f"GetIndex reports distanceMetric {stored_metric!r} for index {index}, "
            f"expected the {metric!r} pinned at CreateIndex"
        )

        # Bounded retry, reason: a just-written vector is not instantly queryable. The poll
        # waits only for the COUNT to settle -- the ORDER is asserted afterwards, outside the
        # poll, so a wrong order fails loudly instead of silently exhausting the deadline.
        resp = _poll_until(
            lambda b=bucket, n=index: s3v.query_vectors(
                vectorBucketName=b,
                indexName=n,
                topK=len(candidates_f32),
                queryVector={"float32": list(query_f32)},
                returnDistance=True,
            ),
            lambda r: len(r["vectors"]) == len(candidates_f32),
            timeout_s=60.0,
            interval_s=2.0,
            description=f"all {len(candidates_f32)} vectors became queryable in the {metric} index",
        )

        assert resp["distanceMetric"] == metric, (
            f"QueryVectors echoed distanceMetric {resp['distanceMetric']!r}, "
            f"expected {metric!r} (the index's declared metric)"
        )

        keys = [v["key"] for v in resp["vectors"]]
        assert keys == expected[metric], (
            f"{metric} index returned ranking {keys}, expected the pure-Python "
            f"{metric}-recomputed ranking {expected[metric]}"
        )

        distances = [v["distance"] for v in resp["vectors"]]
        assert all(
            distances[i] <= distances[i + 1] for i in range(len(distances) - 1)
        ), (
            f"{metric} index returned distances {distances} out of non-decreasing order; "
            "QueryVectors must return nearest neighbours in distance order"
        )

        observed[metric] = keys

    # The load-bearing cross-check, and an observation about the TARGET rather than about two
    # local constants: the same three vectors, queried with the same query vector, must rank
    # DIFFERENTLY under the two metrics. A target that implements one distance function and
    # merely echoes the enum returns the same order twice and fails here even if it somehow
    # matched one of the two legs above.
    assert observed["cosine"] != observed["euclidean"], (
        f"both indexes returned the same ranking {observed['cosine']}; cosine and euclidean "
        f"must disagree on this set (expected cosine {expected['cosine']} vs euclidean "
        f"{expected['euclidean']}) -- the declared distanceMetric is not driving the search"
    )


# ===== helpers (self-contained) =====
def _as_float32(value: float) -> float:
    """The single float32 cast the index's dataType implies, applied client-side so the
    recomputed ranking is over exactly the values the service stores."""
    return struct.unpack("<f", struct.pack("<f", float(value)))[0]


def _cosine_distance(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))
    assert norm_a > 0.0 and norm_b > 0.0, (
        f"cosine distance is undefined for a zero vector (norms {norm_a}, {norm_b})"
    )
    return 1.0 - dot / (norm_a * norm_b)


def _euclidean_distance(a: list[float], b: list[float]) -> float:
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b, strict=True)))


def _ranked_keys(query, candidates, distance_fn) -> list[str]:
    """Keys ordered nearest-first under `distance_fn`, with a guard that the ordering is
    strict: a tie would make the expected ranking ambiguous and the assertion a coin flip."""
    scored = sorted((distance_fn(query, vec), key) for key, vec in candidates.items())
    for i in range(len(scored) - 1):
        assert scored[i][0] < scored[i + 1][0], (
            f"the hand-built candidate set is not strictly ordered under {distance_fn.__name__}: "
            f"{scored[i]} ties with {scored[i + 1]}"
        )
    return [key for _, key in scored]


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
