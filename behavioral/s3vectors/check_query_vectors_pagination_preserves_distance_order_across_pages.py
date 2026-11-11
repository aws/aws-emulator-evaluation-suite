"""query-vectors-pagination-preserves-distance-order-across-pages."""

# QueryVectors paginates via nextToken above the documented 100-per-page cap, and distances are
# non-decreasing across the page boundary. A separate topK=100 query agrees on the distance at every
# rank and on the keys of each tied-distance group, but not on the order within a tie, so the
# comparison groups by distance value (QueryVectors is approximate nearest-neighbour search).
#
# Wall clock: one PutVectors of 130 vectors and three drained passes; the 120s convergence poll is
# the only long wait and it raises on miss.

from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "query-vectors-pagination-preserves-distance-order-across-pages"
GROUP = "ordering"
SERVICES = ["s3vectors"]

_DIMENSION = 4
# Above the documented per-page cap, so at least two pages are structurally required, and well
# under the 500-per-call PutVectors limit so the load is a single request.
_COUNT = 130
_RESULTS_PER_PAGE_CAP = 100
_QUERY = [0.5, 0.0, 0.0, 0.0]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A QueryVectors result larger than the documented per-page cap is delivered across
    nextToken pages that together form ONE non-decreasing distance ranking with no duplicate and
    no fabricated key."""
    s3v = ctx.client("s3vectors")
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account, "STS returned no account id; the check cannot attribute its resources"

    bucket = ctx.unique_name("sim2real-s3v-qpage-")
    s3v.create_vector_bucket(
        vectorBucketName=bucket,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket))

    index = ctx.unique_name("sim2real-s3v-qpage-idx-")
    s3v.create_index(
        vectorBucketName=bucket,
        indexName=index,
        dataType="float32",
        dimension=_DIMENSION,
        distanceMetric="euclidean",
    )
    ctx.on_cleanup(lambda: s3v.delete_index(vectorBucketName=bucket, indexName=index))

    assert _COUNT > _RESULTS_PER_PAGE_CAP, (
        f"the check is only meaningful when the population ({_COUNT}) exceeds the documented "
        f"per-page cap ({_RESULTS_PER_PAGE_CAP})"
    )

    keys = [f"qp-vec-{i:04d}" for i in range(_COUNT)]
    s3v.put_vectors(
        vectorBucketName=bucket,
        indexName=index,
        vectors=[
            {"key": key, "data": {"float32": [float(i + 1), 0.0, 0.0, 0.0]}}
            for i, key in enumerate(keys)
        ],
    )
    ctx.on_cleanup(
        lambda: s3v.delete_vectors(vectorBucketName=bucket, indexName=index, keys=list(keys))
    )

    # The target's OWN reported population, drained through a different operation than the one
    # under test. Bounded retry, reason: newly written vectors are not instantly listable.
    listed = _poll_until(
        lambda: _list_all_keys(s3v, bucket, index),
        lambda found: len(found) == _COUNT,
        timeout_s=120.0,
        interval_s=4.0,
        description=f"all {_COUNT} vectors became listable",
    )
    population = len(set(listed))
    assert population == _COUNT, (
        f"ListVectors reports {population} distinct vectors, expected {_COUNT} written"
    )

    # --- Single-page control, established BEFORE the paginated leg: a topK at the cap must come
    # back in ONE response, so a later multi-page result cannot be blamed on a target that
    # paginates everything, and the page-cap assertion has a same-run reference point.
    control = s3v.query_vectors(
        vectorBucketName=bucket,
        indexName=index,
        topK=_RESULTS_PER_PAGE_CAP,
        queryVector={"float32": list(_QUERY)},
        returnDistance=True,
    )
    control_keys = [v["key"] for v in control["vectors"]]
    assert len(control_keys) == _RESULTS_PER_PAGE_CAP, (
        f"topK={_RESULTS_PER_PAGE_CAP} returned {len(control_keys)} results in the first page, "
        f"expected exactly {_RESULTS_PER_PAGE_CAP} (the population is {population})"
    )
    control_distances = [v["distance"] for v in control["vectors"]]
    assert all(
        control_distances[i] <= control_distances[i + 1]
        for i in range(len(control_distances) - 1)
    ), "the single-page control query returned distances out of non-decreasing order"

    # --- The paginated leg: topK == the whole population.
    pages: list[list[dict]] = []
    token = None
    max_pages = _COUNT  # one vector per page is the pathological floor; more means no progress
    for _ in range(max_pages):
        kwargs: dict[str, Any] = {
            "vectorBucketName": bucket,
            "indexName": index,
            "topK": population,
            "queryVector": {"float32": list(_QUERY)},
            "returnDistance": True,
        }
        if token:
            kwargs["nextToken"] = token
        resp = s3v.query_vectors(**kwargs)
        pages.append(resp["vectors"])
        assert resp["distanceMetric"] == "euclidean", (
            f"page {len(pages)} echoed distanceMetric {resp['distanceMetric']!r}, expected "
            "'euclidean'"
        )
        token = resp.get("nextToken")
        if not token:
            break
    else:
        raise AssertionError(
            f"QueryVectors kept returning a nextToken after {max_pages} pages; pagination does "
            "not terminate"
        )

    for i, page in enumerate(pages):
        assert len(page) <= _RESULTS_PER_PAGE_CAP, (
            f"page {i} carries {len(page)} results, above the documented per-response cap of "
            f"{_RESULTS_PER_PAGE_CAP}"
        )

    assert len(pages) >= 2, (
        f"topK={population} with a documented per-page cap of {_RESULTS_PER_PAGE_CAP} must span "
        f"at least 2 pages; the target delivered it in {len(pages)} page(s) of sizes "
        f"{[len(p) for p in pages]}"
    )

    flat = [v for page in pages for v in page]
    flat_keys = [v["key"] for v in flat]
    assert len(set(flat_keys)) == len(flat_keys), (
        f"pagination returned {len(flat_keys) - len(set(flat_keys))} duplicate key(s) across "
        f"{len(pages)} pages of sizes {[len(p) for p in pages]}"
    )
    assert set(flat_keys) <= set(listed), (
        f"pagination fabricated keys never written: {sorted(set(flat_keys) - set(listed))[:5]}"
    )
    assert len(flat_keys) == population, (
        f"topK={population} delivered {len(flat_keys)} results across {len(pages)} pages, "
        f"expected the whole population ({population}) that ListVectors reports"
    )

    # The discriminating assertion: ONE ranking across the boundary, not per page.
    distances = [v["distance"] for v in flat]
    offenders = [
        (i, flat_keys[i], distances[i], flat_keys[i + 1], distances[i + 1])
        for i in range(len(distances) - 1)
        if distances[i] > distances[i + 1]
    ]
    assert not offenders, (
        f"distance order breaks {len(offenders)} time(s) across {len(pages)} pages of sizes "
        f"{[len(p) for p in pages]}; first break at position {offenders[0][0]}: "
        f"{offenders[0][1]}={offenders[0][2]} then {offenders[0][3]}={offenders[0][4]}"
    )

    # And the first page of the paginated leg must agree with the single-page control -- so a
    # target that returns a *different* set once a token is involved is caught. Confirmed on real
    # AWS: the two separate calls agree exactly on the distance value at every rank, and on which
    # keys occupy each tied-distance group, but QueryVectors ("approximate nearest neighbor
    # search") does not commit to a deterministic tie-break order for same-distance keys across
    # two separate calls -- so equality is checked per tied-distance group, not by raw position.
    page1_keys = flat_keys[:_RESULTS_PER_PAGE_CAP]
    page1_distances = distances[:_RESULTS_PER_PAGE_CAP]
    assert page1_distances == control_distances, (
        "the first page's distance values do not match the single-page control's distance "
        f"values rank-for-rank: page has {page1_distances[:10]}, control has "
        f"{control_distances[:10]}"
    )
    page1_tie_groups = _tie_groups(page1_keys, page1_distances)
    control_tie_groups = _tie_groups(control_keys, control_distances)
    assert page1_tie_groups == control_tie_groups, (
        "the first page of the paginated query and the single-page control disagree on which "
        "keys share a tied distance value: "
        f"page groups {[sorted(g) for g in page1_tie_groups][:5]}, control groups "
        f"{[sorted(g) for g in control_tie_groups][:5]}"
    )


# ===== helpers (self-contained) =====
def _tie_groups(keys: list[str], dists: list[float]) -> list[frozenset[str]]:
    """Partition a distance-sorted (keys, dists) pair into consecutive equal-distance groups."""
    groups: list[frozenset[str]] = []
    start = 0
    for i in range(1, len(dists) + 1):
        if i == len(dists) or dists[i] != dists[start]:
            groups.append(frozenset(keys[start:i]))
            start = i
    return groups


def _list_all_keys(s3v, bucket: str, index: str) -> list[str]:
    out: list[str] = []
    token = None
    max_pages = 200
    for _ in range(max_pages):
        kwargs: dict[str, Any] = {"vectorBucketName": bucket, "indexName": index}
        if token:
            kwargs["nextToken"] = token
        resp = s3v.list_vectors(**kwargs)
        out.extend(v["key"] for v in resp["vectors"])
        token = resp.get("nextToken")
        if not token:
            return out
    raise AssertionError(
        f"ListVectors kept returning a nextToken after {max_pages} pages; pagination does not "
        "terminate"
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
                f"{description} not reached within {timeout_s}s (last observed {len(last)} keys)"
            )
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
