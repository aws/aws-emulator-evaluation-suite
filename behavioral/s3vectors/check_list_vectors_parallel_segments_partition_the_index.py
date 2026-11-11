"""list-vectors-parallel-segments-partition-the-index."""

# segmentCount/segmentIndex partition the index: every vector is in exactly one segment, the union
# is the whole index, and membership repeats on a second pass. segmentIndex == segmentCount is inside
# both shape ranges, so the service, not botocore, refuses it.
#
# Wall clock: one PutVectors of 40 vectors and a few paginated passes; the 90s convergence poll is
# the only long wait and it raises on miss.

from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "list-vectors-parallel-segments-partition-the-index"
GROUP = "ordering"
SERVICES = ["s3vectors"]

MSG_SEGMENT_OUT_OF_RANGE = "Segment index is zero-indexed and must be smaller than segment count"

_DIMENSION = 4
_COUNT = 40
_SEGMENTS = 4
# Deliberately below _COUNT // _SEGMENTS (=10) so at least one nextToken is required INSIDE a
# segment -- a target that ignores pagination within a segment loses vectors and fails the
# union assertion.
_PAGE_SIZE = 7


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A parallel ListVectors sweep (segmentCount/segmentIndex) partitions the index exactly: segments
    are disjoint, their union is the sequential listing, membership repeats on a second pass, and
    segmentIndex == segmentCount is refused.
    """
    s3v = ctx.client("s3vectors")
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account, "STS returned no account id; the check cannot attribute its resources"

    bucket = ctx.unique_name("sim2real-s3v-seg-")
    s3v.create_vector_bucket(
        vectorBucketName=bucket,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket))

    index = ctx.unique_name("sim2real-s3v-seg-idx-")
    s3v.create_index(
        vectorBucketName=bucket,
        indexName=index,
        dataType="float32",
        dimension=_DIMENSION,
        distanceMetric="euclidean",
    )
    ctx.on_cleanup(lambda: s3v.delete_index(vectorBucketName=bucket, indexName=index))

    written = {f"seg-vec-{i:03d}" for i in range(_COUNT)}
    # 40 vectors is well under the documented 500-per-PutVectors-call limit, so this is one call
    # and the index is static from here on -- which is what makes the partition assertion clean.
    s3v.put_vectors(
        vectorBucketName=bucket,
        indexName=index,
        vectors=[
            {"key": key, "data": {"float32": [float(i + 1), 0.0, 0.0, 0.0]}}
            for i, key in enumerate(sorted(written))
        ],
    )
    ctx.on_cleanup(
        lambda: s3v.delete_vectors(
            vectorBucketName=bucket, indexName=index, keys=sorted(written)
        )
    )

    # Bounded retry, reason: newly written vectors take a moment to become listable. Raises on
    # deadline miss; the poll waits for the COUNT only.
    sequential = _poll_until(
        lambda: _paginate(s3v, bucket, index, page_size=_PAGE_SIZE),
        lambda keys: len(keys) == _COUNT,
        timeout_s=90.0,
        interval_s=3.0,
        description=f"all {_COUNT} vectors became listable via a sequential ListVectors pass",
    )
    assert set(sequential) == written, (
        f"the sequential pass returned key set of size {len(set(sequential))}; expected exactly "
        f"the {_COUNT} written keys. Missing: {sorted(written - set(sequential))[:5]}, "
        f"unexpected: {sorted(set(sequential) - written)[:5]}"
    )
    ground_truth = set(sequential)

    # --- The partition, pass 1.
    first_pass = {
        seg: _paginate(
            s3v, bucket, index, page_size=_PAGE_SIZE, segment_count=_SEGMENTS, segment_index=seg
        )
        for seg in range(_SEGMENTS)
    }

    for seg, keys in first_pass.items():
        assert len(keys) == len(set(keys)), (
            f"segment {seg}/{_SEGMENTS} returned duplicate keys within itself: "
            f"{sorted(k for k in keys if keys.count(k) > 1)[:5]}"
        )

    sizes = {seg: len(keys) for seg, keys in first_pass.items()}
    assert sum(sizes.values()) == len(ground_truth), (
        f"segment sizes {sizes} sum to {sum(sizes.values())}, expected exactly "
        f"{len(ground_truth)} -- a partition neither drops nor duplicates a vector"
    )

    for a in range(_SEGMENTS):
        for b in range(a + 1, _SEGMENTS):
            overlap = set(first_pass[a]) & set(first_pass[b])
            assert not overlap, (
                f"segments {a} and {b} of {_SEGMENTS} both returned {sorted(overlap)[:5]}; "
                "parallel segments must be disjoint or a parallel sweep double-counts"
            )

    union = set().union(*(set(v) for v in first_pass.values()))
    assert union == ground_truth, (
        f"the union of {_SEGMENTS} segments has {len(union)} keys but the sequential listing has "
        f"{len(ground_truth)}. Missing from the union: {sorted(ground_truth - union)[:5]}, "
        f"invented by the union: {sorted(union - ground_truth)[:5]}"
    )

    # --- Freeze leg: membership must not move for a static index. A target that assigns
    # segments by request time or by a fresh shuffle satisfies the partition on one pass and
    # fails here.
    for seg in range(_SEGMENTS):
        again = _paginate(
            s3v, bucket, index, page_size=_PAGE_SIZE, segment_count=_SEGMENTS, segment_index=seg
        )
        assert set(again) == set(first_pass[seg]), (
            f"segment {seg}/{_SEGMENTS} membership changed between two passes over a static "
            f"index: gained {sorted(set(again) - set(first_pass[seg]))[:5]}, lost "
            f"{sorted(set(first_pass[seg]) - set(again))[:5]}"
        )

    # --- Negative: segmentIndex out of range for the given segmentCount. The positive control is
    # already established -- segmentIndex=_SEGMENTS-1 returned results moments ago on this exact
    # wiring -- and it is re-established here so the refusal cannot be blamed on the index.
    control = _paginate(
        s3v,
        bucket,
        index,
        page_size=_PAGE_SIZE,
        segment_count=_SEGMENTS,
        segment_index=_SEGMENTS - 1,
    )
    assert set(control) == set(first_pass[_SEGMENTS - 1]), (
        f"positive control for the last valid segmentIndex ({_SEGMENTS - 1}) no longer matches "
        f"its first-pass membership: {sorted(set(control) ^ set(first_pass[_SEGMENTS - 1]))[:5]}"
    )

    err = _client_error(
        lambda: s3v.list_vectors(
            vectorBucketName=bucket,
            indexName=index,
            segmentCount=_SEGMENTS,
            segmentIndex=_SEGMENTS,
        )
    )
    code = err["Error"]["Code"]
    assert code == "ValidationException", (
        f"expected ValidationException for segmentIndex={_SEGMENTS} with "
        f"segmentCount={_SEGMENTS} (valid indexes are 0..{_SEGMENTS - 1}), got {code!r} "
        f"(message: {err['Error'].get('Message', '')!r})"
    )
    message = err["Error"].get("Message")
    assert message == MSG_SEGMENT_OUT_OF_RANGE, (
        f"unexpected {code} message for segmentIndex={_SEGMENTS} with segmentCount={_SEGMENTS}: "
        f"{message!r}"
    )
    # There is no restore beat by construction: segmentIndex == segmentCount can never become a
    # valid pairing (always-invalid input).


# ===== helpers (self-contained) =====
def _paginate(
    s3v,
    bucket: str,
    index: str,
    *,
    page_size: int,
    segment_count: int | None = None,
    segment_index: int | None = None,
) -> list[str]:
    """Every key from a fully drained ListVectors pass, optionally scoped to one segment. The
    per-page collection is hard-subscripted: `vectors` is a required output member, so an
    absent key is a divergence to surface, not a default to supply."""
    keys: list[str] = []
    token = None
    # A page budget derived from the request shape, so a target that returns a token forever
    # fails loudly instead of hanging: even one vector per page cannot need more pages than the
    # documented per-index population, and this index is tiny.
    max_pages = 200
    for _ in range(max_pages):
        kwargs: dict[str, Any] = {
            "vectorBucketName": bucket,
            "indexName": index,
            "maxResults": page_size,
        }
        if segment_count is not None:
            kwargs["segmentCount"] = segment_count
            kwargs["segmentIndex"] = segment_index
        if token:
            kwargs["nextToken"] = token
        resp = s3v.list_vectors(**kwargs)
        page = resp["vectors"]
        assert len(page) <= page_size, (
            f"ListVectors returned {len(page)} items for maxResults={page_size} "
            f"(segment {segment_index}/{segment_count})"
        )
        keys.extend(v["key"] for v in page)
        token = resp.get("nextToken")
        if not token:
            return keys
    raise AssertionError(
        f"ListVectors kept returning a nextToken after {max_pages} pages "
        f"(segment {segment_index}/{segment_count}); pagination does not terminate"
    )


def _client_error(fn) -> Any:
    """The full botocore error response. RAISES on unexpected success -- never returns a falsy
    sentinel."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(
        "the call was expected to be REFUSED but it succeeded -- segmentIndex must be strictly "
        "below segmentCount"
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
