"""deleted-vector-key-reusable-and-deleted-index-refuses-writes."""

# DeleteVectors is @idempotent, so a second delete of the same key returns 200. A deleted key is
# immediately reusable with no trace of the old data, and a PutVectors against a deleted index is
# refused with NotFoundException; index deletion is eventually consistent, so that is polled for.

from __future__ import annotations

import struct
import time
from typing import Any

from behavioral_harness import tags

CHECK = "deleted-vector-key-reusable-and-deleted-index-refuses-writes"
GROUP = "error-semantics"
SERVICES = ["s3vectors"]

MSG_INDEX_NOT_FOUND = "The specified index could not be found"

_DIMENSION = 3
_KEY_A = "vec-recycled"
_KEY_B = "vec-bystander"
_DATA_A_FIRST = [1.0, 0.0, 0.0]
_DATA_A_SECOND = [-0.5, 0.25, 0.125]
_DATA_B = [0.0, 1.0, 0.0]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A deleted vector is gone from all three readers, a second delete of the same key is a
    no-op, the key is immediately REUSABLE with new data and no duplicate, and a PutVectors
    against a DELETED index is refused with NotFoundException."""
    s3v = ctx.client("s3vectors")
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account, "STS returned no account id; the check cannot attribute its resources"

    bucket = ctx.unique_name("sim2real-s3v-recycle-")
    s3v.create_vector_bucket(
        vectorBucketName=bucket,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket))

    index = ctx.unique_name("sim2real-s3v-recycle-idx-")
    s3v.create_index(
        vectorBucketName=bucket,
        indexName=index,
        dataType="float32",
        dimension=_DIMENSION,
        distanceMetric="euclidean",
    )
    ctx.on_cleanup(lambda: s3v.delete_index(vectorBucketName=bucket, indexName=index))

    first = [_as_float32(v) for v in _DATA_A_FIRST]
    second = [_as_float32(v) for v in _DATA_A_SECOND]
    bystander = [_as_float32(v) for v in _DATA_B]
    assert _bits(first) != _bits(second), (
        "the re-put payload must differ from the original at float32 bit level, or 'the new data "
        "replaced the old' is unfalsifiable"
    )

    s3v.put_vectors(
        vectorBucketName=bucket,
        indexName=index,
        vectors=[
            {"key": _KEY_A, "data": {"float32": list(first)}, "metadata": {"generation": "one"}},
            {
                "key": _KEY_B,
                "data": {"float32": list(bystander)},
                "metadata": {"generation": "one"},
            },
        ],
    )
    ctx.on_cleanup(
        lambda: s3v.delete_vectors(
            vectorBucketName=bucket, indexName=index, keys=[_KEY_A, _KEY_B]
        )
    )

    # --- Positive control: both keys are readable and queryable BEFORE anything is deleted.
    both = _poll_until(
        lambda: s3v.get_vectors(
            vectorBucketName=bucket,
            indexName=index,
            keys=[_KEY_A, _KEY_B],
            returnData=True,
            returnMetadata=True,
        ),
        lambda r: len(r["vectors"]) == 2,
        timeout_s=60.0,
        interval_s=2.0,
        description="both vectors became readable",
    )
    by_key = {v["key"]: v for v in both["vectors"]}
    assert _bits(by_key[_KEY_A]["data"]["float32"]) == _bits(first), (
        f"{_KEY_A} did not store its first-generation data: expected float32 bits {_bits(first)}, "
        f"got {_bits(by_key[_KEY_A]['data']['float32'])}"
    )
    queryable = _poll_until(
        lambda: s3v.query_vectors(
            vectorBucketName=bucket,
            indexName=index,
            topK=2,
            queryVector={"float32": list(first)},
        )["vectors"],
        lambda vs: len(vs) == 2,
        timeout_s=60.0,
        interval_s=2.0,
        description="both vectors became queryable",
    )
    assert {v["key"] for v in queryable} == {_KEY_A, _KEY_B}, (
        f"pre-delete query returned {sorted(v['key'] for v in queryable)}, expected both keys"
    )

    # --- Delete exactly one key.
    s3v.delete_vectors(vectorBucketName=bucket, indexName=index, keys=[_KEY_A])

    # Three INDEPENDENT readers, each a different operation from the mutation, and each with the
    # surviving key as the in-instant twin control: a target that deleted everything, or that
    # deleted nothing, fails.
    after_get = _poll_until(
        lambda: s3v.get_vectors(
            vectorBucketName=bucket,
            indexName=index,
            keys=[_KEY_A, _KEY_B],
            returnData=True,
        ),
        lambda r: {v["key"] for v in r["vectors"]} == {_KEY_B},
        timeout_s=60.0,
        interval_s=2.0,
        description=f"GetVectors stopped returning {_KEY_A} while still returning {_KEY_B}",
    )
    assert {v["key"] for v in after_get["vectors"]} == {_KEY_B}, (
        f"GetVectors returned {sorted(v['key'] for v in after_get['vectors'])} after deleting "
        f"{_KEY_A}; expected exactly [{_KEY_B}]"
    )

    listed = {v["key"] for v in _list_all(s3v, bucket, index)}
    assert listed == {_KEY_B}, (
        f"ListVectors returned {sorted(listed)} after deleting {_KEY_A}; expected exactly "
        f"[{_KEY_B}]"
    )

    after_query = s3v.query_vectors(
        vectorBucketName=bucket,
        indexName=index,
        topK=2,
        queryVector={"float32": list(first)},
    )["vectors"]
    assert {v["key"] for v in after_query} == {_KEY_B}, (
        f"QueryVectors still surfaces {_KEY_A} after deletion: returned "
        f"{sorted(v['key'] for v in after_query)}, expected exactly [{_KEY_B}] even though the "
        f"query vector IS {_KEY_A}'s old data"
    )

    # --- A second delete of the same key: @idempotent in the model, so a no-op rather than a
    # refusal -- and it must not take the surviving key with it.
    s3v.delete_vectors(vectorBucketName=bucket, indexName=index, keys=[_KEY_A])
    still = {v["key"] for v in _list_all(s3v, bucket, index)}
    assert still == {_KEY_B}, (
        f"re-deleting the already-deleted {_KEY_A} changed the index: ListVectors now returns "
        f"{sorted(still)}, expected exactly [{_KEY_B}]"
    )

    # --- The identifier is REUSABLE, and the reuse carries the NEW value.
    s3v.put_vectors(
        vectorBucketName=bucket,
        indexName=index,
        vectors=[
            {"key": _KEY_A, "data": {"float32": list(second)}, "metadata": {"generation": "two"}}
        ],
    )
    revived = _poll_until(
        lambda: s3v.get_vectors(
            vectorBucketName=bucket,
            indexName=index,
            keys=[_KEY_A],
            returnData=True,
            returnMetadata=True,
        ),
        lambda r: len(r["vectors"]) == 1,
        timeout_s=60.0,
        interval_s=2.0,
        description=f"the recycled key {_KEY_A} became readable again",
    )
    got = revived["vectors"][0]
    assert _bits(got["data"]["float32"]) == _bits(second), (
        f"the recycled key returned stale data: expected the second-generation float32 bits "
        f"{_bits(second)}, got {_bits(got['data']['float32'])} (first generation was "
        f"{_bits(first)})"
    )
    assert got["metadata"]["generation"] == "two", (
        f"the recycled key kept first-generation metadata: {got['metadata']!r}"
    )
    relisted = [v["key"] for v in _list_all(s3v, bucket, index)]
    assert sorted(relisted) == sorted([_KEY_A, _KEY_B]), (
        f"after recycling {_KEY_A} the index lists {sorted(relisted)}, expected exactly "
        f"{sorted([_KEY_A, _KEY_B])}"
    )
    assert len(relisted) == len(set(relisted)), (
        f"recycling a deleted key produced a duplicate entry: {sorted(relisted)}"
    )

    # --- A data-plane MUTATION on a dead index. A dedicated index, so the flow above keeps its
    # own clean teardown, and a positive control on THIS index first.
    doomed = ctx.unique_name("sim2real-s3v-doomed-idx-")
    s3v.create_index(
        vectorBucketName=bucket,
        indexName=doomed,
        dataType="float32",
        dimension=_DIMENSION,
        distanceMetric="euclidean",
    )
    ctx.on_cleanup(lambda: _delete_index_if_present(s3v, bucket, doomed))
    probe_key = "vec-doomed-probe"

    def _write_probe() -> None:
        s3v.put_vectors(
            vectorBucketName=bucket,
            indexName=doomed,
            vectors=[{"key": probe_key, "data": {"float32": list(bystander)}}],
        )

    # Positive control: the EXACT call that must later be refused works now.
    _write_probe()
    _poll_until(
        lambda: s3v.get_vectors(
            vectorBucketName=bucket, indexName=doomed, keys=[probe_key], returnData=True
        ),
        lambda r: len(r["vectors"]) == 1,
        timeout_s=60.0,
        interval_s=2.0,
        description="the probe vector became readable in the soon-to-be-deleted index",
    )

    s3v.delete_vectors(vectorBucketName=bucket, indexName=doomed, keys=[probe_key])
    s3v.delete_index(vectorBucketName=bucket, indexName=doomed)

    # Bounded retry, reason: index deletion is eventually consistent, so the refusal takes a
    # moment to appear. Raises on deadline miss -- a target that keeps accepting writes to a
    # deleted index simply never reaches the condition, which is the correct verdict.
    code, message = _poll_for_error(
        _write_probe,
        timeout_s=60.0,
        interval_s=2.0,
        description="PutVectors against the deleted index began failing",
    )
    assert code == "NotFoundException", (
        f"PutVectors against a deleted index returned {code!r}, expected NotFoundException"
    )
    assert message == MSG_INDEX_NOT_FOUND, (
        f"unexpected PutVectors {code} message {message!r}"
    )


# ===== helpers (self-contained) =====
def _as_float32(value: float) -> float:
    return struct.unpack("<f", struct.pack("<f", float(value)))[0]


def _bits(values) -> list[str]:
    return [struct.pack("<f", float(v)).hex() for v in values]


def _poll_for_error(fn, *, timeout_s: float, interval_s: float, description: str) -> tuple[str, str]:
    """(code, message) of the first ClientError fn() raises. A call that keeps SUCCEEDING
    raises at the deadline -- a target that keeps accepting writes to a deleted index never
    reaches a refusal, which is the correct verdict."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not reached within {timeout_s}s: the call still SUCCEEDED and "
                f"returned {result!r}"
            )
        time.sleep(interval_s)


def _delete_index_if_present(s3v, bucket: str, index: str) -> None:
    """Teardown for the index the check deletes itself: it is normally already gone."""
    from botocore.exceptions import ClientError

    try:
        s3v.delete_index(vectorBucketName=bucket, indexName=index)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _list_all(s3v, bucket: str, index: str) -> list[dict]:
    out: list[dict] = []
    token = None
    max_pages = 50
    for _ in range(max_pages):
        kwargs: dict[str, Any] = {"vectorBucketName": bucket, "indexName": index}
        if token:
            kwargs["nextToken"] = token
        resp = s3v.list_vectors(**kwargs)
        out.extend(resp["vectors"])
        token = resp.get("nextToken")
        if not token:
            return out
    raise AssertionError(
        f"ListVectors kept returning a nextToken after {max_pages} pages over a 2-vector index"
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
