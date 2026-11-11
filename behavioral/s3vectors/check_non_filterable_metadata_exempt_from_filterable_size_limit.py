"""non-filterable-metadata-exempt-from-filterable-size-limit."""

# The documented limits are two separate budgets: filterable metadata up to 2 KB and total metadata
# up to 40 KB per vector (Amazon S3 User Guide, s3-vectors-limitations.html). An 8 KiB value sits
# strictly between them, so it is accepted only under a key declared non-filterable.

from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "non-filterable-metadata-exempt-from-filterable-size-limit"
GROUP = "representation"
SERVICES = ["s3vectors"]

_DIMENSION = 4
_VECTOR_DATA = [0.125, -0.25, 0.5, -0.75]

# Both figures are FIXED, non-adjustable API constants published in the service's limitations
# table -- not account quotas -- so pinning them is correct. They are named here and the
# payload is DERIVED from them, so a doc change is a one-line edit and the intent stays legible.
_FILTERABLE_LIMIT_BYTES = 2 * 1024
_TOTAL_LIMIT_BYTES = 40 * 1024

_NON_FILTERABLE_KEY = "chunk"
_FILTERABLE_KEY = "body"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A key declared in `nonFilterableMetadataKeys` leaves the 2 KB filterable budget for the 40 KB total:
    an 8 KiB value is accepted under the declared key and refused under an undeclared one, and a small
    value makes the identical call succeed.
    """
    s3v = ctx.client("s3vectors")
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account, "STS returned no account id; the check cannot attribute its resources"

    bucket = ctx.unique_name("sim2real-s3v-nfmeta-")
    s3v.create_vector_bucket(
        vectorBucketName=bucket,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket))

    index = ctx.unique_name("sim2real-s3v-nfmeta-idx-")
    s3v.create_index(
        vectorBucketName=bucket,
        indexName=index,
        dataType="float32",
        dimension=_DIMENSION,
        distanceMetric="euclidean",
        metadataConfiguration={"nonFilterableMetadataKeys": [_NON_FILTERABLE_KEY]},
    )
    ctx.on_cleanup(lambda: s3v.delete_index(vectorBucketName=bucket, indexName=index))

    # Precondition, not the subject: the index really carries the declaration the rest of the
    # check reasons about. Asserted so a later refusal cannot be blamed on a dropped config.
    declared = s3v.get_index(vectorBucketName=bucket, indexName=index)["index"]
    declared_keys = declared["metadataConfiguration"]["nonFilterableMetadataKeys"]
    assert declared_keys == [_NON_FILTERABLE_KEY], (
        f"GetIndex reports nonFilterableMetadataKeys {declared_keys!r}, expected "
        f"[{_NON_FILTERABLE_KEY!r}] as pinned at CreateIndex"
    )

    # One payload, used for BOTH legs, sized strictly between the two documented budgets so the
    # only difference between accept and refuse is WHICH KEY it is stored under.
    payload = "x" * (4 * _FILTERABLE_LIMIT_BYTES)
    payload_bytes = len(payload.encode("utf-8"))
    assert _FILTERABLE_LIMIT_BYTES < payload_bytes < _TOTAL_LIMIT_BYTES, (
        f"the probe payload must sit strictly between the filterable cap "
        f"({_FILTERABLE_LIMIT_BYTES} B) and the total cap ({_TOTAL_LIMIT_BYTES} B); it is "
        f"{payload_bytes} B"
    )

    big_key = "vec-big-non-filterable"
    small_key = "vec-small-filterable"
    reject_key = "vec-big-filterable"

    # --- BEAT 1: positive control. A small FILTERABLE value is accepted, so the index, the
    # credentials and the PutVectors path are all healthy before anything is refused.
    small_value = "s" * 64
    s3v.put_vectors(
        vectorBucketName=bucket,
        indexName=index,
        vectors=[
            {
                "key": small_key,
                "data": {"float32": list(_VECTOR_DATA)},
                "metadata": {_FILTERABLE_KEY: small_value},
            }
        ],
    )
    ctx.on_cleanup(
        lambda: s3v.delete_vectors(vectorBucketName=bucket, indexName=index, keys=[small_key])
    )
    small_read = _poll_until(
        lambda: s3v.get_vectors(
            vectorBucketName=bucket, indexName=index, keys=[small_key], returnMetadata=True
        ),
        lambda r: len(r["vectors"]) == 1,
        timeout_s=60.0,
        interval_s=2.0,
        description="the small-filterable-metadata control vector became readable",
    )
    assert small_read["vectors"][0]["metadata"][_FILTERABLE_KEY] == small_value, (
        f"control vector metadata[{_FILTERABLE_KEY!r}] round-tripped as "
        f"{small_read['vectors'][0]['metadata'][_FILTERABLE_KEY]!r}, expected the "
        f"{len(small_value)}-char value written"
    )

    # --- BEAT 2: the SAME oversized payload under the DECLARED non-filterable key is accepted,
    # and comes back verbatim. This is what proves nonFilterableMetadataKeys DOES something
    # rather than merely echoing on GetIndex.
    s3v.put_vectors(
        vectorBucketName=bucket,
        indexName=index,
        vectors=[
            {
                "key": big_key,
                "data": {"float32": list(_VECTOR_DATA)},
                "metadata": {_NON_FILTERABLE_KEY: payload},
            }
        ],
    )
    ctx.on_cleanup(
        lambda: s3v.delete_vectors(vectorBucketName=bucket, indexName=index, keys=[big_key])
    )
    big_read = _poll_until(
        lambda: s3v.get_vectors(
            vectorBucketName=bucket, indexName=index, keys=[big_key], returnMetadata=True
        ),
        lambda r: len(r["vectors"]) == 1,
        timeout_s=60.0,
        interval_s=2.0,
        description=f"the {payload_bytes}-byte non-filterable metadata vector became readable",
    )
    returned = big_read["vectors"][0]["metadata"][_NON_FILTERABLE_KEY]
    assert returned == payload, (
        f"non-filterable metadata did not round-trip verbatim: wrote {payload_bytes} bytes, "
        f"read back {len(returned.encode('utf-8'))} bytes "
        f"(prefix {returned[:32]!r}, suffix {returned[-32:]!r})"
    )

    # --- BEAT 3: break exactly ONE thing -- the same payload, the same vector data, the same
    # index; only the metadata KEY changes to one that was never declared non-filterable, so
    # the value now counts against the 2 KB filterable budget.
    err = _client_error(
        lambda: s3v.put_vectors(
            vectorBucketName=bucket,
            indexName=index,
            vectors=[
                {
                    "key": reject_key,
                    "data": {"float32": list(_VECTOR_DATA)},
                    "metadata": {_FILTERABLE_KEY: payload},
                }
            ],
        )
    )
    code = err["Error"]["Code"]
    message = err["Error"].get("Message", "")
    assert code == "ValidationException", (
        f"expected ValidationException for {payload_bytes} B of FILTERABLE metadata against a "
        f"{_FILTERABLE_LIMIT_BYTES} B cap, got {code!r} (message: {message!r})"
    )
    expected_message = (
        f"Invalid record for key '{reject_key}': Filterable metadata must have at most "
        f"{_FILTERABLE_LIMIT_BYTES} bytes"
    )
    assert message == expected_message, (
        f"unexpected {code} message for {payload_bytes} B of filterable metadata: {message!r}"
    )

    # --- BEAT 4: effect absent, via independent reads through two other operations.
    absent = s3v.get_vectors(
        vectorBucketName=bucket, indexName=index, keys=[reject_key], returnMetadata=True
    )
    assert absent["vectors"] == [], (
        f"the refused vector was written anyway: GetVectors returned {absent['vectors']!r} for "
        f"key {reject_key!r}"
    )
    listed = {v["key"] for v in _list_all(s3v, bucket, index)}
    assert reject_key not in listed, (
        f"the refused vector appears in ListVectors: {sorted(listed)}"
    )
    assert {big_key, small_key} <= listed, (
        f"the refusal destroyed accepted state: ListVectors returned {sorted(listed)}, expected "
        f"it to still contain {big_key!r} and {small_key!r}"
    )

    # --- BEAT 5+6: restore -- shrink ONLY the payload, keep the same key and the same filterable
    # metadata key, and the identical call shape now succeeds and is readable. This is what
    # separates "rejects oversized filterable metadata" from "rejects this metadata key".
    s3v.put_vectors(
        vectorBucketName=bucket,
        indexName=index,
        vectors=[
            {
                "key": reject_key,
                "data": {"float32": list(_VECTOR_DATA)},
                "metadata": {_FILTERABLE_KEY: payload[: _FILTERABLE_LIMIT_BYTES // 4]},
            }
        ],
    )
    ctx.on_cleanup(
        lambda: s3v.delete_vectors(vectorBucketName=bucket, indexName=index, keys=[reject_key])
    )
    restored = _poll_until(
        lambda: s3v.get_vectors(
            vectorBucketName=bucket, indexName=index, keys=[reject_key], returnMetadata=True
        ),
        lambda r: len(r["vectors"]) == 1,
        timeout_s=60.0,
        interval_s=2.0,
        description="the restored under-cap filterable-metadata vector became readable",
    )
    restored_value = restored["vectors"][0]["metadata"][_FILTERABLE_KEY]
    assert restored_value == payload[: _FILTERABLE_LIMIT_BYTES // 4], (
        f"restored vector metadata[{_FILTERABLE_KEY!r}] is "
        f"{len(restored_value.encode('utf-8'))} bytes, expected "
        f"{_FILTERABLE_LIMIT_BYTES // 4} bytes of the same payload"
    )


# ===== helpers (self-contained) =====
def _client_error(fn) -> Any:
    """The full botocore error response. RAISES on unexpected success -- never returns a falsy
    sentinel."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(
        "the call was expected to be REFUSED but it succeeded -- filterable metadata above the "
        "documented per-vector cap must not be accepted"
    )


def _list_all(s3v, bucket: str, index: str) -> list[dict]:
    out: list[dict] = []
    token = None
    while True:
        kwargs = {"vectorBucketName": bucket, "indexName": index}
        if token:
            kwargs["nextToken"] = token
        resp = s3v.list_vectors(**kwargs)
        out.extend(resp["vectors"])
        token = resp.get("nextToken")
        if not token:
            return out


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
