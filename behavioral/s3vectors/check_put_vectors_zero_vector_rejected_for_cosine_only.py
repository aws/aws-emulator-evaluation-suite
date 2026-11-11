"""put-vectors-zero-vector-rejected-for-cosine-only."""

# The cosine refusal and the euclidean acceptance are both asserted against the same payload.

from __future__ import annotations

import struct
import time
from typing import Any

from behavioral_harness import tags

CHECK = "put-vectors-zero-vector-rejected-for-cosine-only"
GROUP = "error-semantics"
SERVICES = ["s3vectors"]

_DIMENSION = 3
_ZERO_KEY = "vec-all-zeros"
_CONTROL_KEY = "vec-nonzero-control"
_CONTROL_DATA = [0.25, -0.5, 0.75]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An all-zeros vector is refused by a `cosine` index (cosine similarity is undefined at
    the origin) and ACCEPTED by a `euclidean` index -- the identical payload, in the same
    bucket, in the same instant. The metric decides the validation rule, not the payload."""
    s3v = ctx.client("s3vectors")
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account, "STS returned no account id; the check cannot attribute its resources"

    bucket = ctx.unique_name("sim2real-s3v-zerovec-")
    s3v.create_vector_bucket(
        vectorBucketName=bucket,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket))

    indexes: dict[str, str] = {}
    for metric in ("cosine", "euclidean"):
        name = ctx.unique_name(f"sim2real-s3v-{metric[:3]}-")
        s3v.create_index(
            vectorBucketName=bucket,
            indexName=name,
            dataType="float32",
            dimension=_DIMENSION,
            distanceMetric=metric,
        )
        ctx.on_cleanup(lambda b=bucket, n=name: s3v.delete_index(vectorBucketName=b, indexName=n))
        indexes[metric] = name

    zero_vector = [0.0] * _DIMENSION
    control = [_as_float32(v) for v in _CONTROL_DATA]

    # --- BEAT 1: positive control on the SUBJECT wiring. A well-formed non-zero vector is
    # accepted by the cosine index and independently readable, so a later refusal cannot be
    # "this index refuses every PutVectors" or "these credentials cannot write".
    s3v.put_vectors(
        vectorBucketName=bucket,
        indexName=indexes["cosine"],
        vectors=[{"key": _CONTROL_KEY, "data": {"float32": list(control)}}],
    )
    ctx.on_cleanup(
        lambda: s3v.delete_vectors(
            vectorBucketName=bucket, indexName=indexes["cosine"], keys=[_CONTROL_KEY]
        )
    )
    control_read = _poll_until(
        lambda: s3v.get_vectors(
            vectorBucketName=bucket,
            indexName=indexes["cosine"],
            keys=[_CONTROL_KEY],
            returnData=True,
        ),
        lambda r: len(r["vectors"]) == 1,
        timeout_s=60.0,
        interval_s=2.0,
        description="the non-zero control vector became readable in the cosine index",
    )
    assert _bits(control_read["vectors"][0]["data"]["float32"]) == _bits(control), (
        "cosine-index positive control round-tripped wrong: expected float32 bits "
        f"{_bits(control)}, got {_bits(control_read['vectors'][0]['data']['float32'])}"
    )

    # --- BEAT 2: break exactly ONE thing -- the vector is all zeros. Nothing else changes:
    # same bucket, same dimension, same dataType, same batch shape of one.
    err = _client_error(
        lambda: s3v.put_vectors(
            vectorBucketName=bucket,
            indexName=indexes["cosine"],
            vectors=[{"key": _ZERO_KEY, "data": {"float32": list(zero_vector)}}],
        )
    )
    code = err["Error"]["Code"]
    message = err["Error"].get("Message", "")
    assert code == "ValidationException", (
        f"expected ValidationException for an all-zeros vector in a cosine index, got {code!r} "
        f"(message: {message!r})"
    )
    assert message == (
        f"Invalid record for key '{_ZERO_KEY}': cosine distance does not support vectors with zero norm"
    ), (
        "the refusal must name the zero-vector rule so it is distinguishable from a dimension "
        f"or type error; got message {message!r}"
    )

    # --- BEAT 3: effect absent, by an independent read through a different operation. The
    # rejected key must exist neither in GetVectors nor in ListVectors.
    absent = s3v.get_vectors(
        vectorBucketName=bucket,
        indexName=indexes["cosine"],
        keys=[_ZERO_KEY],
        returnData=True,
    )
    assert absent["vectors"] == [], (
        f"the rejected all-zeros vector was written anyway: GetVectors returned "
        f"{absent['vectors']!r} for key {_ZERO_KEY!r}"
    )
    listed = {v["key"] for v in _list_all_keys(s3v, bucket, indexes["cosine"])}
    assert _ZERO_KEY not in listed, (
        "the rejected all-zeros vector appears in ListVectors for the cosine index: "
        f"{sorted(listed)}"
    )
    assert _CONTROL_KEY in listed, (
        f"the positive-control vector vanished from ListVectors for the cosine index: "
        f"{sorted(listed)} -- the rejection must not have destroyed unrelated state"
    )

    # --- BEAT 4: the TWIN control group, in the same instant, on the same wiring, differing
    # ONLY in distanceMetric. The identical all-zeros payload must be ACCEPTED here. A target
    # that refuses zero vectors unconditionally fails this beat; one that accepts them
    # unconditionally already failed beat 2. There is no restore beat by construction: an
    # all-zeros vector can never become valid for a cosine index (always-invalid input).
    s3v.put_vectors(
        vectorBucketName=bucket,
        indexName=indexes["euclidean"],
        vectors=[{"key": _ZERO_KEY, "data": {"float32": list(zero_vector)}}],
    )
    ctx.on_cleanup(
        lambda: s3v.delete_vectors(
            vectorBucketName=bucket, indexName=indexes["euclidean"], keys=[_ZERO_KEY]
        )
    )
    twin = _poll_until(
        lambda: s3v.get_vectors(
            vectorBucketName=bucket,
            indexName=indexes["euclidean"],
            keys=[_ZERO_KEY],
            returnData=True,
        ),
        lambda r: len(r["vectors"]) == 1,
        timeout_s=60.0,
        interval_s=2.0,
        description="the all-zeros vector became readable in the euclidean index",
    )
    got = twin["vectors"][0]
    assert got["key"] == _ZERO_KEY, (
        f"euclidean index returned key {got['key']!r}, expected {_ZERO_KEY!r}"
    )
    assert _bits(got["data"]["float32"]) == _bits(zero_vector), (
        "the all-zeros vector must round-trip as zeros in a euclidean index: expected float32 "
        f"bits {_bits(zero_vector)}, got {_bits(got['data']['float32'])}"
    )


def _as_float32(value: float) -> float:
    return struct.unpack("<f", struct.pack("<f", float(value)))[0]


def _bits(values) -> list[str]:
    """Float32 bit patterns, so float printing cannot mask a difference. -0.0 and
    0.0 have DIFFERENT bit patterns, which is deliberate: a target that flips the sign bit on
    a zero component is diverging."""
    return [struct.pack("<f", float(v)).hex() for v in values]


def _client_error(fn) -> Any:
    """The full botocore error response. RAISES on unexpected success -- never returns a falsy
    sentinel."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(
        "the call was expected to be REFUSED but it succeeded -- an all-zeros vector must not "
        "be accepted by a cosine index"
    )


def _list_all_keys(s3v, bucket: str, index: str) -> list[dict]:
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
