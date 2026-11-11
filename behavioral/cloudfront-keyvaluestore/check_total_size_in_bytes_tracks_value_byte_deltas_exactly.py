"""total-size-in-bytes-tracks-value-byte-deltas-exactly."""

# TotalSizeInBytes counts UTF-16 code units, not UTF-8 bytes, despite the field's name. The two
# agree for text inside the Basic Multilingual Plane and diverge for a character above U+FFFF,
# which costs 2 units (a surrogate pair) but 4 UTF-8 bytes.
# Doc basis: "total_size_in_bytes => Integer. Total size of the Key Value Store in bytes."
# (https://docs.aws.amazon.com/sdk-for-ruby/v3/api/Aws/CloudFrontKeyValueStore/Types/DescribeKeyValueStoreResponse.html)

from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "total-size-in-bytes-tracks-value-byte-deltas-exactly"
GROUP = "data-plane"
SERVICES = ["cloudfront-keyvaluestore"]

# One key for the whole check. Every assertion is a DELTA on this single key, so the per-item
# overhead and the key-name contribution cancel out and are never assumed.
_KEY = "accounting-probe"

# One Python character, four UTF-8 bytes, ONE supplementary-plane code point (U+1F30D) that UTF-16
# must encode as a two-unit surrogate pair. Used to make a value whose CHARACTER count matches
# measurement 1 while its UTF-16 CODE UNIT count doubles and its UTF-8 BYTE count quadruples — the
# three candidate units diverge on this one value, which is what lets the measurement tell them
# apart.
_WIDE_CHAR = "\U0001f30d"

_SHORT_CHARS = 100
_LONG_CHARS = 140


def _utf16_units(s: str) -> int:
    """The number of UTF-16 code units ``s`` encodes to — 1 per BMP character, 2 per character
    outside the BMP (a surrogate pair): the unit TotalSizeInBytes tracks."""
    return len(s.encode("utf-16-le")) // 2


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Overwriting one key, TotalSizeInBytes moves by exactly the value's UTF-16 code-unit delta
    (100 supplementary-plane characters count 200, not 400 UTF-8 bytes) and returns exactly to its
    earlier size when the original value is restored, as GetKey's TotalSizeInBytes agrees."""
    _ensure_awscrt()
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]

    short_ascii = "a" * _SHORT_CHARS                 # 100 chars, 100 bytes, 100 UTF-16 units
    long_ascii = "b" * _LONG_CHARS                    # 140 chars, 140 bytes, 140 UTF-16 units
    wide = _WIDE_CHAR * _SHORT_CHARS                 # 100 chars, 400 bytes, 200 UTF-16 units

    short_units = _utf16_units(short_ascii)
    long_units = _utf16_units(long_ascii)
    wide_units = _utf16_units(wide)
    short_bytes = len(short_ascii.encode("utf-8"))
    long_bytes = len(long_ascii.encode("utf-8"))
    wide_bytes = len(wide.encode("utf-8"))

    baseline = dp.describe_key_value_store(KvsARN=arn)
    assert baseline["ItemCount"] == 0, (
        f"a freshly provisioned store reports ItemCount={baseline['ItemCount']!r}, expected 0"
    )
    assert baseline["TotalSizeInBytes"] == 0, (
        f"a freshly provisioned store reports "
        f"TotalSizeInBytes={baseline['TotalSizeInBytes']!r}, expected 0"
    )

    # ---- Measurement 1: the key exists holding a 100-code-unit value ----
    dp.put_key(KvsARN=arn, Key=_KEY, Value=short_ascii, IfMatch=baseline["ETag"])
    m1 = dp.describe_key_value_store(KvsARN=arn)
    size1 = m1["TotalSizeInBytes"]
    assert m1["ItemCount"] == 1, (
        f"after one PutKey ItemCount={m1['ItemCount']!r}, expected 1"
    )
    assert size1 > 0, (
        f"one item holding a {short_units}-UTF-16-code-unit value must have non-zero size, "
        f"got {size1!r}"
    )

    # ---- Measurement 2: same key, value 40 code units (and 40 bytes) longer ----
    dp.put_key(KvsARN=arn, Key=_KEY, Value=long_ascii, IfMatch=m1["ETag"])
    m2 = dp.describe_key_value_store(KvsARN=arn)
    size2 = m2["TotalSizeInBytes"]
    expected_delta_12 = long_units - short_units
    assert m2["ItemCount"] == 1, (
        f"overwriting an existing key must not change ItemCount: got {m2['ItemCount']!r}, "
        f"expected 1"
    )
    assert size2 - size1 == expected_delta_12, (
        f"overwriting {_KEY!r} from a {short_units}-UTF-16-code-unit value to a "
        f"{long_units}-UTF-16-code-unit value must move TotalSizeInBytes by exactly "
        f"{expected_delta_12}; it moved by {size2 - size1} ({size1} -> {size2}). Same key and "
        f"same item count, so per-item overhead cancels. (Both values are pure ASCII, so UTF-8 "
        f"bytes and UTF-16 code units cannot be told apart by this leg alone: {short_bytes} -> "
        f"{long_bytes} bytes)"
    )

    # ---- Measurement 3: same key, same CHARACTER count as measurement 1, but a supplementary- ----
    # ---- plane value: 4x the UTF-8 bytes, only 2x the UTF-16 code units. This leg is what tells ----
    # ---- the UTF-8-byte theory and the UTF-16-code-unit theory apart. ----
    dp.put_key(KvsARN=arn, Key=_KEY, Value=wide, IfMatch=m2["ETag"])
    m3 = dp.describe_key_value_store(KvsARN=arn)
    size3 = m3["TotalSizeInBytes"]
    expected_delta_23 = wide_units - long_units
    expected_delta_13 = wide_units - short_units
    assert size3 - size2 == expected_delta_23, (
        f"overwriting {_KEY!r} from a {long_units}-UTF-16-code-unit value to a "
        f"{wide_units}-UTF-16-code-unit value ({_SHORT_CHARS} supplementary-plane characters, "
        f"{wide_bytes} UTF-8 bytes) must move TotalSizeInBytes by exactly {expected_delta_23}; "
        f"it moved by {size3 - size2} ({size2} -> {size3}). A UTF-8-byte theory predicts "
        f"{wide_bytes - long_bytes} here instead"
    )
    assert size3 - size1 == expected_delta_13, (
        f"the {_SHORT_CHARS}-character multi-byte value ({wide_units} UTF-16 code units, "
        f"{wide_bytes} UTF-8 bytes) and the {_SHORT_CHARS}-character ASCII value "
        f"({short_units} UTF-16 code units, {short_bytes} UTF-8 bytes) have the SAME character "
        f"count, so a store counting characters would report a delta of 0 here; TotalSizeInBytes "
        f"must differ by exactly {expected_delta_13} (the UTF-16 code-unit delta), and a "
        f"UTF-8-byte theory would instead predict {wide_bytes - short_bytes}. It differs by "
        f"{size3 - size1} ({size1} -> {size3})"
    )

    # ---- Measurement 4: back to the original value; the size must return exactly ----
    dp.put_key(KvsARN=arn, Key=_KEY, Value=short_ascii, IfMatch=m3["ETag"])
    m4 = dp.describe_key_value_store(KvsARN=arn)
    size4 = m4["TotalSizeInBytes"]
    assert size4 == size1, (
        f"restoring {_KEY!r} to the identical {short_units}-UTF-16-code-unit value must restore "
        f"TotalSizeInBytes to exactly {size1}; it is {size4}. Accounting that only ever grows "
        f"(a high-water mark) fails here"
    )
    assert m4["ItemCount"] == 1, (
        f"after four overwrites of one key ItemCount={m4['ItemCount']!r}, expected 1"
    )

    # ---- Terminal read: an independent operation agrees on both the bytes and the accounting ----
    got = dp.get_key(KvsARN=arn, Key=_KEY)
    assert got["Value"] == short_ascii, (
        f"GetKey({_KEY!r}) returned a {len(got['Value'])}-character value, expected the "
        f"{_SHORT_CHARS}-character value last written"
    )
    assert got["TotalSizeInBytes"] == size4, (
        f"GetKey reports the WHOLE store's TotalSizeInBytes={got['TotalSizeInBytes']!r}, which "
        f"must equal DescribeKeyValueStore's {size4!r} for the same store state"
    )


def _ensure_awscrt() -> None:
    """SigV4A signing for this data plane needs awscrt; without it the runner lacks a dependency."""
    from botocore.compat import HAS_CRT

    if not HAS_CRT:
        from fidelity_tests_runner import RequiredToolMissing

        raise RequiredToolMissing(["awscrt"])


def _wait_for_store_ready(ctx, name, timeout_s=180.0, interval_s=3.0):
    """Poll DescribeKeyValueStore until READY. Raises on timeout — never returns a last value."""
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cf.describe_key_value_store(Name=name)["KeyValueStore"]["Status"].upper()
        if status == "READY":
            return
        assert "FAIL" not in status, (
            f"key value store {name} entered a failure status: {status!r}, expected to reach READY"
        )
        time.sleep(interval_s)
    raise AssertionError(
        f"key value store {name} never reached READY within {timeout_s}s, last status={status!r}"
    )


def _create_ready_store(ctx):
    """The name is unique per run, so the store is always this check's own."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-kvs-")
    resp = cf.create_key_value_store(Name=name, Comment="sim2real behavioral check")
    arn = resp["KeyValueStore"]["ARN"]

    def _cleanup() -> None:
        # Registered before the READY poll: a store that never becomes READY still exists and still
        # has to be deleted. The control-plane ETag is re-read because it rotates.
        etag = cf.describe_key_value_store(Name=name)["ETag"]
        cf.delete_key_value_store(Name=name, IfMatch=etag)

    ctx.on_cleanup(_cleanup)
    _wait_for_store_ready(ctx, name)
    return {"name": name, "arn": arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
