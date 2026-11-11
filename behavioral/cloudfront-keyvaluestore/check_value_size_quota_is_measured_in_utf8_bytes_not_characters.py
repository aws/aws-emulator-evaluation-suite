"""value-size-quota-is-measured-in-utf8-bytes-not-characters."""

from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "value-size-quota-is-measured-in-utf8-bytes-not-characters"
GROUP = "overly-permissive"
SERVICES = ["cloudfront-keyvaluestore"]

# One Python character, four UTF-8 bytes (U+1F30D EARTH GLOBE EUROPE-AFRICA). The entire
# discriminator rests on that 1-char/4-byte ratio: it lets two values carry an IDENTICAL character
# count while differing 4x in encoded byte length.
_WIDE_CHAR = "\U0001f30d"

# The shared character count of the ASCII positive control and the multi-byte negative. Chosen so
# the ASCII form (600 bytes) sits comfortably under, and the multi-byte form (2400 bytes)
# comfortably over, the documented 1 KB value limit.
_SHARED_CHAR_COUNT = 600

# A multi-byte value that is UNDER the limit by bytes (200 chars * 4 = 800 bytes). Its only job is
# to prove the refusal below is a SIZE refusal and not "this store rejects every non-ASCII value" —
# without it, a target that refuses all multi-byte input scores green on the negative leg.
_WIDE_UNDER_CHAR_COUNT = 200


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """The value-size quota counts UTF-8 bytes, not characters: 600 ASCII and 200 four-byte characters
    are accepted, while 600 four-byte characters (2400 bytes) are refused, so neither a character
    count nor an ASCII-only rule passes.
    """
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]

    ascii_value = "a" * _SHARED_CHAR_COUNT
    wide_under_value = _WIDE_CHAR * _WIDE_UNDER_CHAR_COUNT
    wide_over_value = _WIDE_CHAR * _SHARED_CHAR_COUNT

    # Byte lengths are computed here, never asserted against each other: an assert over local
    # constants cannot fail. They are carried into the assertion messages instead.
    ascii_bytes = len(ascii_value.encode("utf-8"))
    wide_under_bytes = len(wide_under_value.encode("utf-8"))
    wide_over_bytes = len(wide_over_value.encode("utf-8"))

    # ---- Positive control 1: the ASCII twin of the refused value, same character count ----
    etag = _dp_etag(dp, arn)
    put_ascii = dp.put_key(KvsARN=arn, Key="ascii-twin", Value=ascii_value, IfMatch=etag)
    assert put_ascii["ItemCount"] == 1, (
        f"after the first PutKey the store reports ItemCount={put_ascii['ItemCount']!r}, "
        f"expected 1 (value was {_SHARED_CHAR_COUNT} ASCII chars = {ascii_bytes} bytes)"
    )

    # ---- Positive control 2: multi-byte, but UNDER the limit by bytes ----
    put_wide_ok = dp.put_key(
        KvsARN=arn, Key="wide-under", Value=wide_under_value, IfMatch=put_ascii["ETag"],
    )
    assert put_wide_ok["ItemCount"] == 2, (
        f"a {_WIDE_UNDER_CHAR_COUNT}-character multi-byte value ({wide_under_bytes} UTF-8 bytes, "
        f"under the limit) must be accepted; store reports "
        f"ItemCount={put_wide_ok['ItemCount']!r}, expected 2. A target failing here refuses "
        f"non-ASCII input outright rather than enforcing a byte quota"
    )

    before_refusal = dp.describe_key_value_store(KvsARN=arn)
    etag_before_refusal = before_refusal["ETag"]

    # ---- Negative: identical character count to the accepted ASCII leg, 4x the bytes ----
    # Always-invalid-input by construction, so there is no restore beat: a 2400-byte value can
    # never become a legal value for this API.
    code, message = _error_code(
        lambda: dp.put_key(
            KvsARN=arn, Key="wide-over", Value=wide_over_value, IfMatch=etag_before_refusal,
        ),
        what=(
            f"PutKey with a {_SHARED_CHAR_COUNT}-character value that encodes to "
            f"{wide_over_bytes} UTF-8 bytes"
        ),
    )
    assert code == "ServiceQuotaExceededException", (
        f"expected ServiceQuotaExceededException for a value of {_SHARED_CHAR_COUNT} characters / "
        f"{wide_over_bytes} UTF-8 bytes, got {code!r}: {message!r}. The accepted twin above had "
        f"the SAME {_SHARED_CHAR_COUNT} characters at only {ascii_bytes} bytes, so the quota must "
        f"be measured in encoded bytes"
    )
    assert message == "Limit exceeded: Maximum size of the value in a key value pair", (
        f"PutKey with a {wide_over_bytes}-byte value returned message {message!r}"
    )

    # ---- Effect absent, via an independent read ----
    nf_code, nf_message = _error_code(
        lambda: dp.get_key(KvsARN=arn, Key="wide-over"),
        what="GetKey on the key whose oversized PutKey was refused",
    )
    assert nf_code == "ResourceNotFoundException", (
        f"a refused PutKey must leave no key behind: GetKey('wide-over') returned "
        f"{nf_code!r}: {nf_message!r}, expected ResourceNotFoundException"
    )
    assert nf_message == "No such Key exists", nf_message

    after_refusal = dp.describe_key_value_store(KvsARN=arn)
    assert after_refusal["ItemCount"] == 2, (
        f"a refused PutKey must not change ItemCount: store reports "
        f"{after_refusal['ItemCount']!r}, expected the 2 items written by the positive controls"
    )
    assert after_refusal["ETag"] == etag_before_refusal, (
        f"a refused PutKey must not bump the store's version: ETag is now "
        f"{after_refusal['ETag']!r}, was {etag_before_refusal!r} before the refused call"
    )

    # ---- Terminal read: both accepted values are intact, read through GetKey ----
    got_ascii = dp.get_key(KvsARN=arn, Key="ascii-twin")
    assert got_ascii["Value"] == ascii_value, (
        f"GetKey('ascii-twin') returned a value of {len(got_ascii['Value'])} characters, "
        f"expected the {_SHARED_CHAR_COUNT}-character ASCII value written earlier"
    )
    got_wide = dp.get_key(KvsARN=arn, Key="wide-under")
    assert got_wide["Value"] == wide_under_value, (
        f"GetKey('wide-under') returned a value of {len(got_wide['Value'])} characters / "
        f"{len(got_wide['Value'].encode('utf-8'))} UTF-8 bytes, expected the "
        f"{_WIDE_UNDER_CHAR_COUNT}-character / {wide_under_bytes}-byte multi-byte value"
    )


# ===== helpers =====
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
    """Create-or-adopt is unnecessary here: the name is unique per run, so the store is always ours."""
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


def _dp_etag(dp, arn):
    return dp.describe_key_value_store(KvsARN=arn)["ETag"]


def _error_code(fn, *, what):
    """Return (code, message) for the ClientError ``fn`` raises.

    RAISES on unexpected success rather than returning a falsy sentinel: a sentinel would let an
    over-permissive target pass ACCEPTANCE off as a mere code mismatch.
    """
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"{what} was ACCEPTED, but real AWS refuses it")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
