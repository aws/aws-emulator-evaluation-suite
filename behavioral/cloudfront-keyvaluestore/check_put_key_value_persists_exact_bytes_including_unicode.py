"""put-key-value-persists-exact-bytes-including-unicode."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-key-value-persists-exact-bytes-including-unicode"
GROUP = "data-plane"
SERVICES = ["cloudfront-keyvaluestore"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A multi-byte UTF-8 value round-trips exactly through GetKey, and
    TotalSizeInBytes accounts for encoded size (UTF-16 code units), not characters --
    a store that counts characters would under-report size for supplementary-plane values."""
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]

    ascii_value = "0123456789"  # 10 chars == 10 bytes
    multibyte_value = "\U0001f30d" * 10  # 10 chars, 40 UTF-8 bytes, 20 UTF-16 code units
    assert len(ascii_value) == len(multibyte_value) == 10, (
        f"test fixture invariant broken: expected both values to be 10 Python characters, "
        f"got ascii={len(ascii_value)} multibyte={len(multibyte_value)}"
    )
    assert len(multibyte_value.encode("utf-8")) == 40, (
        f"test fixture invariant broken: expected the multibyte value to encode to 40 UTF-8 "
        f"bytes, got {len(multibyte_value.encode('utf-8'))}"
    )

    before = dp.describe_key_value_store(KvsARN=arn)
    ascii_resp = dp.put_key(KvsARN=arn, Key="ascii-key1", Value=ascii_value, IfMatch=before["ETag"])
    ascii_delta = ascii_resp["TotalSizeInBytes"] - before["TotalSizeInBytes"]

    multibyte_resp = dp.put_key(KvsARN=arn, Key="wide-key-1", Value=multibyte_value, IfMatch=ascii_resp["ETag"])
    multibyte_delta = multibyte_resp["TotalSizeInBytes"] - ascii_resp["TotalSizeInBytes"]

    # Both keys are 10 ASCII characters ("ascii-key1" and "wide-key-1"), so only the
    # value differs between the two deltas. TotalSizeInBytes counts UTF-16 code units:
    # the multi-byte value is 20 units against the ascii value's 10, so the deltas
    # differ by exactly 10. A store that counts characters would report equal deltas.
    assert multibyte_delta - ascii_delta == 10, (
        f"expected the multi-byte value's size delta ({multibyte_delta}) to exceed "
        f"the ascii value's delta ({ascii_delta}) by exactly 10 (20 UTF-16 code units "
        f"minus 10); equal deltas would mean the store is counting characters"
    )

    got = dp.get_key(KvsARN=arn, Key="wide-key-1")
    assert got["Value"] == multibyte_value, (
        f"GetKey after PutKey expected the exact multibyte value back, got {got['Value']!r}"
    )


def _wait_for_store_ready(ctx, name, timeout_s=180.0, interval_s=3.0):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        d = cf.describe_key_value_store(Name=name)
        status = d["KeyValueStore"]["Status"].upper()
        if status == "READY":
            return
        assert "FAIL" not in status, f"store entered a failure status: {status}"
        time.sleep(interval_s)
    raise AssertionError(f"store never reached READY within timeout, last status={status}")


def _create_ready_store(ctx):
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-kvs-")
    resp = cf.create_key_value_store(
        Name=name,
        Comment="sim2real behavioral check",
        Tags={"Items": [{"Key": "sim2real", "Value": CHECK}]},
    )
    arn = resp["KeyValueStore"]["ARN"]

    def _cleanup() -> None:
        d = cf.describe_key_value_store(Name=name)
        cf.delete_key_value_store(Name=name, IfMatch=d["ETag"])

    ctx.on_cleanup(_cleanup)
    _wait_for_store_ready(ctx, name)
    return {"name": name, "arn": arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
