"""store-size-quota-blocks-write-until-space-is-freed."""

from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "store-size-quota-blocks-write-until-space-is-freed"
GROUP = "overly-permissive"
SERVICES = ["cloudfront-keyvaluestore"]

# Filling a ~5 MB store in ~1 KB items takes about a hundred UpdateKeys calls; a truncated fill
# would misreport the limit, so the deadline is declared, not shortened.
_fill_deadline_s = 900.0

# The documented per-request maximum for UpdateKeys ("Maximum key values pairs that you can update
# in a single API request | 50 keys or 3 MB payload"). A fixed, non-adjustable API constant, so
# pinning it is correct.
_BATCH_ITEMS = 50

# Under the documented 1 KB per-value limit. Every key is zero-padded to a FIXED width so that all
# items have an identical byte footprint; the exact-size assertions at the end depend on that.
_VALUE_BYTES = 1000
_KEY_TEMPLATE = "fill-{:06d}"

# A hard structural stop, well past any plausible 5 MB store (400 * 50 * ~1011 B ~= 20 MB). Reaching
# it means the target never enforces a store size limit at all, which fails the check.
_MAX_FILL_BATCHES = 400


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """Filling a key value store until it refuses a write yields a specific refusal that applies
    nothing (independent read), and the identical batch succeeds once space is freed; the limit is
    derived from the store's own reported size, so an unbounded store fails.
    """
    store = _create_ready_store(ctx)
    dp = ctx.client("cloudfront-keyvaluestore")
    arn = store["arn"]

    from botocore.exceptions import ClientError

    value = "v" * _VALUE_BYTES
    written: list[str] = []
    etag = _dp_etag(dp, arn)

    refused_batch: list[dict] | None = None
    refusal_code: str | None = None
    refusal_message = ""

    deadline = time.monotonic() + _fill_deadline_s
    batch_index = 0
    while refused_batch is None:
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"the store accepted {len(written)} items "
                f"({dp.describe_key_value_store(KvsARN=arn)['TotalSizeInBytes']} bytes by its own "
                f"report) without ever refusing a write, and the {_fill_deadline_s}s fill deadline "
                f"elapsed. Real AWS caps an individual key value store, so a target that never "
                f"refuses is over-permissive"
            )
        if batch_index >= _MAX_FILL_BATCHES:
            raise AssertionError(
                f"the store accepted {_MAX_FILL_BATCHES} batches of {_BATCH_ITEMS} items "
                f"({len(written)} items, "
                f"{dp.describe_key_value_store(KvsARN=arn)['TotalSizeInBytes']} bytes by its own "
                f"report) without refusing a write: this target enforces no store size limit"
            )

        first = batch_index * _BATCH_ITEMS
        batch = [
            {"Key": _KEY_TEMPLATE.format(n), "Value": value}
            for n in range(first, first + _BATCH_ITEMS)
        ]
        try:
            resp = dp.update_keys(KvsARN=arn, IfMatch=etag, Puts=batch)
        except ClientError as exc:
            err = exc.response["Error"]
            refusal_code = err.get("Code")
            refusal_message = err.get("Message", "")
            refused_batch = batch
            break
        etag = resp["ETag"]
        written.extend(item["Key"] for item in batch)
        batch_index += 1

    # Beat 1 — the positive control is the fill itself: writes to this store demonstrably work, so
    # the refusal below cannot be "this target refuses every UpdateKeys".
    assert batch_index >= 2, (
        f"the store refused a write after only {batch_index} accepted batch(es) "
        f"({len(written)} items). A capacity refusal that arrives before any meaningful fill is a "
        f"different defect: the refusal was {refusal_code!r}: {refusal_message!r}"
    )

    # Beat 3 — the specific error.
    assert refusal_code == "ServiceQuotaExceededException", (
        f"expected ServiceQuotaExceededException when a write would exceed the store's size "
        f"limit, got {refusal_code!r}: {refusal_message!r} after {len(written)} accepted items"
    )
    assert refusal_message == "Limit exceeded: Maximum size of an individual key value store", (
        f"the store-size refusal returned message {refusal_message!r}"
    )

    at_refusal = dp.describe_key_value_store(KvsARN=arn)
    size_at_refusal = at_refusal["TotalSizeInBytes"]
    items_at_refusal = at_refusal["ItemCount"]

    # Beat 4 — the effect is absent, three ways.
    assert items_at_refusal == len(written), (
        f"the refused batch must apply nothing: the store reports {items_at_refusal} items but "
        f"only {len(written)} were accepted, so {items_at_refusal - len(written)} item(s) from the "
        f"refused batch of {_BATCH_ITEMS} landed"
    )
    assert at_refusal["ETag"] == etag, (
        f"a refused batch must not bump the store's version: ETag is now "
        f"{at_refusal['ETag']!r}, was {etag!r} after the last accepted batch"
    )
    probe_key = refused_batch[0]["Key"]
    nf_code, nf_message = _error_code(
        lambda: dp.get_key(KvsARN=arn, Key=probe_key),
        what=f"GetKey({probe_key!r}) from the batch the store refused",
    )
    assert nf_code == "ResourceNotFoundException", (
        f"no key from the refused batch may exist: GetKey({probe_key!r}) returned "
        f"{nf_code!r}: {nf_message!r}, expected ResourceNotFoundException"
    )
    assert nf_message == "No such Key exists", nf_message

    # Beat 5 — restore: free exactly one batch's worth of identically-shaped items.
    freed_keys = written[:_BATCH_ITEMS]
    after_delete = dp.update_keys(
        KvsARN=arn, IfMatch=at_refusal["ETag"],
        Deletes=[{"Key": k} for k in freed_keys],
    )
    assert after_delete["ItemCount"] == items_at_refusal - _BATCH_ITEMS, (
        f"deleting {_BATCH_ITEMS} keys must leave {items_at_refusal - _BATCH_ITEMS} items; the "
        f"store reports {after_delete['ItemCount']}"
    )
    assert after_delete["TotalSizeInBytes"] < size_at_refusal, (
        f"deleting {_BATCH_ITEMS} items must reduce TotalSizeInBytes below {size_at_refusal}; it "
        f"is {after_delete['TotalSizeInBytes']}"
    )

    # Beat 6 — the IDENTICAL call now succeeds. Every item in this batch has the same key byte
    # length and the same value byte length as every item just deleted, so exactly enough room was
    # freed. A target that refused for any reason other than capacity fails here.
    retried = dp.update_keys(KvsARN=arn, IfMatch=after_delete["ETag"], Puts=refused_batch)
    assert retried["ItemCount"] == items_at_refusal, (
        f"after freeing {_BATCH_ITEMS} identically-sized items the previously-refused batch must "
        f"apply in full, restoring {items_at_refusal} items; the store reports "
        f"{retried['ItemCount']}"
    )
    assert retried["TotalSizeInBytes"] == size_at_refusal, (
        f"swapping {_BATCH_ITEMS} items for {_BATCH_ITEMS} items of identical key-byte and "
        f"value-byte length must restore TotalSizeInBytes to exactly {size_at_refusal}; it is "
        f"{retried['TotalSizeInBytes']}"
    )

    # Terminal read: an independent operation at the destination proves the retried write landed,
    # and that a freed key is genuinely gone.
    got = dp.get_key(KvsARN=arn, Key=probe_key)
    assert got["Value"] == value, (
        f"GetKey({probe_key!r}) returned a {len(got['Value'])}-character value after the retry "
        f"succeeded, expected the {_VALUE_BYTES}-byte value that batch carried"
    )
    gone_code, gone_message = _error_code(
        lambda: dp.get_key(KvsARN=arn, Key=freed_keys[0]),
        what=f"GetKey({freed_keys[0]!r}) on a key deleted to make room",
    )
    assert gone_code == "ResourceNotFoundException", (
        f"a key deleted to free space must be gone: GetKey({freed_keys[0]!r}) returned "
        f"{gone_code!r}: {gone_message!r}, expected ResourceNotFoundException"
    )
    assert gone_message == "No such Key exists", gone_message


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
    """The name is unique per run, so the store is always this check's own."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-kvs-")
    resp = cf.create_key_value_store(Name=name, Comment="sim2real behavioral check")
    arn = resp["KeyValueStore"]["ARN"]

    def _cleanup() -> None:
        # Registered before the READY poll: a store that never becomes READY still exists and still
        # has to be deleted, even while it holds thousands of keys.
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
