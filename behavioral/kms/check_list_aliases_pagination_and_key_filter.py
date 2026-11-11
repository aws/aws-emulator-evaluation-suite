"""list-aliases-pagination-and-key-filter."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "list-aliases-pagination-and-key-filter"
GROUP = 'aliases'
SERVICES = ['kms']


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAliases supports Limit/Marker paging and its KeyId filter narrows to one key's aliases."""
    kms = ctx.client("kms")
    key_id = kms.create_key(
        Description=ctx.unique_name("kms-aliaslist-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    a1 = f"alias/sim2real-behav-aliaslist-a-{uuid.uuid4().hex[:8]}"
    a2 = f"alias/sim2real-behav-aliaslist-b-{uuid.uuid4().hex[:8]}"
    for alias in (a1, a2):
        kms.create_alias(AliasName=alias, TargetKeyId=key_id)
        ctx.on_cleanup(lambda _a=alias: kms.delete_alias(AliasName=_a))

    filtered = _poll_until(
        lambda: kms.list_aliases(KeyId=key_id)["Aliases"],
        lambda al: {a["AliasName"] for a in al} == {a1, a2},
        description="both aliases visible under KeyId filter",
    )
    assert {a["AliasName"] for a in filtered} == {a1, a2}, filtered
    for entry in filtered:
        assert entry["TargetKeyId"] == key_id, entry
        assert entry["AliasArn"].endswith(entry["AliasName"]), entry

    p1 = kms.list_aliases(Limit=1)
    assert len(p1["Aliases"]) == 1, p1["Aliases"]
    assert p1["Truncated"] is True, p1.get("Truncated")
    assert p1["NextMarker"], f"expected a non-empty NextMarker when Truncated, got {p1.get('NextMarker')!r}"

    p2 = kms.list_aliases(Limit=1, Marker=p1["NextMarker"])
    assert len(p2["Aliases"]) == 1, p2["Aliases"]
    assert p2["Aliases"][0]["AliasName"] != p1["Aliases"][0]["AliasName"], "marker must advance"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
