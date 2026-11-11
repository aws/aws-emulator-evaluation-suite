"""put-storage-tier-policy-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-storage-tier-policy-lifecycle"
GROUP = 'log-group-lifecycle'
SERVICES = ['logs']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:logs-storage-tier-policy")
def run(ctx) -> None:
    """PutStorageTierPolicy switches the account's storage tier to INTELLIGENT_TIERING and back to
    STANDARD, and GetStorageTierPolicy reflects each change with a non-decreasing lastUpdatedTime.
    """
    svc = ctx.client("logs")

    if not hasattr(svc, "get_storage_tier_policy") or not hasattr(svc, "put_storage_tier_policy"):
        raise AssertionError("CloudWatch Logs client has no Get/PutStorageTierPolicy operation")

    original = svc.get_storage_tier_policy().get("storageTier", "STANDARD")
    ctx.on_cleanup(lambda _t=original: svc.put_storage_tier_policy(storageTier=_t))

    resp = svc.put_storage_tier_policy(storageTier="INTELLIGENT_TIERING")
    assert resp["storageTier"] == "INTELLIGENT_TIERING", (
        f"PutStorageTierPolicy echo: expected INTELLIGENT_TIERING, got {resp.get('storageTier')!r}"
    )
    got = svc.get_storage_tier_policy()
    assert got["storageTier"] == "INTELLIGENT_TIERING", (
        f"expected INTELLIGENT_TIERING, got {got.get('storageTier')!r}"
    )
    assert isinstance(got.get("lastUpdatedTime"), int), (
        f"expected an integer lastUpdatedTime, got {got.get('lastUpdatedTime')!r}"
    )

    resp2 = svc.put_storage_tier_policy(storageTier="STANDARD")
    assert resp2["storageTier"] == "STANDARD", (
        f"PutStorageTierPolicy echo: expected STANDARD, got {resp2.get('storageTier')!r}"
    )
    got2 = svc.get_storage_tier_policy()
    assert got2["storageTier"] == "STANDARD", f"expected STANDARD, got {got2.get('storageTier')!r}"
    assert got2["lastUpdatedTime"] >= got["lastUpdatedTime"], (
        f"lastUpdatedTime went backwards across the second PutStorageTierPolicy: "
        f"{got.get('lastUpdatedTime')!r} -> {got2.get('lastUpdatedTime')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
