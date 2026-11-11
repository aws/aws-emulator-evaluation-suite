"""get-storage-tier-policy-reflects-put-storage-tier-policy."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-storage-tier-policy-reflects-put-storage-tier-policy"
GROUP = "error-semantics"
SERVICES = ["logs"]

_VALID_TIERS = ("STANDARD", "INTELLIGENT_TIERING")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:logs-storage-tier-policy")
def run(ctx) -> None:
    """GetStorageTierPolicy reflects a PutStorageTierPolicy change immediately,
    rather than returning a stale or default value."""
    logs = ctx.client("logs")

    original_tier = logs.get_storage_tier_policy()["storageTier"]
    assert original_tier in _VALID_TIERS, (
        f"expected GetStorageTierPolicy's initial storageTier to be one of {_VALID_TIERS}, "
        f"got {original_tier!r}"
    )

    target_tier = "INTELLIGENT_TIERING" if original_tier == "STANDARD" else "STANDARD"
    ctx.on_cleanup(lambda: logs.put_storage_tier_policy(storageTier=original_tier))

    logs.put_storage_tier_policy(storageTier=target_tier)
    updated = logs.get_storage_tier_policy()["storageTier"]
    assert updated == target_tier, (
        f"expected GetStorageTierPolicy to reflect the new tier {target_tier!r} immediately, got {updated!r}"
    )

    # Switch back explicitly (in addition to the cleanup safety net) and re-verify,
    # to establish this is a genuine two-way state transition, not a one-shot fluke.
    logs.put_storage_tier_policy(storageTier=original_tier)
    restored = logs.get_storage_tier_policy()["storageTier"]
    assert restored == original_tier, (
        f"expected GetStorageTierPolicy to reflect the restored tier {original_tier!r} "
        f"immediately, got {restored!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
