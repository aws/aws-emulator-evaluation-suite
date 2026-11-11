"""storage-tier-policy-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "storage-tier-policy-lifecycle"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:logs-storage-tier-policy")
def run(ctx) -> None:
    """PutStorageTierPolicy sets the account-level storage tier policy and the
    new value is retrievable via GetStorageTierPolicy, reflecting the
    configured tier transition."""
    logs = ctx.client("logs")

    original = logs.get_storage_tier_policy()
    original_tier = original.get("storageTier", "STANDARD")

    # Ensure we always leave the account in its original state.
    ctx.on_cleanup(lambda: logs.put_storage_tier_policy(storageTier=original_tier))

    target_tier = "INTELLIGENT_TIERING" if original_tier != "INTELLIGENT_TIERING" else "STANDARD"

    put_resp = logs.put_storage_tier_policy(storageTier=target_tier)
    assert put_resp["storageTier"] == target_tier, (
        f"PutStorageTierPolicy({target_tier}) returned storageTier={put_resp.get('storageTier')!r}"
    )
    assert isinstance(put_resp["lastUpdatedTime"], int) and put_resp["lastUpdatedTime"] > 0, (
        f"expected a positive lastUpdatedTime after Put, got {put_resp.get('lastUpdatedTime')!r}"
    )

    fetched = logs.get_storage_tier_policy()
    assert fetched["storageTier"] == target_tier, (
        f"expected storage tier {target_tier} after Put, GetStorageTierPolicy returned {fetched}"
    )

    # Transition back and confirm the state machine reflects the reverse
    # transition too (STANDARD <-> INTELLIGENT_TIERING), and that the second
    # write is a genuine new mutation rather than a no-op replay of the first.
    back_resp = logs.put_storage_tier_policy(storageTier=original_tier)
    assert back_resp["storageTier"] == original_tier, (
        f"PutStorageTierPolicy({original_tier}) returned storageTier={back_resp.get('storageTier')!r}"
    )
    assert back_resp["lastUpdatedTime"] >= put_resp["lastUpdatedTime"], (
        f"lastUpdatedTime went backwards across the second PutStorageTierPolicy call: "
        f"{put_resp['lastUpdatedTime']} -> {back_resp['lastUpdatedTime']}"
    )

    fetched_back = logs.get_storage_tier_policy()
    assert fetched_back["storageTier"] == original_tier, (
        f"expected storage tier {original_tier} after reverse Put, GetStorageTierPolicy returned {fetched_back}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
