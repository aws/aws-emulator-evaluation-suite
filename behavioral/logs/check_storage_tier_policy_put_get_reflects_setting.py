"""storage-tier-policy-put-get-reflects-setting."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "storage-tier-policy-put-get-reflects-setting"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:logs-storage-tier-policy")
def run(ctx) -> None:
    """PutStorageTierPolicy sets the account-wide storage tier and GetStorageTierPolicy reflects it."""
    logs = ctx.client("logs")

    # GetStorageTierPolicy is an account-wide read with an implicit default and never raises
    # ResourceNotFoundException on real AWS.
    original = logs.get_storage_tier_policy()["storageTier"]
    other_tier = "INTELLIGENT_TIERING" if original != "INTELLIGENT_TIERING" else "STANDARD"

    def _restore():
        logs.put_storage_tier_policy(storageTier=original)

    ctx.on_cleanup(_restore)

    put_resp = logs.put_storage_tier_policy(storageTier=other_tier)
    assert put_resp["storageTier"] == other_tier, (
        f"PutStorageTierPolicy returned storageTier={put_resp.get('storageTier')!r}, "
        f"expected {other_tier!r}"
    )
    get_resp = logs.get_storage_tier_policy()
    assert get_resp["storageTier"] == other_tier, (
        f"GetStorageTierPolicy returned storageTier={get_resp.get('storageTier')!r} "
        f"immediately after Put set it to {other_tier!r}"
    )
    assert isinstance(get_resp["lastUpdatedTime"], int) and get_resp["lastUpdatedTime"] > 0, (
        f"expected a positive integer lastUpdatedTime, got {get_resp.get('lastUpdatedTime')!r}"
    )

    # Flip back and confirm the second transition is also reflected, proving this is a live
    # toggle and not a one-shot / write-once setting.
    put_back = logs.put_storage_tier_policy(storageTier=original)
    assert put_back["storageTier"] == original, (
        f"PutStorageTierPolicy (restore) returned storageTier={put_back.get('storageTier')!r}, "
        f"expected original {original!r}"
    )
    get_back = logs.get_storage_tier_policy()
    assert get_back["storageTier"] == original, (
        f"GetStorageTierPolicy returned storageTier={get_back.get('storageTier')!r} "
        f"after restoring to {original!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
