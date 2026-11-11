"""storage-tier-policy-put-then-get."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "storage-tier-policy-put-then-get"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:logs-storage-tier-policy")
def run(ctx) -> None:
    """PutStorageTierPolicy sets the account's archive tier transition rule and
    GetStorageTierPolicy returns the same configuration, in both directions."""
    logs = ctx.client("logs")

    try:
        original = logs.get_storage_tier_policy().get("storageTier", "STANDARD")
    except logs.exceptions.ResourceNotFoundException:
        original = "STANDARD"

    def _restore() -> None:
        logs.put_storage_tier_policy(storageTier=original)

    ctx.on_cleanup(_restore)

    target = "INTELLIGENT_TIERING" if original != "INTELLIGENT_TIERING" else "STANDARD"
    put_resp = logs.put_storage_tier_policy(storageTier=target)
    assert put_resp["storageTier"] == target, put_resp

    get_resp = logs.get_storage_tier_policy()
    assert get_resp["storageTier"] == target, (
        f"GetStorageTierPolicy returned {get_resp['storageTier']!r}, expected {target!r}"
    )

    # Flip to the other value and confirm GetStorageTierPolicy tracks that transition too,
    # proving PutStorageTierPolicy is stateful rather than a fixed/ignored no-op.
    other = "STANDARD" if target == "INTELLIGENT_TIERING" else "INTELLIGENT_TIERING"
    put_resp2 = logs.put_storage_tier_policy(storageTier=other)
    assert put_resp2["storageTier"] == other, put_resp2

    get_resp2 = logs.get_storage_tier_policy()
    assert get_resp2["storageTier"] == other, (
        f"GetStorageTierPolicy returned {get_resp2['storageTier']!r}, expected {other!r}"
    )
    assert get_resp2["lastUpdatedTime"] >= get_resp["lastUpdatedTime"], (
        "lastUpdatedTime did not advance across the second PutStorageTierPolicy call"
    )

    # Restore the account's original setting through the same mutating call the cleanup relies
    # on, and prove — via an independent read — that the restore actually took effect rather than
    # trusting the unasserted ctx.on_cleanup call to be the only evidence of it.
    put_resp3 = logs.put_storage_tier_policy(storageTier=original)
    assert put_resp3["storageTier"] == original, put_resp3

    get_resp3 = logs.get_storage_tier_policy()
    assert get_resp3["storageTier"] == original, (
        f"GetStorageTierPolicy returned {get_resp3['storageTier']!r}, expected {original!r}"
    )
    assert get_resp3["lastUpdatedTime"] >= get_resp2["lastUpdatedTime"], (
        "lastUpdatedTime did not advance across the third PutStorageTierPolicy call"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
