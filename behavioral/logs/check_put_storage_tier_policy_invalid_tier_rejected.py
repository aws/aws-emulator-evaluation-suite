"""put-storage-tier-policy-invalid-tier-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-storage-tier-policy-invalid-tier-rejected"
GROUP = "overly-permissive"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:logs-storage-tier-policy")
def run(ctx) -> None:
    """PutStorageTierPolicy rejects an unsupported storage class (only STANDARD and
    INTELLIGENT_TIERING are valid) instead of silently accepting and persisting it."""
    logs = ctx.client("logs")

    original = logs.get_storage_tier_policy()["storageTier"]
    ctx.on_cleanup(lambda: _restore(logs, original))

    # Positive control: a valid tier on the same wiring succeeds, so a later rejection can be
    # attributed to the invalid value rather than to a target that refuses every PutStorageTierPolicy
    # call (e.g. missing permissions).
    control = logs.put_storage_tier_policy(storageTier=original)
    assert control["storageTier"] == original, (
        f"positive control failed: PutStorageTierPolicy(storageTier={original!r}) should succeed, "
        f"got {control}"
    )

    code, message = _client_error(lambda: logs.put_storage_tier_policy(storageTier="GLACIER"))
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for an unsupported storage tier, got {code}"
    )
    assert message == (
        "1 validation error detected: Value at 'storageTier' failed to satisfy constraint: "
        "Member must satisfy enum value set: [INTELLIGENT_TIERING, STANDARD]"
    ), f"unexpected message: {message!r}"

    after = logs.get_storage_tier_policy()["storageTier"]
    assert after == original, (
        f"the account storage tier should be unchanged after a rejected PutStorageTierPolicy "
        f"call, was {original} but is now {after}"
    )


# ===== helpers =====

def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because a target
    that accepts what real AWS refuses must fail loudly, not read as an error mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _restore(logs, original_tier: str) -> None:
    logs.put_storage_tier_policy(storageTier=original_tier)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
