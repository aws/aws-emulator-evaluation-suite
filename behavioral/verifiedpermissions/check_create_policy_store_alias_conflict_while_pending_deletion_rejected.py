"""create-policy-store-alias-conflict-while-pending-deletion-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-policy-store-alias-conflict-while-pending-deletion-rejected"
GROUP = "overly-permissive"
SERVICES = ["verifiedpermissions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePolicyStoreAlias on an alias in PendingDeletion fails with the exact ConflictException
    and the alias still points at the original store; once the alias is hard-deleted, the name
    resolves Active to the second store."""
    client = ctx.client("verifiedpermissions")
    store_a = _create_policy_store(ctx, client)
    store_b = _create_policy_store(ctx, client)
    alias_name = "policy-store-alias/" + ctx.unique_name("sim2real-behav-alias-")

    client.create_policy_store_alias(aliasName=alias_name, policyStoreId=store_a)
    client.delete_policy_store_alias(aliasName=alias_name)  # soft delete -> PendingDeletion

    hard_deleted = {"done": False}
    ctx.on_cleanup(
        lambda: None
        if hard_deleted["done"]
        else client.delete_policy_store_alias(aliasName=alias_name, deletionMode="HardDelete")
    )

    error = _error(
        lambda: client.create_policy_store_alias(aliasName=alias_name, policyStoreId=store_b)
    )
    expected_error = ("ConflictException", "Conflict occurred during the processing of this request")
    assert error == expected_error, f"expected {expected_error!r}, got {error!r}"
    # effect absent: alias still points at store A (not B) and is still pending deletion.
    still_pending = client.get_policy_store_alias(aliasName=alias_name)
    assert still_pending["policyStoreId"] == store_a, (
        f"expected alias to still resolve to store_a={store_a!r}, "
        f"got {still_pending['policyStoreId']!r}"
    )
    assert still_pending["state"] == "PendingDeletion", (
        f"expected state PendingDeletion, got {still_pending['state']!r}"
    )

    client.delete_policy_store_alias(aliasName=alias_name, deletionMode="HardDelete")
    hard_deleted["done"] = True

    # positive control: name is free again after hard delete, and now resolves to B.
    client.create_policy_store_alias(aliasName=alias_name, policyStoreId=store_b)
    ctx.on_cleanup(
        lambda: client.delete_policy_store_alias(aliasName=alias_name, deletionMode="HardDelete")
    )
    resolved = client.get_policy_store_alias(aliasName=alias_name)
    assert resolved["policyStoreId"] == store_b, (
        f"expected alias freed and resolved to store_b={store_b!r}, "
        f"got {resolved['policyStoreId']!r}"
    )
    assert resolved["state"] == "Active", f"expected state Active, got {resolved['state']!r}"


def _create_policy_store(ctx, client, mode: str = "OFF") -> str:
    store_id = client.create_policy_store(validationSettings={"mode": mode})["policyStoreId"]
    ctx.on_cleanup(lambda: client.delete_policy_store(policyStoreId=store_id))
    return store_id


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
