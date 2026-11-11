"""policy-store-alias-resolves-in-is-authorized."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "policy-store-alias-resolves-in-is-authorized"
GROUP = "data-plane"
SERVICES = ["verifiedpermissions"]


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A policy store alias can be used interchangeably with the raw
    policyStoreId in IsAuthorized -- the alias resolves to the same store
    and yields the identical authorization decision."""
    client = ctx.client("verifiedpermissions")
    store_id = _create_policy_store(ctx, client)
    statement = (
        'permit(principal == User::"alice", action == Action::"viewPhoto", '
        'resource == Photo::"vacation.jpg");'
    )
    policy_id = client.create_policy(
        policyStoreId=store_id, definition={"static": {"statement": statement}}
    )["policyId"]
    ctx.on_cleanup(lambda: client.delete_policy(policyStoreId=store_id, policyId=policy_id))

    alias_name = "policy-store-alias/" + ctx.unique_name("sim2real-behav-alias-")
    client.create_policy_store_alias(aliasName=alias_name, policyStoreId=store_id)
    ctx.on_cleanup(
        lambda: client.delete_policy_store_alias(aliasName=alias_name, deletionMode="HardDelete")
    )

    alias_info = client.get_policy_store_alias(aliasName=alias_name)
    assert alias_info["policyStoreId"] == store_id, (
        f"expected alias {alias_name!r} to resolve to policyStoreId {store_id!r}, "
        f"got {alias_info['policyStoreId']!r}"
    )
    assert alias_info["state"] == "Active", (
        f"expected a freshly created alias to be state=Active, got {alias_info['state']!r}"
    )

    by_id = _retry_until_ready(
        lambda: client.is_authorized(
            policyStoreId=store_id,
            principal={"entityType": "User", "entityId": "alice"},
            action={"actionType": "Action", "actionId": "viewPhoto"},
            resource={"entityType": "Photo", "entityId": "vacation.jpg"},
        )
    )
    by_alias = _retry_until_ready(
        lambda: client.is_authorized(
            policyStoreId=alias_name,
            principal={"entityType": "User", "entityId": "alice"},
            action={"actionType": "Action", "actionId": "viewPhoto"},
            resource={"entityType": "Photo", "entityId": "vacation.jpg"},
        )
    )
    assert by_id["decision"] == "ALLOW", f"expected ALLOW via policyStoreId, got {by_id['decision']!r}"
    assert by_alias["decision"] == "ALLOW", (
        f"expected ALLOW via alias {alias_name!r}, got {by_alias['decision']!r}"
    )
    expected = [{"policyId": policy_id}]
    assert by_id["determiningPolicies"] == expected, (
        f"expected determiningPolicies {expected} via policyStoreId, got {by_id['determiningPolicies']}"
    )
    assert by_alias["determiningPolicies"] == expected, (
        f"expected determiningPolicies {expected} via alias, got {by_alias['determiningPolicies']}"
    )


def _create_policy_store(ctx, client, mode: str = "OFF") -> str:
    store_id = client.create_policy_store(
        validationSettings={"mode": mode}, tags={"simparity-check": CHECK}
    )["policyStoreId"]
    ctx.on_cleanup(lambda: client.delete_policy_store(policyStoreId=store_id))
    return store_id


def _retry_until_ready(fn, timeout: float = 30.0, interval: float = 1.5):
    """Newly created policy stores/policies/aliases can lag briefly before
    the authorization data plane sees them; retry on ResourceNotFoundException
    up to timeout seconds before giving up."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.time() + timeout
    last_exc = None
    while time.time() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            last_exc = exc
            time.sleep(interval)
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
