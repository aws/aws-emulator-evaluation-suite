"""delete-policy-store-alias-soft-delete-transitions-to-pending-deletion."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-policy-store-alias-soft-delete-transitions-to-pending-deletion"
GROUP = "state"
SERVICES = ["verifiedpermissions"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeletePolicyStoreAlias without deletionMode moves an Active alias to PendingDeletion in both GetPolicyStoreAlias
    and ListPolicyStoreAliases; after HardDelete, GetPolicyStoreAlias fails with ResourceNotFoundException "Resource not
    found" naming the alias, and the name is reusable at once."""
    client = ctx.client("verifiedpermissions")
    store_id = _create_policy_store(ctx, client)
    alias_name = "policy-store-alias/" + ctx.unique_name("sim2real-behav-alias-")
    client.create_policy_store_alias(aliasName=alias_name, policyStoreId=store_id)
    hard_deleted = {"done": False}
    ctx.on_cleanup(
        lambda: None
        if hard_deleted["done"]
        else client.delete_policy_store_alias(aliasName=alias_name, deletionMode="HardDelete")
    )

    active = client.get_policy_store_alias(aliasName=alias_name)["state"]
    assert active == "Active", f"expected newly created alias state Active, got {active!r}"

    client.delete_policy_store_alias(aliasName=alias_name)  # default = SoftDelete

    state = _poll_until(
        lambda: client.get_policy_store_alias(aliasName=alias_name)["state"],
        lambda s: s == "PendingDeletion",
        timeout_s=30.0,
    )
    assert state == "PendingDeletion", f"expected soft-deleted alias state PendingDeletion, got {state!r}"

    matches = [
        item
        for item in client.list_policy_store_aliases(
            filter={"policyStoreId": store_id}
        ).get("policyStoreAliases", [])
        if item["aliasName"] == alias_name
    ]
    assert len(matches) == 1, f"expected exactly 1 alias named {alias_name!r} in list, found {len(matches)}"
    assert matches[0]["state"] == "PendingDeletion", (
        f"expected list entry to reflect PendingDeletion, got {matches[0]['state']!r}"
    )

    client.delete_policy_store_alias(aliasName=alias_name, deletionMode="HardDelete")
    hard_deleted["done"] = True

    err = _error(lambda: client.get_policy_store_alias(aliasName=alias_name))
    assert err["Error"]["Code"] == "ResourceNotFoundException", (
        f"expected GetPolicyStoreAlias on the hard-deleted alias to report ResourceNotFoundException, got {err['Error']['Code']!r}"
    )
    assert err["Error"]["Message"] == "Resource not found", (
        f"unexpected message={err['Error']['Message']!r}"
    )
    assert (err.get("resourceType"), err.get("resourceId")) == ("POLICY_STORE_ALIAS", alias_name.removeprefix("policy-store-alias/")), (
        f"unexpected resource={(err.get('resourceType'), err.get('resourceId'))!r}"
    )

    # HardDelete is idempotent: repeating it on an already-gone alias
    # succeeds rather than raising not-found.
    client.delete_policy_store_alias(aliasName=alias_name, deletionMode="HardDelete")

    # the freed name is reusable immediately.
    client.create_policy_store_alias(aliasName=alias_name, policyStoreId=store_id)
    ctx.on_cleanup(
        lambda: client.delete_policy_store_alias(aliasName=alias_name, deletionMode="HardDelete")
    )
    reused = client.get_policy_store_alias(aliasName=alias_name)
    assert reused["state"] == "Active", (
        f"expected reused alias name to resolve Active, got {reused['state']!r}"
    )
    assert reused["policyStoreId"] == store_id, (
        f"expected reused alias to point at {store_id!r}, got {reused['policyStoreId']!r}"
    )


def _create_policy_store(ctx, client, mode: str = "OFF") -> str:
    store_id = client.create_policy_store(validationSettings={"mode": mode})["policyStoreId"]
    ctx.on_cleanup(lambda: client.delete_policy_store(policyStoreId=store_id))
    return store_id


def _error(fn):
    """Call fn(); return the botocore error response. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value) and time.monotonic() < deadline:
        time.sleep(interval_s)
        value = probe()
    if not predicate(value):
        raise AssertionError(f"condition never satisfied, last value={value!r}")
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
