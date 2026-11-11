"""is-authorized-forbid-overrides-permit."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "is-authorized-forbid-overrides-permit"
GROUP = "data-plane"
SERVICES = ["verifiedpermissions"]


@tags("axis:happy-path", "cap:c7", "plane:control")
def run(ctx) -> None:
    """When a permit policy and a forbid policy both match the same request,
    Cedar's explicit-deny-overrides semantics make the forbid policy win, and
    it alone appears as the determining policy."""
    client = ctx.client("verifiedpermissions")
    store_id = _create_policy_store(ctx, client)
    triple = (
        'principal == User::"alice", action == Action::"viewPhoto", '
        'resource == Photo::"vacation.jpg"'
    )
    permit_id = client.create_policy(
        policyStoreId=store_id,
        definition={"static": {"statement": f"permit({triple});"}},
    )["policyId"]
    ctx.on_cleanup(lambda: client.delete_policy(policyStoreId=store_id, policyId=permit_id))
    forbid_id = client.create_policy(
        policyStoreId=store_id,
        definition={"static": {"statement": f"forbid({triple});"}},
    )["policyId"]
    ctx.on_cleanup(lambda: client.delete_policy(policyStoreId=store_id, policyId=forbid_id))

    resp = _retry_until_ready(
        lambda: client.is_authorized(
            policyStoreId=store_id,
            principal={"entityType": "User", "entityId": "alice"},
            action={"actionType": "Action", "actionId": "viewPhoto"},
            resource={"entityType": "Photo", "entityId": "vacation.jpg"},
        )
    )
    assert resp["decision"] == "DENY", f"expected DENY, got {resp['decision']}"
    assert resp["determiningPolicies"] == [{"policyId": forbid_id}], (
        f"expected only the forbid policy {forbid_id!r} as determining, "
        f"got {resp['determiningPolicies']!r}"
    )


def _create_policy_store(ctx, client, mode: str = "OFF") -> str:
    store_id = client.create_policy_store(
        validationSettings={"mode": mode},
        tags={"sim2real": "true"},
    )["policyStoreId"]
    ctx.on_cleanup(lambda: client.delete_policy_store(policyStoreId=store_id))
    return store_id


def _retry_until_ready(fn, timeout: float = 30.0, interval: float = 1.5):
    """Newly created policy stores/policies can lag briefly before the
    authorization data plane sees them; retry on ResourceNotFoundException
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
