"""is-authorized-permit-policy-allows."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "is-authorized-permit-policy-allows"
GROUP = "data-plane"
SERVICES = ["verifiedpermissions"]


@tags("axis:happy-path", "cap:c7", "plane:control")
def run(ctx) -> None:
    """A static permit policy that matches principal/action/resource yields ALLOW,
    and the policy's ID is returned as the determining policy."""
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

    resp = _retry_until_ready(
        lambda: client.is_authorized(
            policyStoreId=store_id,
            principal={"entityType": "User", "entityId": "alice"},
            action={"actionType": "Action", "actionId": "viewPhoto"},
            resource={"entityType": "Photo", "entityId": "vacation.jpg"},
        )
    )
    assert resp["decision"] == "ALLOW", f"expected decision=ALLOW, got {resp['decision']!r}"
    assert resp["determiningPolicies"] == [{"policyId": policy_id}], (
        f"expected determiningPolicies=[{{'policyId': {policy_id!r}}}], "
        f"got {resp['determiningPolicies']!r}"
    )
    assert resp["errors"] == [], f"expected no evaluation errors, got {resp['errors']!r}"


def _create_policy_store(ctx, client, mode: str = "OFF") -> str:
    store_id = client.create_policy_store(
        validationSettings={"mode": mode},
        tags={"simparity-check": CHECK},
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
