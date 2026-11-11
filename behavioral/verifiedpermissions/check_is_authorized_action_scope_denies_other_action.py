"""is-authorized-action-scope-denies-other-action."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "is-authorized-action-scope-denies-other-action"
GROUP = "data-plane"
SERVICES = ["verifiedpermissions"]


@tags("axis:happy-path", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A permit policy scoped to one action does not authorize a different
    action against the same principal/resource pair (default-deny semantics
    apply per-action, not per-resource)."""
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

    scoped_action = _retry_until_ready(
        lambda: client.is_authorized(
            policyStoreId=store_id,
            principal={"entityType": "User", "entityId": "alice"},
            action={"actionType": "Action", "actionId": "viewPhoto"},
            resource={"entityType": "Photo", "entityId": "vacation.jpg"},
        )
    )
    assert scoped_action["decision"] == "ALLOW", (
        f"expected ALLOW for the scoped viewPhoto action, got {scoped_action['decision']}"
    )

    other_action = client.is_authorized(
        policyStoreId=store_id,
        principal={"entityType": "User", "entityId": "alice"},
        action={"actionType": "Action", "actionId": "deletePhoto"},
        resource={"entityType": "Photo", "entityId": "vacation.jpg"},
    )
    assert other_action["decision"] == "DENY", (
        f"expected DENY for deletePhoto (policy only permits viewPhoto), "
        f"got {other_action['decision']}"
    )
    assert other_action["determiningPolicies"] == [], (
        f"expected no determining policies for the implicit deny, "
        f"got {other_action['determiningPolicies']}"
    )


def _create_policy_store(ctx, client, mode: str = "OFF") -> str:
    store_id = client.create_policy_store(validationSettings={"mode": mode})["policyStoreId"]
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
