"""is-authorized-when-clause-context-condition."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "is-authorized-when-clause-context-condition"
GROUP = "data-plane"
SERVICES = ["verifiedpermissions"]


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A policy with a `when` clause referencing context.mfa only permits the
    request when the supplied boolean context attribute is true."""
    client = ctx.client("verifiedpermissions")
    store_id = _create_policy_store(ctx, client)
    statement = (
        'permit(principal == User::"alice", action == Action::"viewPhoto", '
        'resource == Photo::"vacation.jpg") when { context.mfa == true };'
    )
    policy_id = client.create_policy(
        policyStoreId=store_id, definition={"static": {"statement": statement}}
    )["policyId"]
    ctx.on_cleanup(lambda: client.delete_policy(policyStoreId=store_id, policyId=policy_id))

    base_kwargs = dict(
        policyStoreId=store_id,
        principal={"entityType": "User", "entityId": "alice"},
        action={"actionType": "Action", "actionId": "viewPhoto"},
        resource={"entityType": "Photo", "entityId": "vacation.jpg"},
    )

    with_mfa = _retry_until_ready(
        lambda: client.is_authorized(
            context={"contextMap": {"mfa": {"boolean": True}}}, **base_kwargs
        )
    )
    assert with_mfa["decision"] == "ALLOW", (
        f"expected ALLOW when context.mfa=true satisfies the when clause, "
        f"got {with_mfa['decision']!r}"
    )
    assert with_mfa["determiningPolicies"] == [{"policyId": policy_id}], (
        f"expected policy {policy_id!r} as sole determining policy, "
        f"got {with_mfa['determiningPolicies']!r}"
    )
    assert with_mfa["errors"] == [], f"expected no evaluation errors, got {with_mfa['errors']!r}"

    without_mfa = client.is_authorized(
        context={"contextMap": {"mfa": {"boolean": False}}}, **base_kwargs
    )
    assert without_mfa["decision"] == "DENY", (
        f"expected DENY when context.mfa=false fails the when clause, "
        f"got {without_mfa['decision']!r}"
    )
    assert without_mfa["determiningPolicies"] == [], (
        f"expected no determining policies on implicit deny, "
        f"got {without_mfa['determiningPolicies']!r}"
    )
    assert without_mfa["errors"] == [], (
        f"expected no evaluation errors, got {without_mfa['errors']!r}"
    )


def _create_policy_store(ctx, client, mode: str = "OFF") -> str:
    store_id = client.create_policy_store(
        validationSettings={"mode": mode}, tags={"sim2real-check": CHECK}
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
