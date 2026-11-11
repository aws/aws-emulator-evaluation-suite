"""is-authorized-default-deny-no-policy."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "is-authorized-default-deny-no-policy"
GROUP = "data-plane"
SERVICES = ["verifiedpermissions"]


@tags("axis:happy-path", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """IsAuthorized on a policy store with no policies returns DENY with no determining policies,
    and the same request returns ALLOW determined by the policy once a permitting policy is added.
    """
    client = ctx.client("verifiedpermissions")
    store_id = _create_policy_store(ctx, client)
    call = lambda: client.is_authorized(
        policyStoreId=store_id,
        principal={"entityType": "User", "entityId": "alice"},
        action={"actionType": "Action", "actionId": "viewPhoto"},
        resource={"entityType": "Photo", "entityId": "vacation.jpg"},
    )

    empty_store = _retry_until_ready(call)
    assert empty_store["decision"] == "DENY", (
        f"expected DENY with zero policies in the store, got {empty_store['decision']}"
    )
    assert empty_store["determiningPolicies"] == [], (
        f"expected no determining policies with an empty store, "
        f"got {empty_store['determiningPolicies']}"
    )

    statement = (
        'permit(principal == User::"alice", action == Action::"viewPhoto", '
        'resource == Photo::"vacation.jpg");'
    )
    policy_id = client.create_policy(
        policyStoreId=store_id, definition={"static": {"statement": statement}}
    )["policyId"]
    ctx.on_cleanup(lambda: client.delete_policy(policyStoreId=store_id, policyId=policy_id))

    with_policy = _retry_until_allow(call)
    assert with_policy["decision"] == "ALLOW", (
        f"expected the identical call to flip to ALLOW once a matching permit "
        f"policy exists, got {with_policy['decision']}"
    )
    assert with_policy["determiningPolicies"] == [{"policyId": policy_id}], (
        f"expected the new policy to be the sole determining policy, "
        f"got {with_policy['determiningPolicies']}"
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


def _retry_until_allow(fn, timeout: float = 30.0, interval: float = 1.5):
    """A freshly created policy can also lag before the authorization data
    plane picks it up: AWS can still answer DENY for a moment
    after CreatePolicy returns. Poll until the decision flips, and raise
    (never return the last DENY) if it never does within budget."""
    import time

    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = fn()
        if last["decision"] == "ALLOW":
            return last
        time.sleep(interval)
    raise AssertionError(
        f"policy never took effect within {timeout}s, last decision: {last!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
