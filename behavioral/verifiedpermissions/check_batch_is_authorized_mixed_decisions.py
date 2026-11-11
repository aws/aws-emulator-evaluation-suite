"""batch-is-authorized-mixed-decisions."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-is-authorized-mixed-decisions"
GROUP = "data-plane"
SERVICES = ["verifiedpermissions"]


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchIsAuthorized evaluates each request independently against the same
    policy set and returns per-request decisions in request order."""
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

    requests = [
        {
            "principal": {"entityType": "User", "entityId": "alice"},
            "action": {"actionType": "Action", "actionId": "viewPhoto"},
            "resource": {"entityType": "Photo", "entityId": "vacation.jpg"},
        },
        {
            "principal": {"entityType": "User", "entityId": "bob"},
            "action": {"actionType": "Action", "actionId": "viewPhoto"},
            "resource": {"entityType": "Photo", "entityId": "vacation.jpg"},
        },
    ]
    resp = _retry_until_ready(
        lambda: client.batch_is_authorized(policyStoreId=store_id, requests=requests)
    )
    results = resp["results"]
    assert len(results) == 2, f"expected 2 results for 2 requests, got {len(results)}"
    assert results[0]["decision"] == "ALLOW", f"expected alice ALLOW, got {results[0]['decision']}"
    assert results[0]["determiningPolicies"] == [{"policyId": policy_id}], (
        f"expected [{policy_id}] as determining policy, got {results[0]['determiningPolicies']}"
    )
    assert results[0]["errors"] == [], f"expected no evaluation errors, got {results[0]['errors']}"
    assert results[0]["request"] == requests[0], (
        f"expected result[0] to echo request[0] {requests[0]}, got {results[0]['request']}"
    )
    assert results[1]["decision"] == "DENY", f"expected bob DENY, got {results[1]['decision']}"
    assert results[1]["determiningPolicies"] == [], (
        f"expected no determining policies for a default-deny, got {results[1]['determiningPolicies']}"
    )
    assert results[1]["errors"] == [], f"expected no evaluation errors, got {results[1]['errors']}"
    assert results[1]["request"] == requests[1], (
        f"expected result[1] to echo request[1] {requests[1]}, got {results[1]['request']}"
    )


def _create_policy_store(ctx, client, mode: str = "OFF") -> str:
    store_id = client.create_policy_store(
        validationSettings={"mode": mode}, tags={"sim2real": "batch-is-authorized-mixed-decisions"}
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
