"""batch-get-policy-partial-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-get-policy-partial-not-found"
GROUP = "data-plane"
SERVICES = ["verifiedpermissions"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchGetPolicy returns per-item results/errors rather than failing the
    whole call: an existing policy comes back in `results`, and a reference to
    a nonexistent policy comes back as a POLICY_NOT_FOUND item in `errors`."""
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

    missing_policy_id = "SPEXAMPLEnonexistent00000"
    resp = client.batch_get_policy(
        requests=[
            {"policyStoreId": store_id, "policyId": policy_id},
            {"policyStoreId": store_id, "policyId": missing_policy_id},
        ]
    )
    assert len(resp["results"]) == 1, f"expected exactly 1 result, got {resp['results']}"
    assert resp["results"][0]["policyId"] == policy_id, (
        f"expected result for {policy_id}, got {resp['results'][0]['policyId']}"
    )
    assert resp["results"][0]["policyType"] == "STATIC", (
        f"expected policyType STATIC, got {resp['results'][0]['policyType']}"
    )

    assert len(resp["errors"]) == 1, f"expected exactly 1 error, got {resp['errors']}"
    error_item = resp["errors"][0]
    assert error_item["policyId"] == missing_policy_id, (
        f"expected error for {missing_policy_id}, got {error_item['policyId']}"
    )
    assert error_item["code"] == "POLICY_NOT_FOUND", (
        f"expected POLICY_NOT_FOUND, got {error_item['code']}"
    )


def _create_policy_store(ctx, client, mode: str = "OFF") -> str:
    store_id = client.create_policy_store(
        validationSettings={"mode": mode},
        tags={"simparity-check": CHECK},
    )["policyStoreId"]
    ctx.on_cleanup(lambda: client.delete_policy_store(policyStoreId=store_id))
    return store_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
