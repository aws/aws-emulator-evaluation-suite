"""delete-policy-by-name-removes-policy."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-policy-by-name-removes-policy"
GROUP = "state"
SERVICES = ["verifiedpermissions"]

_NOT_FOUND = ("ResourceNotFoundException", "Resource not found")


def expect_error(fn, code: str, message: str):
    """Call fn(); assert it raises exactly (code, message) and return the response; raise on success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        actual = (err.get("Code"), err.get("Message"))
        assert actual == (code, message), f"expected {(code, message)!r}, got {actual!r}"
        return exc.response
    raise AssertionError(f"expected ({code!r}, {message!r}) but the call succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeletePolicy accepts a policy's name/ handle in place of its minted id: once deleted
    that way, GetPolicy on the old id fails with ResourceNotFoundException naming it, and
    ListPolicies on the store returns no policies."""
    client = ctx.client("verifiedpermissions")

    store_id = client.create_policy_store(validationSettings={"mode": "OFF"})["policyStoreId"]
    ctx.on_cleanup(lambda: client.delete_policy_store(policyStoreId=store_id))

    policy_name = f"name/{ctx.unique_name('sim2real-policy')}"
    created = client.create_policy(
        policyStoreId=store_id,
        name=policy_name,
        definition={"static": {"statement": "permit(principal, action, resource);"}},
    )
    policy_id = created["policyId"]
    ctx.on_cleanup(_teardown(
        lambda: client.delete_policy(policyStoreId=store_id, policyId=policy_id),
        "ResourceNotFoundException",
    ))

    # Positive control: the minted id is live right up to the delete-by-name below.
    before = client.get_policy(policyStoreId=store_id, policyId=policy_id)
    assert before["policyId"] == policy_id, (
        f"GetPolicy by id before the delete returned policyId {before['policyId']!r}, "
        f"expected {policy_id!r}"
    )

    client.delete_policy(policyStoreId=store_id, policyId=policy_name)

    response = expect_error(
        lambda: client.get_policy(policyStoreId=store_id, policyId=policy_id), *_NOT_FOUND
    )
    assert response.get("resourceId") == policy_id, (
        f"ResourceNotFoundException named resourceId {response.get('resourceId')!r}, "
        f"expected the deleted policy's id {policy_id!r}"
    )
    assert response.get("resourceType") == "POLICY", (
        f"ResourceNotFoundException named resourceType {response.get('resourceType')!r}, "
        f"expected 'POLICY'"
    )

    remaining = client.list_policies(policyStoreId=store_id)["policies"]
    assert remaining == [], (
        f"ListPolicies after the name-addressed delete returned {remaining!r}, expected none"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
