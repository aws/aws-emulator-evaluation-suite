"""put-schema-strict-mode-validates-policy-actions."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-schema-strict-mode-validates-policy-actions"
GROUP = "overly-permissive"
SERVICES = ["verifiedpermissions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """In STRICT validation mode with a schema, CreatePolicy naming an undeclared action fails with
    ValidationException "Invalid input" and the exact fieldList and creates no policy, while the same
    policy with a declared action is created and read back."""
    client = ctx.client("verifiedpermissions")
    store_id = _create_policy_store(ctx, client)
    schema = {
        "PhotoApp": {
            "entityTypes": {"User": {}, "Photo": {}},
            "actions": {
                "viewPhoto": {
                    "appliesTo": {
                        "principalTypes": ["User"],
                        "resourceTypes": ["Photo"],
                    }
                }
            },
        }
    }
    import json

    client.put_schema(policyStoreId=store_id, definition={"cedarJson": json.dumps(schema)})
    client.update_policy_store(policyStoreId=store_id, validationSettings={"mode": "STRICT"})

    undeclared_action_statement = (
        'permit(principal == PhotoApp::User::"alice", action == PhotoApp::Action::"deletePhoto", '
        'resource == PhotoApp::Photo::"vacation.jpg");'
    )
    err = _error(
        lambda: client.create_policy(
            policyStoreId=store_id,
            definition={"static": {"statement": undeclared_action_statement}},
        )
    )
    assert err["Error"]["Code"] == "ValidationException", (
        f"a static policy referencing an undeclared action was rejected with "
        f"{err['Error']['Code']!r}, expected 'ValidationException'"
    )
    assert err["Error"]["Message"] == "Invalid input", (
        f"unexpected message={err['Error']['Message']!r}"
    )
    expected_fields = [
        {
            "path": "/definition",
            "message": 'for policy `policy0`, unrecognized action `PhotoApp::Action::"deletePhoto"`',
        },
        {
            "path": "/definition",
            "message": (
                "for policy `policy0`, unable to find an applicable action given the policy "
                "scope constraints"
            ),
        },
    ]
    assert err.get("fieldList") == expected_fields, f"unexpected fieldList={err.get('fieldList')!r}"
    # effect absent: the rejected policy never landed in the store.
    after_rejected = client.list_policies(policyStoreId=store_id)["policies"]
    assert after_rejected == [], (
        f"the rejected create_policy call still left policies behind: {after_rejected!r}"
    )

    declared_action_statement = (
        'permit(principal == PhotoApp::User::"alice", action == PhotoApp::Action::"viewPhoto", '
        'resource == PhotoApp::Photo::"vacation.jpg");'
    )
    policy_id = client.create_policy(
        policyStoreId=store_id,
        definition={"static": {"statement": declared_action_statement}},
    )["policyId"]
    ctx.on_cleanup(lambda: client.delete_policy(policyStoreId=store_id, policyId=policy_id))
    fetched = client.get_policy(policyStoreId=store_id, policyId=policy_id)
    assert fetched["policyId"] == policy_id, (
        f"an independent get_policy read returned policyId {fetched['policyId']!r}, "
        f"expected the created policy {policy_id!r}"
    )


def _create_policy_store(ctx, client, mode: str = "OFF") -> str:
    store_id = client.create_policy_store(
        validationSettings={"mode": mode}, tags={"sim2real-check": CHECK}
    )["policyStoreId"]
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
