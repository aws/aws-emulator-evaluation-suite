"""update-policy-immutable-principal-mutation-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-policy-immutable-principal-mutation-rejected"
GROUP = "overly-permissive"
SERVICES = ["verifiedpermissions"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePolicy with a different principal fails with ValidationException "Invalid input" and the
    exact fieldList and keeps principal User::alice, while an update that changes only the action to
    editPhoto succeeds."""
    client = ctx.client("verifiedpermissions")
    store_id = _create_policy_store(ctx, client)
    original_statement = (
        'permit(principal == User::"alice", action == Action::"viewPhoto", '
        'resource == Photo::"vacation.jpg");'
    )
    policy_id = client.create_policy(
        policyStoreId=store_id, definition={"static": {"statement": original_statement}}
    )["policyId"]
    ctx.on_cleanup(lambda: client.delete_policy(policyStoreId=store_id, policyId=policy_id))

    mutated_principal_statement = (
        'permit(principal == User::"bob", action == Action::"viewPhoto", '
        'resource == Photo::"vacation.jpg");'
    )
    err = _error(
        lambda: client.update_policy(
            policyStoreId=store_id,
            policyId=policy_id,
            definition={"static": {"statement": mutated_principal_statement}},
        )
    )
    assert err["Error"]["Code"] == "ValidationException", (
        f"expected ValidationException, got {err['Error']['Code']!r}"
    )
    assert err["Error"]["Message"] == "Invalid input", (
        f"unexpected message={err['Error']['Message']!r}"
    )
    expected_fields = [
        {
            "path": "/definition/static/statement",
            "message": "You can't change the principal referenced in the scope of an existing policy.",
        }
    ]
    assert err.get("fieldList") == expected_fields, f"unexpected fieldList={err.get('fieldList')!r}"
    # effect absent: principal on the stored policy is unchanged.
    unchanged = client.get_policy(policyStoreId=store_id, policyId=policy_id)
    assert unchanged["principal"] == {"entityType": "User", "entityId": "alice"}, (
        f"expected principal unchanged (alice), got {unchanged['principal']!r}"
    )

    # positive control: changing only the action is allowed and persists.
    mutated_action_statement = (
        'permit(principal == User::"alice", action == Action::"editPhoto", '
        'resource == Photo::"vacation.jpg");'
    )
    client.update_policy(
        policyStoreId=store_id,
        policyId=policy_id,
        definition={"static": {"statement": mutated_action_statement}},
    )
    updated = client.get_policy(policyStoreId=store_id, policyId=policy_id)
    assert updated["principal"] == {"entityType": "User", "entityId": "alice"}, (
        f"expected principal still alice after action-only update, got {updated['principal']!r}"
    )
    assert updated["actions"] == [{"actionType": "Action", "actionId": "editPhoto"}], (
        f"expected actions=[editPhoto], got {updated['actions']!r}"
    )


def _create_policy_store(ctx, client, mode: str = "OFF") -> str:
    store_id = client.create_policy_store(validationSettings={"mode": mode})["policyStoreId"]
    ctx.on_cleanup(lambda: client.delete_policy_store(policyStoreId=store_id))
    arn = client.get_policy_store(policyStoreId=store_id)["arn"]
    client.tag_resource(resourceArn=arn, tags={"sim2real": "behavioral"})
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
