"""create-policy-from-template-resolves-placeholders."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-policy-from-template-resolves-placeholders"
GROUP = "data-plane"
SERVICES = ["verifiedpermissions"]


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A TEMPLATE_LINKED policy binds the exact principal and resource given to CreatePolicy, and
    IsAuthorized returns ALLOW determined by that policy for the bound principal and DENY for
    another."""
    client = ctx.client("verifiedpermissions")
    store_id = _create_policy_store(ctx, client)
    template_statement = (
        'permit(principal == ?principal, action == Action::"viewPhoto", resource == ?resource);'
    )
    template_id = client.create_policy_template(
        policyStoreId=store_id, statement=template_statement
    )["policyTemplateId"]
    ctx.on_cleanup(
        lambda: client.delete_policy_template(policyStoreId=store_id, policyTemplateId=template_id)
    )

    principal = {"entityType": "User", "entityId": "bob"}
    resource = {"entityType": "Photo", "entityId": "beach.jpg"}
    policy_id = client.create_policy(
        policyStoreId=store_id,
        definition={
            "templateLinked": {
                "policyTemplateId": template_id,
                "principal": principal,
                "resource": resource,
            }
        },
    )["policyId"]
    ctx.on_cleanup(lambda: client.delete_policy(policyStoreId=store_id, policyId=policy_id))

    got = client.get_policy(policyStoreId=store_id, policyId=policy_id)
    assert got["policyType"] == "TEMPLATE_LINKED", (
        f"expected policyType TEMPLATE_LINKED, got {got['policyType']!r}"
    )
    assert got["definition"]["templateLinked"]["principal"] == principal, (
        f"expected bound principal {principal!r}, "
        f"got {got['definition']['templateLinked']['principal']!r}"
    )
    assert got["definition"]["templateLinked"]["resource"] == resource, (
        f"expected bound resource {resource!r}, "
        f"got {got['definition']['templateLinked']['resource']!r}"
    )

    bound_allowed = _retry_until_ready(
        lambda: client.is_authorized(
            policyStoreId=store_id,
            principal=principal,
            action={"actionType": "Action", "actionId": "viewPhoto"},
            resource=resource,
        )
    )
    assert bound_allowed["decision"] == "ALLOW", (
        f"expected ALLOW for bound principal {principal!r}, got {bound_allowed['decision']!r}"
    )
    assert bound_allowed["determiningPolicies"] == [{"policyId": policy_id}], (
        f"expected determiningPolicies [{{'policyId': {policy_id!r}}}], "
        f"got {bound_allowed['determiningPolicies']!r}"
    )

    unbound_denied = client.is_authorized(
        policyStoreId=store_id,
        principal={"entityType": "User", "entityId": "alice"},
        action={"actionType": "Action", "actionId": "viewPhoto"},
        resource=resource,
    )
    assert unbound_denied["decision"] == "DENY", (
        "expected DENY for a principal never bound to the template-linked policy, "
        f"got {unbound_denied['decision']!r}"
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
