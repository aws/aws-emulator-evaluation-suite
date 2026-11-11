"""delete-policy-template-conflict-with-linked-policy."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-policy-template-conflict-with-linked-policy"
GROUP = "state"
SERVICES = ["verifiedpermissions"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeletePolicyTemplate also deletes its template-linked policy: GetPolicyTemplate, GetPolicy and a new CreatePolicy
    from the template fail with ResourceNotFoundException "Resource not found" naming the resource, and ListPolicies
    omits the linked policy."""
    client = ctx.client("verifiedpermissions")
    store_id = _create_policy_store(ctx, client)
    template_id = client.create_policy_template(
        policyStoreId=store_id,
        statement='permit(principal == ?principal, action == Action::"viewPhoto", resource == ?resource);',
    )["policyTemplateId"]

    linked_policy_id = client.create_policy(
        policyStoreId=store_id,
        definition={
            "templateLinked": {
                "policyTemplateId": template_id,
                "principal": {"entityType": "User", "entityId": "bob"},
                "resource": {"entityType": "Photo", "entityId": "beach.jpg"},
            }
        },
    )["policyId"]

    # DeletePolicyTemplate succeeds even though a template-linked policy
    # still exists -- it cascades the delete rather than rejecting it.
    client.delete_policy_template(policyStoreId=store_id, policyTemplateId=template_id)

    err_template = _error(
        lambda: client.get_policy_template(policyStoreId=store_id, policyTemplateId=template_id)
    )
    assert err_template["Error"]["Code"] == "ResourceNotFoundException", (
        f"expected GetPolicyTemplate after delete to report ResourceNotFoundException, got {err_template['Error']['Code']!r}"
    )
    assert err_template["Error"]["Message"] == "Resource not found", (
        f"unexpected message={err_template['Error']['Message']!r}"
    )
    assert (err_template.get("resourceType"), err_template.get("resourceId")) == ("POLICY_TEMPLATE", template_id), (
        f"unexpected resource={(err_template.get('resourceType'), err_template.get('resourceId'))!r}"
    )

    # ListPolicies immediately reflects the cascade: the linked policy is
    # gone from future API responses right away.
    remaining_ids = [p.get("policyId") for p in client.list_policies(policyStoreId=store_id)["policies"]]
    assert linked_policy_id not in remaining_ids, (
        f"expected {linked_policy_id!r} to be absent from ListPolicies after the template cascade, "
        f"found it among {remaining_ids!r}"
    )

    # GetPolicy on the linked policy converges to ResourceNotFoundException
    # (the underlying record is deleted asynchronously).
    err_policy = _poll_for_deleted_policy(client, store_id, linked_policy_id)
    assert err_policy["Error"]["Code"] == "ResourceNotFoundException", (
        f"expected GetPolicy on the cascade-deleted policy to report ResourceNotFoundException, got {err_policy['Error']['Code']!r}"
    )
    assert err_policy["Error"]["Message"] == "Resource not found", (
        f"unexpected message={err_policy['Error']['Message']!r}"
    )
    assert (err_policy.get("resourceType"), err_policy.get("resourceId")) == ("POLICY", linked_policy_id), (
        f"unexpected resource={(err_policy.get('resourceType'), err_policy.get('resourceId'))!r}"
    )

    # The dead template id is not just unreadable -- it is unusable: a new
    # CreatePolicy that links to it also fails, with the same not-found code.
    err_new_link = _error(
        lambda: client.create_policy(
            policyStoreId=store_id,
            definition={
                "templateLinked": {
                    "policyTemplateId": template_id,
                    "principal": {"entityType": "User", "entityId": "carol"},
                    "resource": {"entityType": "Photo", "entityId": "sunset.jpg"},
                }
            },
        )
    )
    assert err_new_link["Error"]["Code"] == "ResourceNotFoundException", (
        f"expected CreatePolicy linking to the deleted template to report ResourceNotFoundException, got {err_new_link['Error']['Code']!r}"
    )
    assert err_new_link["Error"]["Message"] == "Resource not found", (
        f"unexpected message={err_new_link['Error']['Message']!r}"
    )
    assert (err_new_link.get("resourceType"), err_new_link.get("resourceId")) == ("POLICY_TEMPLATE", template_id), (
        f"unexpected resource={(err_new_link.get('resourceType'), err_new_link.get('resourceId'))!r}"
    )


def _create_policy_store(ctx, client, mode: str = "OFF") -> str:
    store_id = client.create_policy_store(
        validationSettings={"mode": mode}, tags={"simparity-check": CHECK}
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


def _poll_for_deleted_policy(client, store_id, policy_id, timeout: float = 30.0, interval: float = 1.5):
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout
    last = "the policy is still readable"
    while time.monotonic() < deadline:
        try:
            client.get_policy(policyStoreId=store_id, policyId=policy_id)
            last = "the policy is still readable"
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return exc.response
            last = exc.response["Error"]["Code"]
        time.sleep(interval)
    raise AssertionError(
        f"GetPolicy never reported ResourceNotFoundException within {timeout}s; last: {last!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
