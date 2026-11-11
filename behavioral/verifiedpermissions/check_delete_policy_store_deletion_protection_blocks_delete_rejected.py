"""delete-policy-store-deletion-protection-blocks-delete-rejected."""
from __future__ import annotations

CHECK = "delete-policy-store-deletion-protection-blocks-delete-rejected"
GROUP = "overly-permissive"
SERVICES = ["verifiedpermissions"]

from behavioral_harness import tags


def _cleanup_store(client, store_id: str, deleted: dict) -> None:
    if deleted["done"]:
        return
    client.update_policy_store(
        policyStoreId=store_id, validationSettings={"mode": "OFF"}, deletionProtection="DISABLED"
    )
    client.delete_policy_store(policyStoreId=store_id)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeletePolicyStore on a store with deletionProtection ENABLED fails with InvalidStateException and the exact
    message and the store survives; after UpdatePolicyStore disables protection the delete succeeds and GetPolicyStore
    fails with ResourceNotFoundException "Resource not found" naming the store."""
    client = ctx.client("verifiedpermissions")
    store_id = client.create_policy_store(
        validationSettings={"mode": "OFF"},
        deletionProtection="ENABLED",
        tags={"owner": "sim2real"},
    )["policyStoreId"]
    deleted = {"done": False}
    ctx.on_cleanup(lambda: _cleanup_store(client, store_id, deleted))

    err = _error(lambda: client.delete_policy_store(policyStoreId=store_id))
    assert err["Error"]["Code"] == "InvalidStateException", (
        f"DeletePolicyStore on a store with deletionProtection=ENABLED must be refused with "
        f"InvalidStateException, got {err['Error']['Code']!r}"
    )
    assert err["Error"]["Message"] == (
        "The policy store cannot be deleted because deletion protection is enabled. "
        "Deletion protection must be disabled first."
    ), f"unexpected message={err['Error']['Message']!r}"
    # effect absent: the store is still there.
    surviving_id = client.get_policy_store(policyStoreId=store_id)["policyStoreId"]
    assert surviving_id == store_id, (
        f"the store must survive the rejected delete; GetPolicyStore returned {surviving_id!r} "
        f"instead of {store_id!r}"
    )

    client.update_policy_store(
        policyStoreId=store_id, validationSettings={"mode": "OFF"}, deletionProtection="DISABLED"
    )
    client.delete_policy_store(policyStoreId=store_id)
    deleted["done"] = True

    # positive control: deletion actually happened this time.
    err_after = _error(lambda: client.get_policy_store(policyStoreId=store_id))
    assert err_after["Error"]["Code"] == "ResourceNotFoundException", (
        f"expected GetPolicyStore after the unprotected delete to report ResourceNotFoundException, got {err_after['Error']['Code']!r}"
    )
    assert err_after["Error"]["Message"] == "Resource not found", (
        f"unexpected message={err_after['Error']['Message']!r}"
    )
    assert (err_after.get("resourceType"), err_after.get("resourceId")) == ("POLICY_STORE", store_id), (
        f"unexpected resource={(err_after.get('resourceType'), err_after.get('resourceId'))!r}"
    )


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
