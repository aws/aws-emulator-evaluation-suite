"""update-group-description-remove."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-group-description-remove"
GROUP = "state"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """An AttributeOperation with no AttributeValue removes the targeted attribute entirely."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")
    group_id = idstore.create_group(
        IdentityStoreId=store_id,
        DisplayName=ctx.unique_name("sim2real-behav-group-"),
        Description="to be removed",
    )["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=group_id)))

    # Positive control: the description is present before the remove operation.
    before = idstore.describe_group(IdentityStoreId=store_id, GroupId=group_id)
    assert before.get("Description") == "to be removed", (
        f"expected Description='to be removed' before the remove operation, got {before.get('Description')!r}"
    )

    idstore.update_group(
        IdentityStoreId=store_id,
        GroupId=group_id,
        Operations=[{"AttributePath": "description"}],
    )

    after = idstore.describe_group(IdentityStoreId=store_id, GroupId=group_id)
    assert "Description" not in after or not after["Description"], (
        f"expected Description absent or empty after the remove operation, got {after.get('Description')!r}"
    )


from botocore.exceptions import ClientError


def _get_identity_store_id(ctx):
    import time
    from botocore.exceptions import ClientError

    sso_admin = ctx.client("sso-admin")

    def _ready_id(insts):
        for inst in insts:
            if inst.get("IdentityStoreId"):
                return inst["IdentityStoreId"]
        return None

    instances = sso_admin.list_instances().get("Instances", [])
    found = _ready_id(instances)
    if found:
        return found
    if not instances:
        try:
            sso_admin.create_instance(Name="sim2real-behav-idc")
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("ConflictException",):
                raise
    deadline = time.time() + 180
    while time.time() < deadline:
        instances = sso_admin.list_instances().get("Instances", [])
        found = _ready_id(instances)
        if found:
            return found
        time.sleep(3)
    raise AssertionError(
        "no IAM Identity Center instance could be enabled in this account/region"
    )


def _safe_delete(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
