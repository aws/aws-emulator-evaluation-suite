"""update-group-description-persist."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-group-description-persist"
GROUP = "state"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """UpdateGroup on the description AttributePath replaces the description
    and leaves the displayName attribute untouched."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")
    display_name = ctx.unique_name("sim2real-behav-group-")
    group_id = idstore.create_group(
        IdentityStoreId=store_id,
        DisplayName=display_name,
        Description="original description",
    )["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=group_id)))

    idstore.update_group(
        IdentityStoreId=store_id,
        GroupId=group_id,
        Operations=[{"AttributePath": "description", "AttributeValue": "Contains all engineers"}],
    )

    described = idstore.describe_group(IdentityStoreId=store_id, GroupId=group_id)
    assert described["Description"] == "Contains all engineers", (
        f"expected Description 'Contains all engineers' after UpdateGroup, "
        f"got {described.get('Description')!r}"
    )
    assert described["DisplayName"] == display_name, (
        f"expected DisplayName untouched at {display_name!r} after a description-only "
        f"UpdateGroup, got {described.get('DisplayName')!r}"
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
