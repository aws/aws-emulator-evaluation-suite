"""update-group-description-persists."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-group-description-persists"
GROUP = "state"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """UpdateGroup with a 'description' AttributePath operation replaces the description,
    leaves DisplayName untouched, and DeleteGroup then makes the id unreadable and unmutable."""
    identity_store_id = _get_identity_store_id(ctx)
    idc = ctx.client("identitystore")
    display_name = ctx.unique_name("sim2real-idstore-group-")
    group_id = idc.create_group(
        IdentityStoreId=identity_store_id,
        DisplayName=display_name,
        Description="Original description",
    )["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete_group(ctx, identity_store_id, group_id))

    idc.update_group(
        IdentityStoreId=identity_store_id,
        GroupId=group_id,
        Operations=[{"AttributePath": "description", "AttributeValue": "Updated description"}],
    )

    after = idc.describe_group(IdentityStoreId=identity_store_id, GroupId=group_id)
    assert after["Description"] == "Updated description", (
        f"expected Description == 'Updated description' after UpdateGroup, "
        f"got {after.get('Description')!r}"
    )
    # The display name is untouched by the targeted update.
    assert after["DisplayName"] == display_name, (
        f"expected DisplayName untouched by the targeted description update, "
        f"got {after.get('DisplayName')!r}, expected {display_name!r}"
    )

    idc.delete_group(IdentityStoreId=identity_store_id, GroupId=group_id)

    try:
        idc.describe_group(IdentityStoreId=identity_store_id, GroupId=group_id)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException from DescribeGroup after DeleteGroup, got {code!r}"
        )
        message = exc.response["Error"].get("Message")
        assert message == "Group not found", (
            f"expected DescribeGroup after DeleteGroup to say 'Group not found', got {message!r}"
        )
    else:
        raise AssertionError(
            "DescribeGroup succeeded for a group_id already removed by DeleteGroup"
        )

    try:
        idc.update_group(
            IdentityStoreId=identity_store_id,
            GroupId=group_id,
            Operations=[{"AttributePath": "description", "AttributeValue": "post-delete"}],
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException from UpdateGroup against a deleted group_id, "
            f"got {code!r}"
        )
        message = exc.response["Error"].get("Message")
        assert message == "Group not found", (
            f"expected UpdateGroup against a deleted group_id to say 'Group not found', got {message!r}"
        )
    else:
        raise AssertionError(
            "UpdateGroup succeeded against a group_id already removed by DeleteGroup"
        )


def _get_identity_store_id(ctx) -> str:
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
            sso_admin.create_instance(Name="sim2real-idstore-idc")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException":
                raise
    deadline = time.time() + 60
    while time.time() < deadline:
        instances = sso_admin.list_instances().get("Instances", [])
        found = _ready_id(instances)
        if found:
            return found
        time.sleep(2)
    raise AssertionError(
        "no IAM Identity Center instance with a populated IdentityStoreId became available "
        "in this account/region within 60s (sso-admin ListInstances returned none, or an "
        "instance whose IdentityStoreId had not yet propagated)"
    )


def _safe_delete_group(ctx, identity_store_id: str, group_id: str) -> None:
    idc = ctx.client("identitystore")
    try:
        idc.delete_group(IdentityStoreId=identity_store_id, GroupId=group_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
