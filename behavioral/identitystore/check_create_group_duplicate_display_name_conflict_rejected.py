"""create-group-duplicate-display-name-conflict-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-group-duplicate-display-name-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["identitystore"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """CreateGroup rejects a DisplayName that collides with an existing group (uniqueness constraint);
    the collision leaves the original as the sole owner of that name; and once the original group is
    deleted, the same DisplayName is no longer claimed and becomes creatable again."""
    identity_store_id = _get_identity_store_id(ctx)
    idc = ctx.client("identitystore")

    display_name = ctx.unique_name("sim2real-idstore-group-dup-")
    group_id = idc.create_group(IdentityStoreId=identity_store_id, DisplayName=display_name)["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete_group(ctx, identity_store_id, group_id))

    # Positive control: CreateGroup still works for a distinct DisplayName.
    other_display_name = ctx.unique_name("sim2real-idstore-group-dup-other-")
    other_group_id = idc.create_group(IdentityStoreId=identity_store_id, DisplayName=other_display_name)["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete_group(ctx, identity_store_id, other_group_id))
    other_described = idc.describe_group(IdentityStoreId=identity_store_id, GroupId=other_group_id)
    assert other_described["DisplayName"] == other_display_name, (
        f"positive control: expected DescribeGroup({other_group_id!r}) DisplayName "
        f"{other_display_name!r}, got {other_described.get('DisplayName')!r}"
    )

    err = _error(
        lambda: idc.create_group(IdentityStoreId=identity_store_id, DisplayName=display_name)
    )
    assert err == ("ConflictException", "Duplicate GroupDisplayName"), (
        f"expected ConflictException 'Duplicate GroupDisplayName' for a CreateGroup with a duplicate "
        f"DisplayName, got {err!r}"
    )

    # Effect absent: the unique-attribute index still resolves to the ORIGINAL group only,
    # proving no second group with the same DisplayName was created.
    resolved = idc.get_group_id(
        IdentityStoreId=identity_store_id,
        AlternateIdentifier={"UniqueAttribute": {"AttributePath": "displayName", "AttributeValue": display_name}},
    )["GroupId"]
    assert resolved == group_id, (
        f"expected GetGroupId(displayName={display_name!r}) to resolve to the original "
        f"{group_id!r}, got {resolved!r}"
    )

    # Restore: the rejection is a live uniqueness constraint, not the name being permanently
    # blocked -- once the original group is gone, the identical CreateGroup call succeeds.
    idc.delete_group(IdentityStoreId=identity_store_id, GroupId=group_id)
    restored_group_id = idc.create_group(IdentityStoreId=identity_store_id, DisplayName=display_name)["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete_group(ctx, identity_store_id, restored_group_id))
    assert restored_group_id != group_id, (
        f"expected a fresh GroupId after {group_id!r} was deleted and the name released, "
        f"got the same id back"
    )
    resolved_after_restore = idc.get_group_id(
        IdentityStoreId=identity_store_id,
        AlternateIdentifier={"UniqueAttribute": {"AttributePath": "displayName", "AttributeValue": display_name}},
    )["GroupId"]
    assert resolved_after_restore == restored_group_id, (
        f"expected GetGroupId(displayName={display_name!r}) to resolve to the restored "
        f"{restored_group_id!r}, got {resolved_after_restore!r}"
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
            sso_admin.create_instance(Name=ctx.unique_name("sim2real-idstore-group-dup-idc-"))
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException":
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


def _safe_delete_group(ctx, identity_store_id: str, group_id: str) -> None:
    idc = ctx.client("identitystore")
    try:
        idc.delete_group(IdentityStoreId=identity_store_id, GroupId=group_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected the duplicate-DisplayName CreateGroup to be rejected, but it SUCCEEDED "
        f"and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
