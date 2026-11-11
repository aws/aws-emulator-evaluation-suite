"""create-group-describe-reflects-fields."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-group-describe-reflects-fields"
GROUP = "state"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """CreateGroup persists DisplayName/Description and DescribeGroup reflects them."""
    identity_store_id = _get_identity_store_id(ctx)
    idc = ctx.client("identitystore")
    display_name = ctx.unique_name("sim2real-idstore-group-")
    resp = idc.create_group(
        IdentityStoreId=identity_store_id,
        DisplayName=display_name,
        Description="a sim2real test group",
    )
    group_id = resp["GroupId"]
    assert resp["IdentityStoreId"] == identity_store_id, (
        f"CreateGroup response IdentityStoreId mismatch: expected {identity_store_id!r}, "
        f"got {resp.get('IdentityStoreId')!r}"
    )
    ctx.on_cleanup(lambda: _safe_delete_group(ctx, identity_store_id, group_id))

    desc = idc.describe_group(IdentityStoreId=identity_store_id, GroupId=group_id)
    assert desc["DisplayName"] == display_name, (
        f"DescribeGroup DisplayName mismatch: expected {display_name!r}, got {desc.get('DisplayName')!r}"
    )
    assert desc["Description"] == "a sim2real test group", (
        f"DescribeGroup Description mismatch: expected 'a sim2real test group', "
        f"got {desc.get('Description')!r}"
    )
    assert desc["GroupId"] == group_id, (
        f"DescribeGroup GroupId mismatch: expected {group_id!r}, got {desc.get('GroupId')!r}"
    )
    assert desc["IdentityStoreId"] == identity_store_id, (
        f"DescribeGroup IdentityStoreId mismatch: expected {identity_store_id!r}, "
        f"got {desc.get('IdentityStoreId')!r}"
    )
    assert "CreatedAt" in desc, "DescribeGroup response is missing CreatedAt"

    idc.delete_group(IdentityStoreId=identity_store_id, GroupId=group_id)
    try:
        idc.describe_group(IdentityStoreId=identity_store_id, GroupId=group_id)
        raise AssertionError("DescribeGroup succeeded for a group that was just deleted")
    except ClientError as exc:
        err = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
        assert err == ("ResourceNotFoundException", "Group not found"), (
            f"expected ResourceNotFoundException 'Group not found' from DescribeGroup after delete, got {err}"
        )
    try:
        idc.update_group(
            IdentityStoreId=identity_store_id,
            GroupId=group_id,
            Operations=[{"AttributePath": "description", "AttributeValue": "post-delete-update"}],
        )
        raise AssertionError("UpdateGroup succeeded against a group that was just deleted")
    except ClientError as exc:
        err = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
        assert err == ("ResourceNotFoundException", "Group not found"), (
            f"expected ResourceNotFoundException 'Group not found' from UpdateGroup on a deleted group, got {err}"
        )


def _get_identity_store_id(ctx) -> str:
    sso_admin = ctx.client("sso-admin")

    def _first_ready(instances):
        for inst in instances:
            if inst.get("IdentityStoreId"):
                return inst["IdentityStoreId"]
        return None

    instances = sso_admin.list_instances().get("Instances", [])
    found = _first_ready(instances)
    if found:
        return found

    try:
        sso_admin.create_instance(Name=ctx.unique_name("sim2real-idstore-"))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ConflictException":
            raise

    deadline = time.time() + 180
    while time.time() < deadline:
        instances = sso_admin.list_instances().get("Instances", [])
        found = _first_ready(instances)
        if found:
            return found
        time.sleep(3)
    raise AssertionError(
        "no IAM Identity Center instance became available in this account/region "
        "after CreateInstance (sso-admin ListInstances kept returning none)"
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
