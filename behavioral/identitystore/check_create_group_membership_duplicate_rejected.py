"""create-group-membership-duplicate-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-group-membership-duplicate-rejected"
GROUP = "overly-permissive"
SERVICES = ["identitystore"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateGroupMembership rejects adding a member that is already in the group."""
    identity_store_id = _get_identity_store_id(ctx)
    idc = ctx.client("identitystore")

    display_name = ctx.unique_name("sim2real-idstore-group-")
    group_id = idc.create_group(IdentityStoreId=identity_store_id, DisplayName=display_name)["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete_group(ctx, identity_store_id, group_id))

    user1_name = ctx.unique_name("sim2real-idstore-user-1-")
    user1_id = idc.create_user(
        IdentityStoreId=identity_store_id,
        UserName=user1_name,
        DisplayName=user1_name,
        Name={"GivenName": "Sim", "FamilyName": "Parity"},
    )["UserId"]
    ctx.on_cleanup(lambda: _safe_delete_user(ctx, identity_store_id, user1_id))

    user2_name = ctx.unique_name("sim2real-idstore-user-2-")
    user2_id = idc.create_user(
        IdentityStoreId=identity_store_id,
        UserName=user2_name,
        DisplayName=user2_name,
        Name={"GivenName": "Sim", "FamilyName": "Parity"},
    )["UserId"]
    ctx.on_cleanup(lambda: _safe_delete_user(ctx, identity_store_id, user2_id))

    idc.create_group_membership(IdentityStoreId=identity_store_id, GroupId=group_id, MemberId={"UserId": user1_id})

    # Positive control: CreateGroupMembership still works for a distinct member of the same group.
    idc.create_group_membership(IdentityStoreId=identity_store_id, GroupId=group_id, MemberId={"UserId": user2_id})

    err = _error(
        lambda: idc.create_group_membership(
            IdentityStoreId=identity_store_id, GroupId=group_id, MemberId={"UserId": user1_id}
        )
    )
    assert err == ("ConflictException", "Member and Group relationship already exists"), (
        f"expected ConflictException 'Member and Group relationship already exists' for a duplicate "
        f"member, got {err!r}"
    )

    # Effect absent: the group still has exactly the two distinct members, not three.
    memberships = idc.list_group_memberships(IdentityStoreId=identity_store_id, GroupId=group_id)["GroupMemberships"]
    member_ids = sorted(m["MemberId"]["UserId"] for m in memberships)
    expected_ids = sorted([user1_id, user2_id])
    assert member_ids == expected_ids, f"expected members {expected_ids}, got {member_ids}"


def _get_identity_store_id(ctx) -> str:
    sso_admin = ctx.client("sso-admin")
    instances = sso_admin.list_instances().get("Instances", [])
    if not instances:
        raise AssertionError(
            "No IAM Identity Center instance is enabled in this account/region "
            "(sso-admin ListInstances returned none); enable IAM Identity Center "
            "to provision an identity store for identitystore checks."
        )
    return instances[0]["IdentityStoreId"]


def _safe_delete_user(ctx, identity_store_id: str, user_id: str) -> None:
    idc = ctx.client("identitystore")
    try:
        idc.delete_user(IdentityStoreId=identity_store_id, UserId=user_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
