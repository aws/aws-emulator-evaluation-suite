"""is-member-in-groups-reflects-membership."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "is-member-in-groups-reflects-membership"
GROUP = "state"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """IsMemberInGroups reports MembershipExists=True only for the groups the member joined."""
    identity_store_id = _get_identity_store_id(ctx)
    idc = ctx.client("identitystore")

    username = ctx.unique_name("sim2real-idstore-user-")
    user_id = idc.create_user(
        IdentityStoreId=identity_store_id,
        UserName=username,
        DisplayName=username,
        Name={"GivenName": "Sim", "FamilyName": "Parity"},
    )["UserId"]
    ctx.on_cleanup(lambda: _safe_delete_user(ctx, identity_store_id, user_id))

    group_ids = []
    for i in range(3):
        display_name = ctx.unique_name("sim2real-idstore-group-")
        group_id = idc.create_group(IdentityStoreId=identity_store_id, DisplayName=display_name)["GroupId"]
        ctx.on_cleanup(lambda gid=group_id: _safe_delete_group(ctx, identity_store_id, gid))
        group_ids.append(group_id)

    member_group_ids = group_ids[:2]
    non_member_group_id = group_ids[2]
    for gid in member_group_ids:
        idc.create_group_membership(
            IdentityStoreId=identity_store_id,
            GroupId=gid,
            MemberId={"UserId": user_id},
        )

    results = idc.is_member_in_groups(
        IdentityStoreId=identity_store_id,
        MemberId={"UserId": user_id},
        GroupIds=group_ids,
    )["Results"]

    by_group = {r["GroupId"]: r["MembershipExists"] for r in results}
    assert by_group[member_group_ids[0]] is True, (
        f"expected MembershipExists=True for joined group {member_group_ids[0]}, "
        f"got {by_group[member_group_ids[0]]!r}"
    )
    assert by_group[member_group_ids[1]] is True, (
        f"expected MembershipExists=True for joined group {member_group_ids[1]}, "
        f"got {by_group[member_group_ids[1]]!r}"
    )
    assert by_group[non_member_group_id] is False, (
        f"expected MembershipExists=False for non-member group {non_member_group_id}, "
        f"got {by_group[non_member_group_id]!r}"
    )


def _get_identity_store_id(ctx) -> str:
    import time

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
    raise AssertionError("no IAM Identity Center instance could be enabled in this account/region")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
