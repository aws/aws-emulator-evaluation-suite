"""list-group-memberships-for-member."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-group-memberships-for-member"
GROUP = "data-plane"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """ListGroupMembershipsForMember returns exactly the groups a user was added to."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")
    user_id = idstore.create_user(
        IdentityStoreId=store_id,
        UserName=ctx.unique_name("sim2real-behav-user-"),
        DisplayName=ctx.unique_name("sim2real-behav-user-"),
        Name={"GivenName": "Multi", "FamilyName": "Group"},
    )["UserId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=user_id)))

    group_ids = []
    for i in range(2):
        gid = idstore.create_group(
            IdentityStoreId=store_id, DisplayName=ctx.unique_name(f"sim2real-behav-group{i}-")
        )["GroupId"]
        ctx.on_cleanup(lambda gid=gid: _safe_delete(lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=gid)))
        group_ids.append(gid)
        mid = idstore.create_group_membership(
            IdentityStoreId=store_id, GroupId=gid, MemberId={"UserId": user_id}
        )["MembershipId"]
        ctx.on_cleanup(
            lambda mid=mid: _safe_delete(
                lambda: idstore.delete_group_membership(IdentityStoreId=store_id, MembershipId=mid)
            )
        )

    # a sibling group the user is deliberately NOT added to, so the equality below cannot pass
    # merely because the account happens to have no other groups at the time of this run
    other_group_id = idstore.create_group(
        IdentityStoreId=store_id, DisplayName=ctx.unique_name("sim2real-behav-othergroup-")
    )["GroupId"]
    ctx.on_cleanup(
        lambda: _safe_delete(lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=other_group_id))
    )

    memberships = idstore.list_group_memberships_for_member(
        IdentityStoreId=store_id, MemberId={"UserId": user_id}
    )["GroupMemberships"]
    listed_group_ids = {m["GroupId"] for m in memberships}
    assert listed_group_ids == set(group_ids), (
        f"expected exactly the joined groups {set(group_ids)}, got {listed_group_ids}"
    )
    assert other_group_id not in listed_group_ids, (
        f"group {other_group_id} the member never joined leaked into the membership listing"
    )
    for m in memberships:
        assert m["MemberId"]["UserId"] == user_id, (
            f"expected MemberId.UserId {user_id}, got {m['MemberId'].get('UserId')}"
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
