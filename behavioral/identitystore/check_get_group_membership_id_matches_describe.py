"""get-group-membership-id-matches-describe."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-group-membership-id-matches-describe"
GROUP = "data-plane"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """GetGroupMembershipId returns the same MembershipId that CreateGroupMembership produced."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")
    group_id = idstore.create_group(
        IdentityStoreId=store_id, DisplayName=ctx.unique_name("sim2real-behav-group-")
    )["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=group_id)))

    user_id = idstore.create_user(
        IdentityStoreId=store_id,
        UserName=ctx.unique_name("sim2real-behav-user-"),
        DisplayName=ctx.unique_name("sim2real-behav-user-"),
        Name={"GivenName": "Get", "FamilyName": "Membership"},
    )["UserId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=user_id)))

    created_membership_id = idstore.create_group_membership(
        IdentityStoreId=store_id, GroupId=group_id, MemberId={"UserId": user_id}
    )["MembershipId"]
    ctx.on_cleanup(
        lambda: _safe_delete(
            lambda: idstore.delete_group_membership(IdentityStoreId=store_id, MembershipId=created_membership_id)
        )
    )

    fetched = idstore.get_group_membership_id(
        IdentityStoreId=store_id, GroupId=group_id, MemberId={"UserId": user_id}
    )
    assert fetched["MembershipId"] == created_membership_id, (
        f"GetGroupMembershipId returned {fetched['MembershipId']!r}, "
        f"expected the id CreateGroupMembership produced: {created_membership_id!r}"
    )

    described = idstore.describe_group_membership(
        IdentityStoreId=store_id, MembershipId=created_membership_id
    )
    assert described["GroupId"] == group_id, (
        f"DescribeGroupMembership reported GroupId {described['GroupId']!r}, expected {group_id!r}"
    )
    assert described["MemberId"]["UserId"] == user_id, (
        f"DescribeGroupMembership reported MemberId.UserId {described['MemberId']['UserId']!r}, "
        f"expected {user_id!r}"
    )
    assert described["IdentityStoreId"] == store_id, (
        f"DescribeGroupMembership reported IdentityStoreId {described['IdentityStoreId']!r}, "
        f"expected {store_id!r}"
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
