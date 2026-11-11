"""group-membership-create-list-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "group-membership-create-list-roundtrip"
GROUP = "data-plane"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """ListGroupMemberships on a freshly created group returns exactly the members added to it."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")
    group_id = idstore.create_group(
        IdentityStoreId=store_id, DisplayName=ctx.unique_name("sim2real-behav-group-")
    )["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=group_id)))

    user_ids = []
    for i in range(2):
        uid = idstore.create_user(
            IdentityStoreId=store_id,
            UserName=ctx.unique_name(f"sim2real-behav-member{i}-"),
            DisplayName=ctx.unique_name(f"sim2real-behav-member{i}-"),
            Name={"GivenName": "Member", "FamilyName": str(i)},
        )["UserId"]
        ctx.on_cleanup(lambda uid=uid: _safe_delete(lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=uid)))
        user_ids.append(uid)
        mid = idstore.create_group_membership(
            IdentityStoreId=store_id, GroupId=group_id, MemberId={"UserId": uid}
        )["MembershipId"]
        ctx.on_cleanup(
            lambda mid=mid: _safe_delete(
                lambda: idstore.delete_group_membership(IdentityStoreId=store_id, MembershipId=mid)
            )
        )

    memberships = idstore.list_group_memberships(IdentityStoreId=store_id, GroupId=group_id)["GroupMemberships"]
    assert len(memberships) == len(user_ids), (
        f"expected exactly {len(user_ids)} membership records, got {len(memberships)}: {memberships}"
    )
    listed_user_ids = {m["MemberId"]["UserId"] for m in memberships}
    assert listed_user_ids == set(user_ids), f"expected members {set(user_ids)}, listed {listed_user_ids}"
    for m in memberships:
        assert m["GroupId"] == group_id, f"expected GroupId {group_id}, got {m['GroupId']}"
        assert m["IdentityStoreId"] == store_id, f"expected IdentityStoreId {store_id}, got {m['IdentityStoreId']}"


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
