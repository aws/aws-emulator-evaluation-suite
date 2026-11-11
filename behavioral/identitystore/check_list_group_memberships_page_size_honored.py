"""list-group-memberships-page-size-honored."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-group-memberships-page-size-honored"
GROUP = "data-plane"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """ListGroupMemberships honors MaxResults and NextToken advances to a disjoint page, mirroring
    ListUsers/ListGroups pagination but for the membership listing operation specifically."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")

    group_id = idstore.create_group(
        IdentityStoreId=store_id, DisplayName=ctx.unique_name("sim2real-behav-pagegroup-")
    )["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=group_id)))

    for i in range(3):
        uid = idstore.create_user(
            IdentityStoreId=store_id,
            UserName=ctx.unique_name(f"sim2real-behav-pagemember{i}-"),
            DisplayName=ctx.unique_name(f"sim2real-behav-pagemember{i}-"),
            Name={"GivenName": "Page", "FamilyName": f"Member{i}"},
        )["UserId"]
        ctx.on_cleanup(lambda uid=uid: _safe_delete(lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=uid)))
        idstore.create_group_membership(IdentityStoreId=store_id, GroupId=group_id, MemberId={"UserId": uid})

    page1 = idstore.list_group_memberships(IdentityStoreId=store_id, GroupId=group_id, MaxResults=1)
    assert len(page1["GroupMemberships"]) == 1, (
        f"MaxResults=1 not honored: expected exactly 1 membership, got "
        f"{len(page1['GroupMemberships'])}"
    )
    assert page1.get("NextToken"), "expected a NextToken since 2 of 3 memberships remain unread"

    page2 = idstore.list_group_memberships(
        IdentityStoreId=store_id, GroupId=group_id, MaxResults=5, NextToken=page1["NextToken"]
    )
    assert len(page2["GroupMemberships"]) == 2, (
        f"expected the remaining 2 of 3 memberships on page 2 (MaxResults=5 exceeds what's left), "
        f"got {len(page2['GroupMemberships'])}"
    )

    page1_ids = {m["MembershipId"] for m in page1["GroupMemberships"]}
    page2_ids = {m["MembershipId"] for m in page2["GroupMemberships"]}
    assert page1_ids.isdisjoint(page2_ids), (
        f"page 1 and page 2 must be disjoint, got overlap {page1_ids & page2_ids}"
    )


from botocore.exceptions import ClientError


def _get_identity_store_id(ctx):
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
