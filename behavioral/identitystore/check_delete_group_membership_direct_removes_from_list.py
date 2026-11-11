"""delete-group-membership-direct-removes-from-list."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-group-membership-direct-removes-from-list"
GROUP = "state"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """A direct DeleteGroupMembership removes exactly that record, leaving sibling memberships intact."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")
    group_id = idstore.create_group(
        IdentityStoreId=store_id, DisplayName=ctx.unique_name("sim2real-behav-group-")
    )["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=group_id)))

    user_a = idstore.create_user(
        IdentityStoreId=store_id,
        UserName=ctx.unique_name("sim2real-behav-user-a-"),
        DisplayName=ctx.unique_name("sim2real-behav-user-a-"),
        Name={"GivenName": "Direct", "FamilyName": "Delete"},
    )["UserId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=user_a)))

    user_b = idstore.create_user(
        IdentityStoreId=store_id,
        UserName=ctx.unique_name("sim2real-behav-user-b-"),
        DisplayName=ctx.unique_name("sim2real-behav-user-b-"),
        Name={"GivenName": "Direct", "FamilyName": "Survivor"},
    )["UserId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=user_b)))

    membership_a = idstore.create_group_membership(
        IdentityStoreId=store_id, GroupId=group_id, MemberId={"UserId": user_a}
    )["MembershipId"]
    membership_b = idstore.create_group_membership(
        IdentityStoreId=store_id, GroupId=group_id, MemberId={"UserId": user_b}
    )["MembershipId"]
    ctx.on_cleanup(
        lambda: _safe_delete(
            lambda: idstore.delete_group_membership(IdentityStoreId=store_id, MembershipId=membership_b)
        )
    )

    idstore.delete_group_membership(IdentityStoreId=store_id, MembershipId=membership_a)

    # DeleteGroupMembership is eventually consistent; poll DescribeGroupMembership on a bounded
    # deadline rather than trusting a single immediate read.
    err = _poll_error(
        lambda: idstore.describe_group_membership(IdentityStoreId=store_id, MembershipId=membership_a)
    )
    assert err == ("ResourceNotFoundException", "Group membership not found for given pool and membershipId."), (
        f"expected DescribeGroupMembership on deleted membership_a ({membership_a}) to raise "
        f"ResourceNotFoundException, got {err!r}"
    )

    remaining = idstore.list_group_memberships(IdentityStoreId=store_id, GroupId=group_id)["GroupMemberships"]
    remaining_ids = {m["MembershipId"] for m in remaining}
    assert membership_a not in remaining_ids, (
        f"deleted membership_a ({membership_a}) is still present in ListGroupMemberships: {remaining_ids}"
    )
    assert membership_b in remaining_ids, (
        f"sibling membership_b ({membership_b}) is missing from ListGroupMemberships after deleting "
        f"membership_a: {remaining_ids}"
    )

    # Positive control: the sibling membership (user_b) is still fully describable.
    described = idstore.describe_group_membership(IdentityStoreId=store_id, MembershipId=membership_b)
    assert described["MemberId"]["UserId"] == user_b, (
        f"expected sibling membership_b to describe as user_b, got {described['MemberId']}"
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


def _poll_error(fn, timeout_s=60):
    """Call fn() until it raises; return that ClientError (code, message). A call that keeps
    succeeding past the deadline raises, so a delete that never takes effect fails loudly."""
    import time as _poll_time

    deadline = _poll_time.time() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        if _poll_time.time() >= deadline:
            raise AssertionError(f"expected the call to fail within {timeout_s}s, but it still returned {result!r}")
        _poll_time.sleep(3)


def _safe_delete(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
