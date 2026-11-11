"""delete-group-cascades-membership-removal."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-group-cascades-membership-removal"
GROUP = "state"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """Deleting a group also removes the memberships that referenced it."""
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

    display_name = ctx.unique_name("sim2real-idstore-group-")
    group_id = idc.create_group(IdentityStoreId=identity_store_id, DisplayName=display_name)["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete_group(idc, identity_store_id, group_id))

    membership_id = idc.create_group_membership(
        IdentityStoreId=identity_store_id,
        GroupId=group_id,
        MemberId={"UserId": user_id},
    )["MembershipId"]

    idc.delete_group(IdentityStoreId=identity_store_id, GroupId=group_id)

    err = _poll_error(
        lambda: idc.describe_group_membership(IdentityStoreId=identity_store_id, MembershipId=membership_id)
    )
    assert err == ("ResourceNotFoundException", "Group membership not found for given pool and membershipId."), (
        f"expected DeleteGroup to cascade-remove membership {membership_id!r} within 60s "
        f"(DescribeGroupMembership -> ResourceNotFoundException), got {err!r}"
    )

    # The user itself must survive the group's deletion.
    idc.describe_user(IdentityStoreId=identity_store_id, UserId=user_id)


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
    raise AssertionError(
        "no IAM Identity Center instance could be enabled in this account/region"
    )


def _safe_delete_user(ctx, identity_store_id: str, user_id: str) -> None:
    idc = ctx.client("identitystore")
    try:
        idc.delete_user(IdentityStoreId=identity_store_id, UserId=user_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_group(idc, identity_store_id: str, group_id: str) -> None:
    try:
        idc.delete_group(IdentityStoreId=identity_store_id, GroupId=group_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
