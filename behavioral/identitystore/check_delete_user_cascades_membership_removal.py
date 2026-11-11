"""delete-user-cascades-membership-removal."""
from __future__ import annotations

import time as _time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-user-cascades-membership-removal"
GROUP = "state"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """Deleting a user also removes the group memberships that referenced it."""
    identity_store_id = _get_identity_store_id(ctx)
    idc = ctx.client("identitystore")

    username = ctx.unique_name("sim2real-idstore-user-")
    user_id = idc.create_user(
        IdentityStoreId=identity_store_id,
        UserName=username,
        DisplayName=username,
        Name={"GivenName": "Sim", "FamilyName": "Parity"},
    )["UserId"]

    display_name = ctx.unique_name("sim2real-idstore-group-")
    group_id = idc.create_group(IdentityStoreId=identity_store_id, DisplayName=display_name)["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete_group(ctx, identity_store_id, group_id))

    membership_id = idc.create_group_membership(
        IdentityStoreId=identity_store_id,
        GroupId=group_id,
        MemberId={"UserId": user_id},
    )["MembershipId"]

    # Positive control: an independent read confirms the membership exists BEFORE the user is
    # deleted, so a target that never actually persisted it cannot pass by already being empty.
    pre_delete = idc.describe_group_membership(IdentityStoreId=identity_store_id, MembershipId=membership_id)
    assert pre_delete["MemberId"]["UserId"] == user_id, (
        f"expected membership {membership_id} to reference user {user_id} before delete, "
        f"got {pre_delete!r}"
    )

    idc.delete_user(IdentityStoreId=identity_store_id, UserId=user_id)

    user_code, user_message = _client_error(
        lambda: idc.describe_user(IdentityStoreId=identity_store_id, UserId=user_id)
    )
    assert user_code == "ResourceNotFoundException", (
        f"expected DescribeUser on the deleted user {user_id} to 404, got {user_code!r}"
    )
    assert user_message == "User not found", (
        f"expected DescribeUser on the deleted user to say 'User not found', got {user_message!r}"
    )

    code = message = None
    deadline = _time.time() + 60
    while _time.time() < deadline:
        try:
            idc.describe_group_membership(IdentityStoreId=identity_store_id, MembershipId=membership_id)
        except ClientError as exc:
            code, message = exc.response["Error"]["Code"], exc.response["Error"].get("Message")
            if code == "ResourceNotFoundException":
                break
        _time.sleep(3)
    assert code == "ResourceNotFoundException", (
        f"expected membership {membership_id} to be gone after deleting its user, last saw {code!r}"
    )
    assert message == "Group membership not found for given pool and membershipId.", (
        f"expected DescribeGroupMembership on the cascaded membership to report AWS's not-found "
        f"message, got {message!r}"
    )

    memberships = idc.list_group_memberships(IdentityStoreId=identity_store_id, GroupId=group_id)["GroupMemberships"]
    assert memberships == [], f"expected no memberships left in group {group_id}, got {memberships!r}"

    # The group itself must survive the user's deletion — positive control on the cascade's blast radius.
    described_group = idc.describe_group(IdentityStoreId=identity_store_id, GroupId=group_id)
    assert described_group["GroupId"] == group_id, (
        f"expected group {group_id} to survive its member's deletion, got {described_group!r}"
    )


# ===== helpers =====
def _get_identity_store_id(ctx) -> str:
    """Adopt the account's IAM Identity Center instance, or create one on a fresh account.

    A fresh account routinely has none enabled yet, and Identity Center has no
    API of its own to provision an identity store -- so create-or-adopt here rather than failing
    every check that touches identitystore on a target that simply has not enabled it yet.
    """
    sso_admin = ctx.client("sso-admin")
    instances = sso_admin.list_instances().get("Instances", [])
    if instances:
        return instances[0]["IdentityStoreId"]
    try:
        created = sso_admin.create_instance(Name=ctx.unique_name("sim2real-idc-"))
    except ClientError as exc:
        raise AssertionError(
            "no IAM Identity Center instance exists and sso-admin.create_instance failed "
            f"({exc}); this is expected for AWS Organizations management/member accounts, which "
            "reject self-service instance creation -- run against a standalone account or an "
            "emulator that seeds a default identity store"
        ) from exc
    instance_arn = created["InstanceArn"]
    ctx.on_cleanup(lambda: _safe(lambda: sso_admin.delete_instance(InstanceArn=instance_arn)))
    deadline = _time.monotonic() + 30
    while _time.monotonic() < deadline:
        for inst in sso_admin.list_instances().get("Instances", []):
            if inst.get("InstanceArn") == instance_arn and inst.get("IdentityStoreId"):
                return inst["IdentityStoreId"]
        _time.sleep(1)
    raise AssertionError(
        "created an IAM Identity Center instance but its IdentityStoreId never appeared via "
        "list_instances within 30s"
    )


def _safe(fn):
    try:
        fn()
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


def _client_error(fn):
    """Run ``fn`` and return the (code, message) of the ClientError it raises; a success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
