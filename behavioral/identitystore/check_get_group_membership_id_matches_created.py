"""get-group-membership-id-matches-created."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-group-membership-id-matches-created"
GROUP = "state"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """GetGroupMembershipId resolves the same MembershipId that CreateGroupMembership returned."""
    identity_store_id = _get_or_create_identity_store_id(ctx)
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
    ctx.on_cleanup(lambda: _safe_delete_group(ctx, identity_store_id, group_id))

    created_membership_id = idc.create_group_membership(
        IdentityStoreId=identity_store_id,
        GroupId=group_id,
        MemberId={"UserId": user_id},
    )["MembershipId"]

    resolved = idc.get_group_membership_id(
        IdentityStoreId=identity_store_id,
        GroupId=group_id,
        MemberId={"UserId": user_id},
    )["MembershipId"]

    assert resolved == created_membership_id, (
        f"GetGroupMembershipId resolved {resolved!r} but CreateGroupMembership returned "
        f"{created_membership_id!r} for the same GroupId/MemberId pair"
    )


def _get_or_create_identity_store_id(ctx) -> str:
    sso_admin = ctx.client("sso-admin")
    instances = sso_admin.list_instances().get("Instances", [])
    if instances:
        return instances[0]["IdentityStoreId"]

    try:
        created = sso_admin.create_instance(Name=ctx.unique_name("sim2real-idstore-"))
    except ClientError as exc:
        raise AssertionError(
            "No IAM Identity Center instance exists and sso-admin.CreateInstance was rejected "
            f"({exc.response['Error']['Code']}: {exc.response['Error'].get('Message')}); this is "
            "expected for AWS Organizations management/member accounts, which reject self-service "
            "instance creation -- run against a standalone account or an emulator that seeds a "
            "default identity store"
        ) from exc
    instance_arn = created["InstanceArn"]
    ctx.on_cleanup(lambda: _safe_delete_instance(ctx, instance_arn))

    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        instances = sso_admin.list_instances().get("Instances", [])
        for inst in instances:
            if inst.get("InstanceArn") == instance_arn and inst.get("IdentityStoreId"):
                return inst["IdentityStoreId"]
        time.sleep(3)
    raise AssertionError(
        f"created IAM Identity Center instance {instance_arn} but its IdentityStoreId never "
        "appeared via sso-admin.ListInstances within 180s"
    )


def _safe_delete_instance(ctx, instance_arn: str) -> None:
    sso_admin = ctx.client("sso-admin")
    try:
        sso_admin.delete_instance(InstanceArn=instance_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
