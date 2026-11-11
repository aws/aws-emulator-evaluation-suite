"""group-membership-create-then-describe."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "group-membership-create-then-describe"
GROUP = "state"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """CreateGroupMembership creates a relationship DescribeGroupMembership can retrieve exactly."""
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
    ctx.on_cleanup(lambda: _safe_delete_group(ctx, identity_store_id, group_id))

    membership_id = idc.create_group_membership(
        IdentityStoreId=identity_store_id,
        GroupId=group_id,
        MemberId={"UserId": user_id},
    )["MembershipId"]

    desc = idc.describe_group_membership(IdentityStoreId=identity_store_id, MembershipId=membership_id)
    assert desc["MembershipId"] == membership_id, (
        f"expected DescribeGroupMembership to echo MembershipId {membership_id!r}, got {desc['MembershipId']!r}"
    )
    assert desc["GroupId"] == group_id, (
        f"expected DescribeGroupMembership GroupId {group_id!r}, got {desc['GroupId']!r}"
    )
    assert desc["MemberId"]["UserId"] == user_id, (
        f"expected DescribeGroupMembership MemberId.UserId {user_id!r}, got {desc['MemberId']['UserId']!r}"
    )
    assert desc["IdentityStoreId"] == identity_store_id, (
        f"expected DescribeGroupMembership IdentityStoreId {identity_store_id!r}, got {desc['IdentityStoreId']!r}"
    )


def _get_identity_store_id(ctx) -> str:
    sso_admin = ctx.client("sso-admin")
    instances = sso_admin.list_instances().get("Instances", [])
    if instances:
        return instances[0]["IdentityStoreId"]
    try:
        created = sso_admin.create_instance(Name=ctx.unique_name("sim2real-idstore-idc-"))
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        raise AssertionError(
            "No IAM Identity Center instance is enabled in this account/region "
            "(sso-admin ListInstances returned none), and self-service provisioning "
            f"was rejected ({code}: {exc.response['Error'].get('Message', '')}); this is "
            "expected for an AWS Organizations management/member account, which AWS blocks "
            "from creating its own IAM Identity Center instance -- enable IAM Identity Center "
            "to provision an identity store for identitystore checks."
        ) from exc
    instance_arn = created["InstanceArn"]
    ctx.on_cleanup(lambda: _safe_delete_instance(sso_admin, instance_arn))
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        for inst in sso_admin.list_instances().get("Instances", []):
            if inst.get("InstanceArn") == instance_arn and inst.get("IdentityStoreId"):
                return inst["IdentityStoreId"]
        time.sleep(1)
    raise AssertionError(
        f"created IAM Identity Center instance {instance_arn} but its IdentityStoreId never "
        "appeared via sso-admin ListInstances within 30s"
    )


def _safe_delete_instance(sso_admin, instance_arn: str) -> None:
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
