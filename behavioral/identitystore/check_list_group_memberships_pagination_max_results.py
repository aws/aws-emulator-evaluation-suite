"""list-group-memberships-pagination-max-results."""
from __future__ import annotations

import time as _time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-group-memberships-pagination-max-results"
GROUP = "state"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """ListGroupMemberships with MaxResults=1 pages through every membership exactly once each."""
    identity_store_id = _get_identity_store_id(ctx)
    idc = ctx.client("identitystore")

    display_name = ctx.unique_name("sim2real-idstore-group-")
    group_id = idc.create_group(IdentityStoreId=identity_store_id, DisplayName=display_name)["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete_group(ctx, identity_store_id, group_id))

    created_membership_ids = []
    for _ in range(3):
        username = ctx.unique_name("sim2real-idstore-user-")
        user_id = idc.create_user(
            IdentityStoreId=identity_store_id,
            UserName=username,
            DisplayName=username,
            Name={"GivenName": "Sim", "FamilyName": "Parity"},
        )["UserId"]
        ctx.on_cleanup(lambda uid=user_id: _safe_delete_user(ctx, identity_store_id, uid))
        membership_id = idc.create_group_membership(
            IdentityStoreId=identity_store_id,
            GroupId=group_id,
            MemberId={"UserId": user_id},
        )["MembershipId"]
        created_membership_ids.append(membership_id)

    collected_membership_ids = []
    next_token = None
    for _ in range(20):
        kwargs = {"IdentityStoreId": identity_store_id, "GroupId": group_id, "MaxResults": 1}
        if next_token:
            kwargs["NextToken"] = next_token
        page = idc.list_group_memberships(**kwargs)
        assert len(page["GroupMemberships"]) <= 1, (
            f"MaxResults=1 but page returned {len(page['GroupMemberships'])} memberships: "
            f"{page['GroupMemberships']}"
        )
        collected_membership_ids.extend(item["MembershipId"] for item in page["GroupMemberships"])
        next_token = page.get("NextToken")
        if not next_token:
            break

    assert sorted(collected_membership_ids) == sorted(created_membership_ids), (
        f"paginated union {sorted(collected_membership_ids)} != "
        f"created memberships {sorted(created_membership_ids)}"
    )


def _get_identity_store_id(ctx) -> str:
    sso_admin = ctx.client("sso-admin")
    instances = sso_admin.list_instances().get("Instances", [])
    if instances:
        return instances[0]["IdentityStoreId"]
    try:
        created = sso_admin.create_instance(Name=ctx.unique_name("sim2real-idc-"))
    except ClientError as exc:
        raise AssertionError(
            "no IAM Identity Center instance exists and sso-admin.create_instance failed "
            f"({exc.response['Error']['Code']}: {exc.response['Error']['Message']}); this is "
            "expected for AWS Organizations management/member accounts, which reject "
            "self-service instance creation -- run against a standalone account or an emulator "
            "that seeds a default identity store"
        ) from exc
    instance_arn = created["InstanceArn"]
    ctx.on_cleanup(lambda: _safe_delete_instance(sso_admin, instance_arn))
    deadline = _time.monotonic() + 30
    while _time.monotonic() < deadline:
        for inst in sso_admin.list_instances().get("Instances", []):
            if inst.get("InstanceArn") == instance_arn and inst.get("IdentityStoreId"):
                return inst["IdentityStoreId"]
        _time.sleep(1)
    raise AssertionError(
        f"created IAM Identity Center instance {instance_arn} but its IdentityStoreId never "
        "appeared via sso-admin.list_instances within 30s"
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
