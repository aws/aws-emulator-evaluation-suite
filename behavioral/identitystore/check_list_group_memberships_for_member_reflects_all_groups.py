"""list-group-memberships-for-member-reflects-all-groups."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-group-memberships-for-member-reflects-all-groups"
GROUP = "state"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """ListGroupMembershipsForMember returns every group the member was added to, and none else."""
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

    group_ids = []
    for _ in range(2):
        display_name = ctx.unique_name("sim2real-idstore-group-")
        group_id = idc.create_group(IdentityStoreId=identity_store_id, DisplayName=display_name)["GroupId"]
        ctx.on_cleanup(lambda gid=group_id: _safe_delete_group(ctx, identity_store_id, gid))
        idc.create_group_membership(
            IdentityStoreId=identity_store_id,
            GroupId=group_id,
            MemberId={"UserId": user_id},
        )
        group_ids.append(group_id)

    # A third group the member is deliberately NOT added to.
    other_display_name = ctx.unique_name("sim2real-idstore-group-")
    other_group_id = idc.create_group(IdentityStoreId=identity_store_id, DisplayName=other_display_name)["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete_group(ctx, identity_store_id, other_group_id))

    seen_group_ids = set()
    next_token = None
    for _ in range(20):
        kwargs = {"IdentityStoreId": identity_store_id, "MemberId": {"UserId": user_id}}
        if next_token:
            kwargs["NextToken"] = next_token
        page = idc.list_group_memberships_for_member(**kwargs)
        for item in page["GroupMemberships"]:
            seen_group_ids.add(item["GroupId"])
        next_token = page.get("NextToken")
        if not next_token:
            break

    assert seen_group_ids == set(group_ids), (
        f"expected ListGroupMembershipsForMember to return exactly {set(group_ids)}, got {seen_group_ids}"
    )
    assert other_group_id not in seen_group_ids, (
        f"group {other_group_id} the member was never added to leaked into the membership listing"
    )


def _get_identity_store_id(ctx) -> str:
    import time

    sso_admin = ctx.client("sso-admin")
    instances = sso_admin.list_instances().get("Instances", [])
    if instances:
        return instances[0]["IdentityStoreId"]

    try:
        created = sso_admin.create_instance(Name=ctx.unique_name("sim2real-idc-"))
    except ClientError as exc:
        raise AssertionError(
            "No IAM Identity Center instance is enabled in this account/region "
            "(sso-admin ListInstances returned none) and sso-admin.create_instance failed "
            f"({exc.response['Error']['Code']}); this is expected for AWS Organizations "
            "management/member accounts, which reject self-service instance creation -- run "
            "against a standalone account or an emulator that seeds a default identity store."
        ) from exc
    instance_arn = created["InstanceArn"]
    ctx.on_cleanup(lambda: _safe_delete_instance(ctx, instance_arn))

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        for inst in sso_admin.list_instances().get("Instances", []):
            if inst.get("InstanceArn") == instance_arn and inst.get("IdentityStoreId"):
                return inst["IdentityStoreId"]
        time.sleep(1)
    raise AssertionError(
        f"created IAM Identity Center instance {instance_arn} but its IdentityStoreId never "
        "appeared via sso-admin.list_instances within 30s"
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
