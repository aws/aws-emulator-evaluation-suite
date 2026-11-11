"""is-member-in-groups-mixed-results."""
from __future__ import annotations

import time as _time

from behavioral_harness import tags

CHECK = "is-member-in-groups-mixed-results"
GROUP = "data-plane"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """IsMemberInGroups reports True for a group the user belongs to and False for one it doesn't, in one call."""
    identity_store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")

    user_id = idstore.create_user(
        IdentityStoreId=identity_store_id,
        UserName=ctx.unique_name("sim2real-behav-user-"),
        DisplayName=ctx.unique_name("sim2real-behav-user-"),
        Name={"GivenName": "Mixed", "FamilyName": "Results"},
    )["UserId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: idstore.delete_user(IdentityStoreId=identity_store_id, UserId=user_id))
    )

    member_group_id = idstore.create_group(
        IdentityStoreId=identity_store_id, DisplayName=ctx.unique_name("sim2real-behav-group-member-")
    )["GroupId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: idstore.delete_group(IdentityStoreId=identity_store_id, GroupId=member_group_id)
        )
    )
    idstore.create_group_membership(
        IdentityStoreId=identity_store_id, GroupId=member_group_id, MemberId={"UserId": user_id}
    )

    non_member_group_id = idstore.create_group(
        IdentityStoreId=identity_store_id, DisplayName=ctx.unique_name("sim2real-behav-group-nonmember-")
    )["GroupId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: idstore.delete_group(IdentityStoreId=identity_store_id, GroupId=non_member_group_id)
        )
    )

    resp = idstore.is_member_in_groups(
        IdentityStoreId=identity_store_id,
        MemberId={"UserId": user_id},
        GroupIds=[member_group_id, non_member_group_id],
    )
    by_group = {r["GroupId"]: r["MembershipExists"] for r in resp["Results"]}
    assert by_group[member_group_id] is True, (
        f"expected MembershipExists=True for member group {member_group_id}, got {by_group[member_group_id]!r}"
    )
    assert by_group[non_member_group_id] is False, (
        f"expected MembershipExists=False for non-member group {non_member_group_id}, "
        f"got {by_group[non_member_group_id]!r}"
    )


def _get_identity_store_id(ctx):
    """Discover the account's IAM Identity Center identity store id, provisioning one if absent.

    identitystore has no CreateIdentityStore API -- every operation requires a
    pre-existing store. sso-admin CreateInstance provisions one for a standalone
    account; an AWS Organizations member/management account rejects it, which is a
    deterministic, permanent refusal this check surfaces rather than silently skipping.
    """
    ssoadmin = ctx.client("sso-admin")
    instances = ssoadmin.list_instances().get("Instances", [])
    if instances:
        return instances[0]["IdentityStoreId"]

    from botocore.exceptions import ClientError

    try:
        created = ssoadmin.create_instance(Name=ctx.unique_name("sim2real-idc-"))
    except ClientError as exc:
        raise AssertionError(
            f"no IAM Identity Center instance enabled for this account/region, and "
            f"sso-admin.create_instance was refused ({exc.response['Error']['Code']}: "
            f"{exc.response['Error'].get('Message', '')}); identitystore requires a "
            "pre-existing instance that this check cannot provision itself"
        ) from exc

    instance_arn = created["InstanceArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: ssoadmin.delete_instance(InstanceArn=instance_arn)))
    deadline = _time.monotonic() + 30
    while _time.monotonic() < deadline:
        for inst in ssoadmin.list_instances().get("Instances", []):
            if inst.get("InstanceArn") == instance_arn and inst.get("IdentityStoreId"):
                return inst["IdentityStoreId"]
        _time.sleep(1)
    raise AssertionError(
        f"created IAM Identity Center instance {instance_arn} but its IdentityStoreId "
        "never appeared via list_instances within 30s"
    )


def _ignore_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
