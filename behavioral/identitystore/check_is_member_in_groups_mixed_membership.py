"""is-member-in-groups-mixed-membership."""
from __future__ import annotations

import time as _time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "is-member-in-groups-mixed-membership"
GROUP = "data-plane"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """IsMemberInGroups reports MembershipExists=True for a group the user was added to and
    False for a sibling group the user was never added to, in a single batched call."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")

    user_id = idstore.create_user(
        IdentityStoreId=store_id,
        UserName=ctx.unique_name("sim2real-user-"),
        DisplayName=ctx.unique_name("sim2real-user-"),
        Name={"GivenName": "Mixed", "FamilyName": "Membership"},
    )["UserId"]
    ctx.on_cleanup(lambda: _teardown(lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=user_id)))

    group_in_id = idstore.create_group(
        IdentityStoreId=store_id, DisplayName=ctx.unique_name("sim2real-group-in-")
    )["GroupId"]
    ctx.on_cleanup(lambda: _teardown(lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=group_in_id)))
    group_out_id = idstore.create_group(
        IdentityStoreId=store_id, DisplayName=ctx.unique_name("sim2real-group-out-")
    )["GroupId"]
    ctx.on_cleanup(lambda: _teardown(lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=group_out_id)))

    idstore.create_group_membership(
        IdentityStoreId=store_id, GroupId=group_in_id, MemberId={"UserId": user_id}
    )

    resp = idstore.is_member_in_groups(
        IdentityStoreId=store_id, MemberId={"UserId": user_id}, GroupIds=[group_in_id, group_out_id]
    )
    results = {r["GroupId"]: r["MembershipExists"] for r in resp["Results"]}
    assert results[group_in_id] is True, (
        f"expected MembershipExists=True for the group the user was added to ({group_in_id}), "
        f"got {results[group_in_id]!r}"
    )
    assert results[group_out_id] is False, (
        f"expected MembershipExists=False for the sibling group the user was never added to "
        f"({group_out_id}), got {results[group_out_id]!r}"
    )


def _teardown(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _get_identity_store_id(ctx):
    ssoadmin = ctx.client("sso-admin")
    try:
        resp = ssoadmin.list_instances()
    except Exception as exc:
        raise AssertionError(
            f"ssoadmin.list_instances is unavailable ({exc}); identitystore has no API of its "
            "own to provision an identity store, so a pre-existing (or emulator-seeded) IAM "
            "Identity Center instance is required"
        ) from exc
    instances = resp.get("Instances", [])
    if instances:
        return instances[0]["IdentityStoreId"]
    try:
        created = ssoadmin.create_instance(Name=ctx.unique_name("sim2real-idc-"))
    except Exception as exc:
        raise AssertionError(
            f"no IAM Identity Center instance exists and ssoadmin.create_instance failed ({exc}); "
            "this is expected for AWS Organizations management/member accounts, which reject "
            "self-service instance creation -- run against a standalone account or an emulator "
            "that seeds a default identity store"
        ) from exc
    instance_arn = created["InstanceArn"]
    ctx.on_cleanup(lambda: _teardown(lambda: ssoadmin.delete_instance(InstanceArn=instance_arn)))
    deadline = _time.monotonic() + 30
    while _time.monotonic() < deadline:
        resp = ssoadmin.list_instances()
        for inst in resp.get("Instances", []):
            if inst.get("InstanceArn") == instance_arn and inst.get("IdentityStoreId"):
                return inst["IdentityStoreId"]
        _time.sleep(1)
    raise AssertionError(
        "created an IAM Identity Center instance but its IdentityStoreId never appeared via "
        "list_instances within 30s",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
