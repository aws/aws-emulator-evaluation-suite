"""list-group-memberships-for-member-reflects-multiple-groups."""
from __future__ import annotations

import time as _time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-group-memberships-for-member-reflects-multiple-groups"
GROUP = "data-plane"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """ListGroupMembershipsForMember returns exactly the set of groups a user was added to,
    not a superset or subset, across two distinct groups."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")

    user_id = idstore.create_user(
        IdentityStoreId=store_id,
        UserName=ctx.unique_name("sim2real-user-"),
        DisplayName=ctx.unique_name("sim2real-user-"),
        Name={"GivenName": "Multi", "FamilyName": "Groups"},
    )["UserId"]
    ctx.on_cleanup(lambda: _safe(lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=user_id)))

    expected_group_ids = set()
    for _ in range(2):
        group_id = idstore.create_group(
            IdentityStoreId=store_id, DisplayName=ctx.unique_name("sim2real-group-")
        )["GroupId"]
        ctx.on_cleanup(lambda gid=group_id: _safe(lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=gid)))
        idstore.create_group_membership(
            IdentityStoreId=store_id, GroupId=group_id, MemberId={"UserId": user_id}
        )
        expected_group_ids.add(group_id)

    # a sibling group the user is NOT a member of must not leak into the result
    other_group_id = idstore.create_group(
        IdentityStoreId=store_id, DisplayName=ctx.unique_name("sim2real-group-other-")
    )["GroupId"]
    ctx.on_cleanup(lambda: _safe(lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=other_group_id)))

    resp = idstore.list_group_memberships_for_member(
        IdentityStoreId=store_id, MemberId={"UserId": user_id}, MaxResults=100
    )
    found_group_ids = {m["GroupId"] for m in resp["GroupMemberships"]}
    assert found_group_ids == expected_group_ids, (
        f"expected ListGroupMembershipsForMember to return exactly {expected_group_ids}, "
        f"got {found_group_ids}"
    )
    assert other_group_id not in found_group_ids, (
        f"group {other_group_id!r}, which the member was never added to, leaked into "
        f"ListGroupMembershipsForMember result {found_group_ids}"
    )


def _safe(fn):
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
    ctx.on_cleanup(lambda: _safe(lambda: ssoadmin.delete_instance(InstanceArn=instance_arn)))
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
