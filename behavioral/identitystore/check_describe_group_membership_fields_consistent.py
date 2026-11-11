"""describe-group-membership-fields-consistent."""
from __future__ import annotations

import time as _time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "describe-group-membership-fields-consistent"
GROUP = "data-plane"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """The GroupMembership item returned inline by ListGroupMemberships is byte-for-byte
    consistent with the same MembershipId fetched directly via DescribeGroupMembership."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")

    group_id = idstore.create_group(
        IdentityStoreId=store_id, DisplayName=ctx.unique_name("sim2real-group-")
    )["GroupId"]
    ctx.on_cleanup(lambda: _safe(lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=group_id)))
    user_id = idstore.create_user(
        IdentityStoreId=store_id,
        UserName=ctx.unique_name("sim2real-user-"),
        DisplayName=ctx.unique_name("sim2real-user-"),
        Name={"GivenName": "Describe", "FamilyName": "Consistent"},
    )["UserId"]
    ctx.on_cleanup(lambda: _safe(lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=user_id)))

    membership_id = idstore.create_group_membership(
        IdentityStoreId=store_id, GroupId=group_id, MemberId={"UserId": user_id}
    )["MembershipId"]

    listed = idstore.list_group_memberships(IdentityStoreId=store_id, GroupId=group_id)["GroupMemberships"]
    listed_item = next(m for m in listed if m["MembershipId"] == membership_id)

    described = idstore.describe_group_membership(IdentityStoreId=store_id, MembershipId=membership_id)

    for field, expected in (
        ("MembershipId", membership_id),
        ("GroupId", group_id),
        ("IdentityStoreId", store_id),
    ):
        assert listed_item[field] == expected == described[field], (
            field,
            listed_item[field],
            described[field],
            expected,
        )
    for field in ("CreatedAt", "UpdatedAt"):
        assert listed_item[field] == described[field], (field, listed_item[field], described[field])
    assert listed_item["MemberId"]["UserId"] == described["MemberId"]["UserId"] == user_id, (
        listed_item["MemberId"],
        described["MemberId"],
        user_id,
    )


def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]["Code"]


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
