"""duplicate-group-membership-conflict-rejected."""
from __future__ import annotations

import time as _time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "duplicate-group-membership-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["identitystore"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """Adding the same member to the same group twice is rejected with ConflictException, no
    second membership row is created, and adding a different member to the same group still
    succeeds as a positive control."""
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
        Name={"GivenName": "Dup", "FamilyName": "Member"},
    )["UserId"]
    ctx.on_cleanup(lambda: _safe(lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=user_id)))

    idstore.create_group_membership(
        IdentityStoreId=store_id, GroupId=group_id, MemberId={"UserId": user_id}
    )

    code, message = _client_error(
        lambda: idstore.create_group_membership(
            IdentityStoreId=store_id, GroupId=group_id, MemberId={"UserId": user_id}
        )
    )
    assert code == "ConflictException", (
        f"expected ConflictException for a duplicate CreateGroupMembership, got {code!r}"
    )
    assert message == "Member and Group relationship already exists", (
        f"expected AWS's exact ConflictException message, got {message!r}"
    )

    # effect absent: exactly one membership row for this user, not two
    memberships = idstore.list_group_memberships(IdentityStoreId=store_id, GroupId=group_id)[
        "GroupMemberships"
    ]
    matching = [m for m in memberships if m["MemberId"]["UserId"] == user_id]
    assert len(matching) == 1, matching

    # positive control: a different member can still join the same group
    other_user_id = idstore.create_user(
        IdentityStoreId=store_id,
        UserName=ctx.unique_name("sim2real-user-other-"),
        DisplayName=ctx.unique_name("sim2real-user-other-"),
        Name={"GivenName": "Other", "FamilyName": "Member"},
    )["UserId"]
    ctx.on_cleanup(lambda: _safe(lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=other_user_id)))
    control_membership_id = idstore.create_group_membership(
        IdentityStoreId=store_id, GroupId=group_id, MemberId={"UserId": other_user_id}
    )["MembershipId"]
    assert control_membership_id, "positive control create_group_membership returned no MembershipId"

    # terminal read: independent of every mutating call above, at the destination
    final_memberships = idstore.list_group_memberships(IdentityStoreId=store_id, GroupId=group_id)[
        "GroupMemberships"
    ]
    final_member_ids = sorted(m["MemberId"]["UserId"] for m in final_memberships)
    expected_member_ids = sorted([user_id, other_user_id])
    assert final_member_ids == expected_member_ids, (
        f"expected exactly the original member and the positive-control member "
        f"{expected_member_ids} after the rejected duplicate, got {final_member_ids}"
    )


# ===== helpers =====
def _client_error(fn):
    """Run ``fn`` and return the (code, message) of the ClientError it raises; a success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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
