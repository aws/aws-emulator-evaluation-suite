"""group-membership-created-and-described."""
from __future__ import annotations

import time as _time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "group-membership-created-and-described"
GROUP = "state"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """CreateGroupMembership links the exact GroupId/MemberId; DescribeGroupMembership and
    GetGroupMembershipId both resolve back to the same MembershipId."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")

    group_id = _create_group(ctx, store_id)
    user_id = _create_user(ctx, store_id)
    membership_id = _create_membership(ctx, store_id, group_id, user_id)

    described = idstore.describe_group_membership(IdentityStoreId=store_id, MembershipId=membership_id)
    assert described["MembershipId"] == membership_id, (
        f"DescribeGroupMembership echoed MembershipId={described['MembershipId']!r}, "
        f"expected the id CreateGroupMembership returned ({membership_id!r})"
    )
    assert described["GroupId"] == group_id, (
        f"DescribeGroupMembership reported GroupId={described['GroupId']!r}, "
        f"expected the group this membership was created under ({group_id!r})"
    )
    assert described["MemberId"]["UserId"] == user_id, (
        f"DescribeGroupMembership reported MemberId.UserId={described['MemberId']['UserId']!r}, "
        f"expected the user this membership was created for ({user_id!r})"
    )
    assert described["IdentityStoreId"] == store_id, (
        f"DescribeGroupMembership reported IdentityStoreId={described['IdentityStoreId']!r}, "
        f"expected the identity store it was created in ({store_id!r})"
    )

    looked_up = idstore.get_group_membership_id(
        IdentityStoreId=store_id, GroupId=group_id, MemberId={"UserId": user_id}
    )
    assert looked_up["MembershipId"] == membership_id, (
        f"GetGroupMembershipId resolved MembershipId={looked_up['MembershipId']!r} for the same "
        f"GroupId/MemberId pair, expected it to match the id CreateGroupMembership returned "
        f"({membership_id!r})"
    )


# ===== self-contained helpers =====
def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]["Code"]


def _teardown(undo, *not_found: str):
    """``undo()`` where a failed delete raises; only the resource's own not-found code is "gone"."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


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
    ctx.on_cleanup(_teardown(lambda: ssoadmin.delete_instance(InstanceArn=instance_arn)))
    deadline = _time.monotonic() + 180
    while _time.monotonic() < deadline:
        resp = ssoadmin.list_instances()
        for inst in resp.get("Instances", []):
            if inst.get("InstanceArn") == instance_arn and inst.get("IdentityStoreId"):
                return inst["IdentityStoreId"]
        _time.sleep(3)
    raise AssertionError(
        "created an IAM Identity Center instance but its IdentityStoreId never appeared via "
        "list_instances within 180s",
    )


def _create_user(ctx, store_id, **kwargs):
    idstore = ctx.client("identitystore")
    display = ctx.unique_name("sim2real-user-")
    params = {
        "IdentityStoreId": store_id,
        "UserName": display,
        "DisplayName": display,
        "Name": {"GivenName": "Sim", "FamilyName": "User"},
    }
    params.update(kwargs)
    user_id = idstore.create_user(**params)["UserId"]
    ctx.on_cleanup(
        _teardown(lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=user_id), "ResourceNotFoundException")
    )
    return user_id


def _create_group(ctx, store_id, **kwargs):
    idstore = ctx.client("identitystore")
    params = {"IdentityStoreId": store_id, "DisplayName": ctx.unique_name("sim2real-group-")}
    params.update(kwargs)
    group_id = idstore.create_group(**params)["GroupId"]
    ctx.on_cleanup(
        _teardown(lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=group_id), "ResourceNotFoundException")
    )
    return group_id


def _create_membership(ctx, store_id, group_id, user_id):
    idstore = ctx.client("identitystore")
    membership_id = idstore.create_group_membership(
        IdentityStoreId=store_id, GroupId=group_id, MemberId={"UserId": user_id}
    )["MembershipId"]
    ctx.on_cleanup(
        _teardown(
            lambda: idstore.delete_group_membership(IdentityStoreId=store_id, MembershipId=membership_id),
            "ResourceNotFoundException",
        )
    )
    return membership_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
