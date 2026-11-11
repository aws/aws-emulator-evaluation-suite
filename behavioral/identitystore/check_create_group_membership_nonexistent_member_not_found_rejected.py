"""create-group-membership-nonexistent-member-not-found-rejected."""
from __future__ import annotations

import time as _time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-group-membership-nonexistent-member-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["identitystore"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """CreateGroupMembership rejects a MemberId that does not reference an existing user."""
    identity_store_id = _get_identity_store_id(ctx)
    idc = ctx.client("identitystore")

    display_name = ctx.unique_name("sim2real-idstore-group-")
    group_id = idc.create_group(IdentityStoreId=identity_store_id, DisplayName=display_name)["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete_group(ctx, identity_store_id, group_id))

    bogus_user_id = "11111111-2222-3333-4444-555555555555"
    err = _error(
        lambda: idc.create_group_membership(
            IdentityStoreId=identity_store_id, GroupId=group_id, MemberId={"UserId": bogus_user_id}
        )
    )
    assert err == ("ResourceNotFoundException", "User with provided member ID not found"), (
        f"expected ResourceNotFoundException 'User with provided member ID not found', got {err!r}"
    )

    # Effect absent: no membership was created for the nonexistent member.
    memberships = idc.list_group_memberships(IdentityStoreId=identity_store_id, GroupId=group_id)["GroupMemberships"]
    assert memberships == [], f"expected no memberships after rejected create, got {memberships!r}"

    # Positive control: CreateGroupMembership succeeds for a real, existing user.
    username = ctx.unique_name("sim2real-idstore-user-")
    real_user_id = idc.create_user(
        IdentityStoreId=identity_store_id,
        UserName=username,
        DisplayName=username,
        Name={"GivenName": "Sim", "FamilyName": "Parity"},
    )["UserId"]
    ctx.on_cleanup(lambda: _safe_delete_user(ctx, identity_store_id, real_user_id))
    idc.create_group_membership(IdentityStoreId=identity_store_id, GroupId=group_id, MemberId={"UserId": real_user_id})

    memberships_after = idc.list_group_memberships(
        IdentityStoreId=identity_store_id, GroupId=group_id
    )["GroupMemberships"]
    assert len(memberships_after) == 1, f"expected exactly 1 membership, got {memberships_after!r}"
    assert memberships_after[0]["MemberId"]["UserId"] == real_user_id, (
        f"expected membership for {real_user_id!r}, got {memberships_after[0]['MemberId']!r}"
    )


# ===== helpers =====
def _get_identity_store_id(ctx) -> str:
    sso_admin = ctx.client("sso-admin")
    try:
        resp = sso_admin.list_instances()
    except Exception as exc:
        raise AssertionError(
            f"sso-admin.list_instances is unavailable ({exc}); identitystore has no API of its "
            "own to provision an identity store, so a pre-existing (or emulator-seeded) IAM "
            "Identity Center instance is required"
        ) from exc
    instances = resp.get("Instances", [])
    instance_arn = None
    if not instances:
        try:
            created = sso_admin.create_instance(Name=ctx.unique_name("sim2real-idc-"))
        except Exception as exc:
            raise AssertionError(
                f"no IAM Identity Center instance exists and sso_admin.create_instance failed "
                f"({exc}); this is expected for AWS Organizations management/member accounts, "
                "which reject self-service instance creation -- run against a standalone account "
                "or an emulator that seeds a default identity store"
            ) from exc
        instance_arn = created["InstanceArn"]
        ctx.on_cleanup(lambda: _safe(lambda: sso_admin.delete_instance(InstanceArn=instance_arn)))
        instances = []

    def _ready_id(candidates):
        for inst in candidates:
            if instance_arn is not None and inst.get("InstanceArn") != instance_arn:
                continue
            if "IdentityStoreId" in inst:
                return inst["IdentityStoreId"]
        return None

    ready = _ready_id(instances)
    if ready is not None:
        return ready

    # Either an adopted instance or one this check just created has not finished provisioning
    # yet -- IdentityStoreId is assigned after the instance first appears via ListInstances, not
    # atomically with it, so a hard subscript on the first list_instances() response is a race.
    deadline = _time.monotonic() + 30
    while _time.monotonic() < deadline:
        resp = sso_admin.list_instances()
        ready = _ready_id(resp.get("Instances", []))
        if ready is not None:
            return ready
        _time.sleep(1)
    raise AssertionError(
        "an IAM Identity Center instance exists but its IdentityStoreId never appeared via "
        "list_instances within 30s"
    )


def _safe(fn) -> None:
    try:
        fn()
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


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
