"""concurrent-duplicate-membership-creation-race."""
from __future__ import annotations

import time as _time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-duplicate-membership-creation-race"
GROUP = "concurrency"
SERVICES = ["identitystore"]


# A losing racer's ConflictException carries one of these two exact messages, depending on where
# it collides with the winner.
_CONFLICT_MESSAGES = ("Member and Group relationship already exists", "Membership updated by another request")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """N racing CreateGroupMembership calls for the same GroupId/MemberId pair produce exactly one
    winner; every other racer fails with ConflictException and one of its two exact messages, and
    the group lists one membership for that member, the winner's."""
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
        Name={"GivenName": "Race", "FamilyName": "Membership"},
    )["UserId"]
    ctx.on_cleanup(lambda: _safe(lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=user_id)))

    racer_count = 8

    def _racer():
        try:
            resp = idstore.create_group_membership(
                IdentityStoreId=store_id, GroupId=group_id, MemberId={"UserId": user_id}
            )
            return ("ok", resp["MembershipId"])
        except ClientError as exc:
            return ("error", exc.response["Error"]["Code"], exc.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        results = list(pool.map(lambda _i: _racer(), range(racer_count)))

    successes = [r for r in results if r[0] == "ok"]
    errors = [r for r in results if r[0] == "error"]

    assert len(successes) == 1, f"expected exactly one winner, got {successes}"
    assert len(errors) == racer_count - 1, (
        f"expected {racer_count - 1} racers to lose, got {len(errors)}: {results}"
    )
    assert all(code == "ConflictException" for _, code, _message in errors), errors
    assert all(message in _CONFLICT_MESSAGES for _, _code, message in errors), errors

    winning_membership_id = successes[0][1]
    ctx.on_cleanup(
        lambda: _safe(
            lambda: idstore.delete_group_membership(IdentityStoreId=store_id, MembershipId=winning_membership_id)
        )
    )

    memberships = idstore.list_group_memberships(IdentityStoreId=store_id, GroupId=group_id)[
        "GroupMemberships"
    ]
    matching = [m for m in memberships if m["MemberId"]["UserId"] == user_id]
    assert len(matching) == 1, f"expected exactly one membership row for {user_id}, got {matching}"
    assert matching[0]["MembershipId"] == winning_membership_id, (
        f"list_group_memberships row {matching[0]['MembershipId']!r} does not match the "
        f"race's winning MembershipId {winning_membership_id!r}"
    )


# ===== local helpers (self-contained) =====
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
