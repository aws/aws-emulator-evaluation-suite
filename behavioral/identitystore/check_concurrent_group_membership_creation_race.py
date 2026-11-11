"""concurrent-group-membership-creation-race."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-group-membership-creation-race"
GROUP = "concurrency"
SERVICES = ["identitystore"]


# A losing racer's ConflictException carries one of these two exact messages, depending on where
# it collides with the winner.
_CONFLICT_MESSAGES = ("Member and Group relationship already exists", "Membership updated by another request")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """Racing CreateGroupMembership for the same (group, member) pair yields exactly one winner;
    every loser fails with ConflictException and one of its two exact messages, and the group
    lists one membership, the winner's."""
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

    display_name = ctx.unique_name("sim2real-idstore-group-")
    group_id = idc.create_group(IdentityStoreId=identity_store_id, DisplayName=display_name)["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete_group(ctx, identity_store_id, group_id))

    def attempt():
        try:
            resp = idc.create_group_membership(
                IdentityStoreId=identity_store_id,
                GroupId=group_id,
                MemberId={"UserId": user_id},
            )
            return ("ok", resp["MembershipId"])
        except ClientError as exc:
            return ("error", (exc.response["Error"]["Code"], exc.response["Error"].get("Message")))

    racers = 6
    with ThreadPoolExecutor(max_workers=racers) as pool:
        futures = [pool.submit(attempt) for _ in range(racers)]
        outcomes = [f.result() for f in as_completed(futures)]

    successes = [v for kind, v in outcomes if kind == "ok"]
    errors = [v[0] for kind, v in outcomes if kind == "error"]
    messages = [v[1] for kind, v in outcomes if kind == "error"]

    assert len(successes) == 1, f"expected exactly 1 winner, got {successes}"
    assert len(errors) == racers - 1, f"expected {racers - 1} losers, got {len(errors)}: {errors}"
    assert all(code == "ConflictException" for code in errors), (
        f"expected every loser to get ConflictException, got {errors}"
    )
    assert all(message in _CONFLICT_MESSAGES for message in messages), (
        f"expected every loser's message to be one of {_CONFLICT_MESSAGES}, got {messages}"
    )

    memberships = idc.list_group_memberships(IdentityStoreId=identity_store_id, GroupId=group_id)["GroupMemberships"]
    assert len(memberships) == 1, f"expected exactly 1 membership row, got {memberships}"
    assert memberships[0]["MembershipId"] == successes[0], (
        f"expected the surviving membership to be the race winner {successes[0]!r}, "
        f"got {memberships[0]['MembershipId']!r}"
    )


def _get_identity_store_id(ctx) -> str:
    """Adopt the account's IAM Identity Center instance, creating it if none exists yet.

    An account has at most one instance, and it is a permanent account-wide fixture (like a
    default VPC) rather than a per-check resource, so this never registers a cleanup to delete
    it: doing so would race every other identitystore check that also depends on it existing.
    """
    sso_admin = ctx.client("sso-admin")
    instances = sso_admin.list_instances().get("Instances", [])
    if instances:
        return instances[0]["IdentityStoreId"]
    try:
        sso_admin.create_instance(Name=ctx.unique_name("sim2real-idc-"))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ConflictException":
            raise AssertionError(
                "no IAM Identity Center instance exists and create_instance failed with "
                f"{exc.response['Error']['Code']}: {exc.response['Error']['Message']}"
            ) from exc
        # ConflictException: a concurrent check is enabling it right now -- fall through to poll.
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        instances = sso_admin.list_instances().get("Instances", [])
        if instances:
            return instances[0]["IdentityStoreId"]
        time.sleep(2)
    raise AssertionError(
        "created an IAM Identity Center instance but sso-admin.list_instances never reflected "
        "it within 60s"
    )


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
