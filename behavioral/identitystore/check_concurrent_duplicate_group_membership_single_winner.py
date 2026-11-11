"""concurrent-duplicate-group-membership-single-winner."""
from __future__ import annotations

import threading

from behavioral_harness import tags

CHECK = "concurrent-duplicate-group-membership-single-winner"
GROUP = "concurrency"
SERVICES = ["identitystore"]


# A losing racer's ConflictException carries one of these two exact messages, depending on where
# it collides with the winner.
_CONFLICT_MESSAGES = ("Member and Group relationship already exists", "Membership updated by another request")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """Racing CreateGroupMembership for the same (Group, Member) pair yields exactly one winner;
    every loser fails with ConflictException and one of its two exact messages, and the group
    lists one membership, the winner's."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")
    group_id = idstore.create_group(
        IdentityStoreId=store_id, DisplayName=ctx.unique_name("sim2real-behav-group-")
    )["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=group_id)))

    user_id = idstore.create_user(
        IdentityStoreId=store_id,
        UserName=ctx.unique_name("sim2real-behav-user-"),
        DisplayName=ctx.unique_name("sim2real-behav-user-"),
        Name={"GivenName": "Race", "FamilyName": "Condition"},
    )["UserId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=user_id)))

    n_racers = 6
    successes = []
    errors = []
    lock = threading.Lock()
    barrier = threading.Barrier(n_racers)

    def racer():
        barrier.wait()
        try:
            resp = idstore.create_group_membership(
                IdentityStoreId=store_id, GroupId=group_id, MemberId={"UserId": user_id}
            )
            with lock:
                successes.append(resp["MembershipId"])
        except Exception as exc:  # noqa: BLE001 - classify below
            with lock:
                errors.append((_client_error_code(exc),
                               exc.response["Error"].get("Message") if isinstance(exc, ClientError) else repr(exc)))

    threads = [threading.Thread(target=racer) for _ in range(n_racers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(successes) == 1, f"expected exactly one winner, got {len(successes)}: {successes}"
    assert len(errors) == n_racers - 1, (
        f"expected {n_racers - 1} losers, got {len(errors)}: {errors}"
    )
    assert all(code == "ConflictException" for code, _message in errors), (
        f"expected every loser to get ConflictException, got {errors}"
    )
    assert all(message in _CONFLICT_MESSAGES for _code, message in errors), (
        f"expected every loser's message to be one of {_CONFLICT_MESSAGES}, got {errors}"
    )

    winning_membership_id = successes[0]
    ctx.on_cleanup(
        lambda: _safe_delete(
            lambda: idstore.delete_group_membership(IdentityStoreId=store_id, MembershipId=winning_membership_id)
        )
    )

    memberships = idstore.list_group_memberships(IdentityStoreId=store_id, GroupId=group_id)["GroupMemberships"]
    matching = [m for m in memberships if m["MemberId"]["UserId"] == user_id]
    assert len(matching) == 1, (
        f"expected exactly one surviving membership row for {user_id}, got {matching}"
    )
    assert matching[0]["MembershipId"] == winning_membership_id, (
        f"expected the surviving membership to be the race winner {winning_membership_id!r}, "
        f"got {matching[0]['MembershipId']!r}"
    )


from botocore.exceptions import ClientError


def _get_identity_store_id(ctx):
    import time
    from botocore.exceptions import ClientError

    sso_admin = ctx.client("sso-admin")

    def _ready_id(insts):
        for inst in insts:
            if inst.get("IdentityStoreId"):
                return inst["IdentityStoreId"]
        return None

    instances = sso_admin.list_instances().get("Instances", [])
    found = _ready_id(instances)
    if found:
        return found
    if not instances:
        try:
            sso_admin.create_instance(Name="sim2real-behav-idc")
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("ConflictException",):
                raise
    deadline = time.time() + 180
    while time.time() < deadline:
        instances = sso_admin.list_instances().get("Instances", [])
        found = _ready_id(instances)
        if found:
            return found
        time.sleep(3)
    raise AssertionError(
        "no IAM Identity Center instance could be enabled in this account/region"
    )


def _safe_delete(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _client_error_code(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"non-ClientError:{type(exc).__name__}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
