"""delete-user-removes-memberships."""
from __future__ import annotations

import time as _time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-user-removes-memberships"
GROUP = "state"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """Deleting a user removes their group memberships (ListGroupMemberships for the group no
    longer includes it) but leaves the group itself untouched (positive control: DescribeGroup
    still succeeds)."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")

    group_display_name = ctx.unique_name("sim2real-group-")
    group_id = idstore.create_group(
        IdentityStoreId=store_id, DisplayName=group_display_name
    )["GroupId"]
    ctx.on_cleanup(_teardown(
        lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=group_id),
        "ResourceNotFoundException",
    ))
    user_id = idstore.create_user(
        IdentityStoreId=store_id,
        UserName=ctx.unique_name("sim2real-user-"),
        DisplayName=ctx.unique_name("sim2real-user-"),
        Name={"GivenName": "Delete", "FamilyName": "RemovesMembership"},
    )["UserId"]
    membership_id = idstore.create_group_membership(
        IdentityStoreId=store_id, GroupId=group_id, MemberId={"UserId": user_id}
    )["MembershipId"]

    # Positive control: the membership is describable and listed for the group before deletion.
    # Without this, a target whose ListGroupMemberships always returns [] would pass the
    # post-delete absence assertions below for the wrong reason.
    described_before = idstore.describe_group_membership(
        IdentityStoreId=store_id, MembershipId=membership_id
    )
    assert described_before["GroupId"] == group_id, (
        f"expected DescribeGroupMembership({membership_id!r}) to report GroupId={group_id!r} "
        f"before deletion, got {described_before.get('GroupId')!r}"
    )
    before = idstore.list_group_memberships(IdentityStoreId=store_id, GroupId=group_id)[
        "GroupMemberships"
    ]
    assert [m["MembershipId"] for m in before] == [membership_id], (
        f"expected ListGroupMemberships({group_id!r}) to report exactly [{membership_id!r}] "
        f"before deletion, got {[m['MembershipId'] for m in before]!r}"
    )

    idstore.delete_user(IdentityStoreId=store_id, UserId=user_id)

    code = message = None
    deadline = _time.time() + 60
    while _time.time() < deadline:
        try:
            idstore.describe_group_membership(IdentityStoreId=store_id, MembershipId=membership_id)
        except ClientError as exc:
            code, message = exc.response["Error"]["Code"], exc.response["Error"].get("Message")
            if code == "ResourceNotFoundException":
                break
        _time.sleep(3)
    assert code == "ResourceNotFoundException", (
        f"expected DescribeGroupMembership({membership_id!r}) to 404 with "
        f"ResourceNotFoundException within 60s of DeleteUser, last saw {code!r}"
    )
    assert message == "Group membership not found for given pool and membershipId.", (
        f"expected DescribeGroupMembership({membership_id!r}) to report AWS's not-found message, "
        f"got {message!r}"
    )

    remaining = idstore.list_group_memberships(IdentityStoreId=store_id, GroupId=group_id)[
        "GroupMemberships"
    ]
    assert remaining == [], (
        f"expected ListGroupMemberships({group_id!r}) to report no memberships after the "
        f"member's user was deleted, got {[m['MembershipId'] for m in remaining]!r}"
    )

    # The delete already happened above and was unasserted for the user itself — prove
    # the user, not just its membership, is gone.
    user_deleted_code, user_deleted_message = _client_error(
        lambda: idstore.describe_user(IdentityStoreId=store_id, UserId=user_id)
    )
    assert user_deleted_code == "ResourceNotFoundException", (
        f"expected DescribeUser({user_id!r}) to 404 with ResourceNotFoundException after "
        f"DeleteUser, got {user_deleted_code!r}"
    )
    assert user_deleted_message == "User not found", (
        f"expected DescribeUser({user_id!r}) after DeleteUser to say 'User not found', "
        f"got {user_deleted_message!r}"
    )

    # positive control: the group itself was not touched by the member's cascade delete
    described_group = idstore.describe_group(IdentityStoreId=store_id, GroupId=group_id)
    assert described_group["GroupId"] == group_id, (
        f"expected DescribeGroup({group_id!r}) to still succeed after the member's user was "
        f"deleted, got {described_group!r}"
    )
    assert described_group["DisplayName"] == group_display_name, (
        f"expected the surviving group's DisplayName to be unchanged "
        f"({group_display_name!r}), got {described_group.get('DisplayName')!r}"
    )


def _client_error(fn):
    """Run ``fn`` and return the (code, message) of the ClientError it raises; a success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises, unless already gone."""

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
