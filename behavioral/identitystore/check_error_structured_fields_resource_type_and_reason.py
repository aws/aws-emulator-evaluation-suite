"""error-structured-fields-resource-type-and-reason."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "error-structured-fields-resource-type-and-reason"
GROUP = "error-shapes"
SERVICES = ["identitystore"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _refusal(fn) -> dict:
    """The refusal ``fn`` raises: code, message and the typed error members botocore surfaces.

    An unexpected success raises too, naming what came back.
    """
    try:
        result = fn()
    except ClientError as exc:
        resp = exc.response
        return {
            "code": resp["Error"]["Code"],
            "message": resp["Error"].get("Message"),
            "ResourceType": resp.get("ResourceType"),
            "ResourceId": resp.get("ResourceId"),
            "Reason": resp.get("Reason"),
        }
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _identity_store(ctx) -> str:
    """The account's Identity Center identity store.

    Reads the prior state first: an existing instance is used as it is; with none, this check
    creates an account instance and deletes it at cleanup, restoring the state it found.
    """
    sso = ctx.client("sso-admin")
    instances = sso.list_instances()["Instances"]
    if not instances:
        arn = sso.create_instance(Name=ctx.unique_name("sim2real-behav-idc-"),
                                  Tags=[{"Key": "sim2real", "Value": CHECK}])["InstanceArn"]
        ctx.on_cleanup(lambda: _delete_instance(sso, arn))
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        for inst in sso.list_instances()["Instances"]:
            if inst.get("Status", "ACTIVE") == "ACTIVE" and inst.get("IdentityStoreId"):
                return inst["IdentityStoreId"]
        time.sleep(3)
    raise AssertionError("no ACTIVE IAM Identity Center instance with an identity store within 180s")


def _delete_instance(sso, arn: str) -> None:
    try:
        sso.delete_instance(InstanceArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    deadline = time.monotonic() + 45
    while any(i["InstanceArn"] == arn for i in sso.list_instances()["Instances"]):
        if time.monotonic() > deadline:
            raise AssertionError("the Identity Center instance this check created is still listed after 45s")
        time.sleep(2)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """Identity Store refusals carry typed members: Describe of a deleted user, group or membership
    is ResourceNotFoundException with ResourceType USER/GROUP/GROUP_MEMBERSHIP and no ResourceId;
    a duplicate UserName or membership is ConflictException UNIQUENESS_CONSTRAINT_VIOLATION.
    """
    store = _identity_store(ctx)
    ids = ctx.client("identitystore")
    username = ctx.unique_name("sim2real-behav-errf-user-")
    group_name = ctx.unique_name("sim2real-behav-errf-grp-")
    user_id = ids.create_user(IdentityStoreId=store, UserName=username, DisplayName=username,
                              Name={"GivenName": "Original", "FamilyName": "Holder"})["UserId"]
    ctx.on_cleanup(_teardown(lambda: ids.delete_user(IdentityStoreId=store, UserId=user_id),
                             "ResourceNotFoundException"))
    group_id = ids.create_group(IdentityStoreId=store, DisplayName=group_name)["GroupId"]
    ctx.on_cleanup(_teardown(lambda: ids.delete_group(IdentityStoreId=store, GroupId=group_id),
                             "ResourceNotFoundException"))
    membership_id = ids.create_group_membership(IdentityStoreId=store, GroupId=group_id,
                                                MemberId={"UserId": user_id})["MembershipId"]
    ctx.on_cleanup(_teardown(
        lambda: ids.delete_group_membership(IdentityStoreId=store, MembershipId=membership_id),
        "ResourceNotFoundException"))

    # Positive control: every resource the negatives below name is readable while it exists.
    assert ids.describe_user(IdentityStoreId=store, UserId=user_id)["UserName"] == username, (
        "DescribeUser of the live user did not return its UserName"
    )
    assert ids.describe_group(IdentityStoreId=store, GroupId=group_id)["DisplayName"] == group_name, (
        "DescribeGroup of the live group did not return its DisplayName"
    )
    live = ids.describe_group_membership(IdentityStoreId=store, MembershipId=membership_id)
    assert (live["GroupId"], live["MemberId"]) == (group_id, {"UserId": user_id}), (
        "DescribeGroupMembership of the live membership names a different group or member"
    )

    dup_user = _refusal(lambda: ids.create_user(
        IdentityStoreId=store, UserName=username, DisplayName=ctx.unique_name("sim2real-behav-errf-other-"),
        Name={"GivenName": "Second", "FamilyName": "Claimant"}))
    assert dup_user == {"code": "ConflictException", "message": "Duplicate UserName", "ResourceType": None,
                        "ResourceId": None, "Reason": "UNIQUENESS_CONSTRAINT_VIOLATION"}, (
        f"a duplicate UserName was refused with {dup_user!r}"
    )
    dup_member = _refusal(lambda: ids.create_group_membership(
        IdentityStoreId=store, GroupId=group_id, MemberId={"UserId": user_id}))
    assert dup_member == {"code": "ConflictException", "message": "Member and Group relationship already exists",
                          "ResourceType": None, "ResourceId": None,
                          "Reason": "UNIQUENESS_CONSTRAINT_VIOLATION"}, (
        f"a duplicate membership was refused with {dup_member!r}"
    )
    resolved = ids.get_user_id(IdentityStoreId=store, AlternateIdentifier={
        "UniqueAttribute": {"AttributePath": "userName", "AttributeValue": username}})["UserId"]
    assert resolved == user_id, "after the refused CreateUser the UserName resolves to a different user"
    members = [m["MemberId"] for p in ids.get_paginator("list_group_memberships").paginate(
        IdentityStoreId=store, GroupId=group_id) for m in p["GroupMemberships"]]
    assert members == [{"UserId": user_id}], (
        f"after the refused membership the group lists {len(members)} membership(s), expected 1"
    )

    ids.delete_group_membership(IdentityStoreId=store, MembershipId=membership_id)
    ids.delete_group(IdentityStoreId=store, GroupId=group_id)
    ids.delete_user(IdentityStoreId=store, UserId=user_id)

    expected = {
        "DescribeUser": (lambda: ids.describe_user(IdentityStoreId=store, UserId=user_id),
                         "User not found", "USER"),
        "DescribeGroup": (lambda: ids.describe_group(IdentityStoreId=store, GroupId=group_id),
                          "Group not found", "GROUP"),
        "DescribeGroupMembership": (
            lambda: ids.describe_group_membership(IdentityStoreId=store, MembershipId=membership_id),
            "Group membership not found for given pool and membershipId.", "GROUP_MEMBERSHIP"),
    }
    wrong = {}
    for op, (call, message, kind) in expected.items():
        got = _refusal(call)
        want = {"code": "ResourceNotFoundException", "message": message, "ResourceType": kind,
                "ResourceId": None, "Reason": None}
        if got != want:
            wrong[op] = {"expected": want, "got": got}
    assert not wrong, f"not-found refusals carry the wrong typed members: {wrong!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
