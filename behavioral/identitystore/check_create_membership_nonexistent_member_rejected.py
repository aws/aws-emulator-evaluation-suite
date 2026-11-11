"""create-membership-nonexistent-member-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "create-membership-nonexistent-member-rejected"
GROUP = "overly-permissive"
SERVICES = ["identitystore"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGroupMembership with a well-formed but non-existent MemberId is rejected; no membership is created."""
    identity_store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")

    group_id = idstore.create_group(
        IdentityStoreId=identity_store_id, DisplayName=ctx.unique_name("sim2real-behav-group-")
    )["GroupId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: idstore.delete_group(IdentityStoreId=identity_store_id, GroupId=group_id))
    )

    bogus_member_id = str(uuid.uuid4())
    err = _error(
        lambda: idstore.create_group_membership(
            IdentityStoreId=identity_store_id, GroupId=group_id, MemberId={"UserId": bogus_member_id}
        )
    )
    assert err == ("ResourceNotFoundException", "User with provided member ID not found"), (
        f"expected ResourceNotFoundException 'User with provided member ID not found', got {err!r}"
    )

    # effect absent: the group has no memberships at all
    memberships = idstore.list_group_memberships(IdentityStoreId=identity_store_id, GroupId=group_id)
    assert memberships["GroupMemberships"] == [], (
        f"expected no memberships after the rejected CreateGroupMembership, "
        f"got {memberships['GroupMemberships']!r}"
    )

    # positive control: creating a membership with a real member for the same group succeeds
    real_user_id = idstore.create_user(
        IdentityStoreId=identity_store_id,
        UserName=ctx.unique_name("sim2real-behav-user-"),
        DisplayName=ctx.unique_name("sim2real-behav-user-"),
        Name={"GivenName": "Real", "FamilyName": "Member"},
    )["UserId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: idstore.delete_user(IdentityStoreId=identity_store_id, UserId=real_user_id)
        )
    )
    membership_id = idstore.create_group_membership(
        IdentityStoreId=identity_store_id, GroupId=group_id, MemberId={"UserId": real_user_id}
    )["MembershipId"]
    desc = idstore.describe_group_membership(IdentityStoreId=identity_store_id, MembershipId=membership_id)
    assert desc["MemberId"] == {"UserId": real_user_id}, (
        f"expected the positive-control membership to bind to {real_user_id!r}, got {desc['MemberId']!r}"
    )


def _get_identity_store_id(ctx):
    """Discover the account's IAM Identity Center identity store id.

    identitystore has no CreateIdentityStore API -- every operation requires a
    pre-existing store, provisioned by enabling IAM Identity Center. Skip if
    none is enabled for this account/region.
    """
    resp = ctx.client("sso-admin").list_instances()
    instances = resp.get("Instances", [])
    if not instances:
        raise AssertionError(
            "no IAM Identity Center instance enabled for this account/region; "
            "identitystore requires a pre-existing instance (enable IAM Identity "
            "Center to obtain an IdentityStoreId) that this check cannot provision itself"
        )
    return instances[0]["IdentityStoreId"]


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
