"""delete-group-membership-repeat-delete-idempotent."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-group-membership-repeat-delete-idempotent"
GROUP = "state"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """A second DeleteGroupMembership on an already-deleted MembershipId is idempotent (no error,
    no resurrected record) rather than raising."""
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
        Name={"GivenName": "Double", "FamilyName": "Delete"},
    )["UserId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=user_id)))

    other_user_id = idstore.create_user(
        IdentityStoreId=store_id,
        UserName=ctx.unique_name("sim2real-behav-user-other-"),
        DisplayName=ctx.unique_name("sim2real-behav-user-other-"),
        Name={"GivenName": "Control", "FamilyName": "Member"},
    )["UserId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=other_user_id)))

    membership_id = idstore.create_group_membership(
        IdentityStoreId=store_id, GroupId=group_id, MemberId={"UserId": user_id}
    )["MembershipId"]

    # First delete succeeds.
    idstore.delete_group_membership(IdentityStoreId=store_id, MembershipId=membership_id)

    # The deletion may take a moment to fully propagate; wait for DescribeGroupMembership to
    # confirm the membership is actually gone before exercising the SECOND delete.
    describe_err = _poll_error(
        lambda: idstore.describe_group_membership(IdentityStoreId=store_id, MembershipId=membership_id)
    )
    assert describe_err == ("ResourceNotFoundException", "Group membership not found for given pool and membershipId."), (
        f"expected the first delete to propagate as ResourceNotFoundException within 60s, got {describe_err!r}"
    )

    # Second delete of the SAME already-removed membership does not error (idempotent delete),
    # and does not resurrect the record.
    idstore.delete_group_membership(IdentityStoreId=store_id, MembershipId=membership_id)
    describe_err = _error(
        lambda: idstore.describe_group_membership(IdentityStoreId=store_id, MembershipId=membership_id)
    )
    assert describe_err == ("ResourceNotFoundException", "Group membership not found for given pool and membershipId."), (
        f"expected the already-deleted membership to remain absent (not resurrected) after a "
        f"second DeleteGroupMembership, got describe error {describe_err!r}"
    )

    # Positive control: creating and deleting a DIFFERENT membership still works end-to-end.
    other_membership_id = idstore.create_group_membership(
        IdentityStoreId=store_id, GroupId=group_id, MemberId={"UserId": other_user_id}
    )["MembershipId"]
    idstore.delete_group_membership(IdentityStoreId=store_id, MembershipId=other_membership_id)
    other_err = _error(
        lambda: idstore.describe_group_membership(IdentityStoreId=store_id, MembershipId=other_membership_id)
    )
    assert other_err == ("ResourceNotFoundException", "Group membership not found for given pool and membershipId."), (
        f"positive control: expected a fresh, distinct membership to delete cleanly "
        f"(ResourceNotFoundException on describe), got {other_err!r}"
    )


from botocore.exceptions import ClientError


def _get_identity_store_id(ctx):
    import time

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


def _error(fn):
    """Call fn(); return the ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _poll_error(fn, timeout_s=60):
    """Call fn() until it raises; return that ClientError (code, message). A call that keeps
    succeeding past the deadline raises, so a delete that never takes effect fails loudly."""
    import time as _poll_time

    deadline = _poll_time.time() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        if _poll_time.time() >= deadline:
            raise AssertionError(f"expected the call to fail within {timeout_s}s, but it still returned {result!r}")
        _poll_time.sleep(3)


def _safe_delete(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
