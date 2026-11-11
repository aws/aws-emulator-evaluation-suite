"""delete-user-then-describe-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-user-then-describe-not-found"
GROUP = "state"
SERVICES = ["identitystore"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """DeleteUser transitions the user from exists -> deleted: an independent DescribeUser then
    404s, and a further mutation (UpdateUser) on the same dead id 404s the same way rather than
    resurrecting or silently no-op'ing on a nonexistent target."""
    identity_store_id = _get_identity_store_id(ctx)
    idc = ctx.client("identitystore")
    username = ctx.unique_name("sim2real-idstore-user-")
    user_id = idc.create_user(
        IdentityStoreId=identity_store_id,
        UserName=username,
        DisplayName=username,
        Name={"GivenName": "Sim", "FamilyName": "Parity"},
    )["UserId"]
    ctx.on_cleanup(lambda: _delete_if_present(idc, identity_store_id, user_id))

    # Positive control: the user is visible and describable before deletion.
    described = idc.describe_user(IdentityStoreId=identity_store_id, UserId=user_id)
    assert described["UserId"] == user_id, (
        f"expected DescribeUser to return the created user {user_id!r}, got {described.get('UserId')!r}"
    )

    idc.delete_user(IdentityStoreId=identity_store_id, UserId=user_id)

    describe_code, describe_message = _client_error(
        lambda: idc.describe_user(IdentityStoreId=identity_store_id, UserId=user_id)
    )
    assert describe_code == "ResourceNotFoundException", (
        f"expected DescribeUser on a deleted user to 404, got {describe_code!r}"
    )
    assert describe_message == "User not found", (
        f"expected DescribeUser on a deleted user to say 'User not found', got {describe_message!r}"
    )

    # A mutation on the dead id must fail the same specific way, proving the id is not merely absent
    # from reads but genuinely unusable. UpdateUser is used rather than a repeat DeleteUser because
    # DeleteUser on this API family is empirically idempotent on an already-deleted target, so a
    # second delete would not discriminate a truly-gone id from a no-op-on-anything target.
    update_code, update_message = _client_error(
        lambda: idc.update_user(
            IdentityStoreId=identity_store_id,
            UserId=user_id,
            Operations=[{"AttributePath": "nickName", "AttributeValue": "ghost"}],
        )
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected UpdateUser on a deleted user to 404, got {update_code!r}"
    )
    assert update_message == "User not found", (
        f"expected UpdateUser on a deleted user to say 'User not found', got {update_message!r}"
    )


def _get_identity_store_id(ctx) -> str:
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


def _delete_if_present(idc, identity_store_id: str, user_id: str) -> None:
    try:
        idc.delete_user(IdentityStoreId=identity_store_id, UserId=user_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _client_error(fn):
    """Run ``fn`` and return the (code, message) of the ClientError it raises; a success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
