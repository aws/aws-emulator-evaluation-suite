"""update-user-immutable-userid-attribute-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-user-immutable-userid-attribute-rejected"
GROUP = "overly-permissive"
SERVICES = ["identitystore"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """UpdateUser rejects an attempt to mutate the immutable userId attribute path."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")
    username = ctx.unique_name("sim2real-behav-immutable-")
    user_id = idstore.create_user(
        IdentityStoreId=store_id,
        UserName=username,
        DisplayName=username,
        Name={"GivenName": "Immutable", "FamilyName": "Identifier"},
    )["UserId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=user_id)))

    bogus_target_id = "11111111-2222-3333-4444-555555555555"
    code, message = _error(
        lambda: idstore.update_user(
            IdentityStoreId=store_id,
            UserId=user_id,
            Operations=[{"AttributePath": "userId", "AttributeValue": bogus_target_id}],
        )
    )
    assert code == "ValidationException", f"expected ValidationException rejecting a userId mutation, got {code!r}"
    expected_message = "Updates for AttributePath: userId is not supported"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the user's identifier and profile are completely unchanged.
    described = idstore.describe_user(IdentityStoreId=store_id, UserId=user_id)
    assert described["UserId"] == user_id, f"expected UserId unchanged at {user_id!r}, got {described['UserId']!r}"
    assert described["UserName"] == username, (
        f"expected UserName unchanged at {username!r}, got {described['UserName']!r}"
    )

    # Positive control: a genuinely mutable attribute on the SAME user still updates.
    idstore.update_user(
        IdentityStoreId=store_id,
        UserId=user_id,
        Operations=[{"AttributePath": "nickName", "AttributeValue": "StillMutable"}],
    )
    after = idstore.describe_user(IdentityStoreId=store_id, UserId=user_id)
    assert after["NickName"] == "StillMutable", f"expected NickName='StillMutable', got {after.get('NickName')!r}"
    assert after["UserId"] == user_id, (
        f"expected the positive-control update to keep UserId at {user_id!r}, got {after['UserId']!r}"
    )

    # The teardown delete is a free negative: prove it actually removes the user, and that a
    # mutation on the now-dead id fails with the specific not-found code rather than succeeding.
    idstore.delete_user(IdentityStoreId=store_id, UserId=user_id)
    deleted_code, deleted_message = _error(lambda: idstore.describe_user(IdentityStoreId=store_id, UserId=user_id))
    assert deleted_code == "ResourceNotFoundException", (
        f"expected describe_user on a deleted user to raise ResourceNotFoundException, got {deleted_code!r}"
    )
    assert deleted_message == "User not found", (
        f"expected describe_user on a deleted user to say 'User not found', got {deleted_message!r}"
    )
    mutate_after_delete_code, mutate_after_delete_message = _error(
        lambda: idstore.update_user(
            IdentityStoreId=store_id,
            UserId=user_id,
            Operations=[{"AttributePath": "nickName", "AttributeValue": "ShouldNotApply"}],
        )
    )
    assert mutate_after_delete_code == "ResourceNotFoundException", (
        f"expected update_user on a deleted user to raise ResourceNotFoundException, "
        f"got {mutate_after_delete_code!r}"
    )
    assert mutate_after_delete_message == "User not found", (
        f"expected update_user on a deleted user to say 'User not found', got {mutate_after_delete_message!r}"
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
    """Call fn() and return the (code, message) of its ClientError; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _safe_delete(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
