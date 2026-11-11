"""create-user-duplicate-username-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-user-duplicate-username-rejected"
GROUP = "overly-permissive"
SERVICES = ["identitystore"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """A second CreateUser with a UserName already in use is rejected; the original is untouched."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")
    username = ctx.unique_name("sim2real-behav-dup-user-")
    original_id = idstore.create_user(
        IdentityStoreId=store_id,
        UserName=username,
        DisplayName=username,
        Name={"GivenName": "First", "FamilyName": "Claimant"},
    )["UserId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=original_id)))

    err = _error(
        lambda: idstore.create_user(
            IdentityStoreId=store_id,
            UserName=username,
            DisplayName=ctx.unique_name("sim2real-behav-dup-user-other-display-"),
            Name={"GivenName": "Second", "FamilyName": "Claimant"},
        )
    )
    assert err == ("ConflictException", "Duplicate UserName"), (
        f"expected ConflictException 'Duplicate UserName' for a duplicate UserName, got {err!r}"
    )

    # Effect absent: the UserName still resolves to the ORIGINAL user, no second one was created.
    resolved = idstore.get_user_id(
        IdentityStoreId=store_id,
        AlternateIdentifier={"UniqueAttribute": {"AttributePath": "userName", "AttributeValue": username}},
    )
    assert resolved["UserId"] == original_id, (
        f"UserName {username!r} should still resolve to the original user {original_id!r}, "
        f"got {resolved['UserId']!r}"
    )
    original_given_name = idstore.describe_user(IdentityStoreId=store_id, UserId=original_id)["Name"]["GivenName"]
    assert original_given_name == "First", (
        f"the rejected duplicate CreateUser must not have mutated the original user; "
        f"expected GivenName 'First', got {original_given_name!r}"
    )

    # Positive control: a user with a genuinely different UserName still succeeds.
    control_username = ctx.unique_name("sim2real-behav-dup-user-control-")
    control_id = idstore.create_user(
        IdentityStoreId=store_id,
        UserName=control_username,
        DisplayName=control_username,
        Name={"GivenName": "Control", "FamilyName": "User"},
    )["UserId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=control_id)))
    control_username_seen = idstore.describe_user(IdentityStoreId=store_id, UserId=control_id)["UserName"]
    assert control_username_seen == control_username, (
        f"a genuinely different UserName must still be accepted; "
        f"expected {control_username!r}, got {control_username_seen!r}"
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
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_delete(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
