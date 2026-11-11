"""describe-nonexistent-user-not-found."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-nonexistent-user-not-found"
GROUP = "overly-permissive"
SERVICES = ["identitystore"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """DescribeUser on a well-formed but non-existent UserId is rejected with ResourceNotFoundException."""
    identity_store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")

    bogus_user_id = str(uuid.uuid4())
    code, message = _client_error(
        lambda: idstore.describe_user(IdentityStoreId=identity_store_id, UserId=bogus_user_id)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a well-formed but non-existent UserId, got {code!r}"
    )
    assert message == "User not found", (
        f"expected AWS's exact ResourceNotFoundException message, got {message!r}"
    )

    # positive control: a real, just-created user resolves cleanly in the same store
    real_user_id = idstore.create_user(
        IdentityStoreId=identity_store_id,
        UserName=ctx.unique_name("sim2real-behav-user-"),
        DisplayName=ctx.unique_name("sim2real-behav-user-"),
        Name={"GivenName": "Real", "FamilyName": "User"},
    )["UserId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: idstore.delete_user(IdentityStoreId=identity_store_id, UserId=real_user_id)
        )
    )
    desc = idstore.describe_user(IdentityStoreId=identity_store_id, UserId=real_user_id)
    assert desc["UserId"] == real_user_id, (
        f"positive control: expected DescribeUser to resolve {real_user_id!r}, got {desc.get('UserId')!r}"
    )


def _get_identity_store_id(ctx):
    """Discover (or provision) the account's IAM Identity Center identity store id.

    identitystore has no CreateIdentityStore API of its own, but sso-admin does provide
    CreateInstance for standalone/member accounts. Create-or-adopt: use an existing instance
    if one is already enabled, otherwise create one -- tolerating ConflictException, since a
    concurrently-running sibling check may win the race to create the same account-global
    singleton instance.
    """
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
            sso_admin.create_instance(Name=ctx.unique_name("sim2real-idc-"))
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException":
                raise
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        instances = sso_admin.list_instances().get("Instances", [])
        found = _ready_id(instances)
        if found:
            return found
        time.sleep(3)
    raise AssertionError(
        "no IAM Identity Center instance could be discovered or enabled in this account/region "
        "within 180s"
    )


def _client_error(fn):
    """Run ``fn`` and return the (code, message) of the ClientError it raises; a success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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
