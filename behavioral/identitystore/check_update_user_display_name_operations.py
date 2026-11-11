"""update-user-display-name-operations."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-user-display-name-operations"
GROUP = "state"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """UpdateUser applies an AttributeOperations replace on displayName; UserName is untouched."""
    identity_store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")

    user_name = ctx.unique_name("sim2real-behav-user-")
    original_display_name = "original-display-name"
    user_id = idstore.create_user(
        IdentityStoreId=identity_store_id,
        UserName=user_name,
        DisplayName=original_display_name,
        Name={"GivenName": "Display", "FamilyName": "Ops"},
    )["UserId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: idstore.delete_user(IdentityStoreId=identity_store_id, UserId=user_id))
    )

    new_display_name = "updated-display-name"
    idstore.update_user(
        IdentityStoreId=identity_store_id,
        UserId=user_id,
        Operations=[{"AttributePath": "displayName", "AttributeValue": new_display_name}],
    )

    desc = idstore.describe_user(IdentityStoreId=identity_store_id, UserId=user_id)
    assert desc["DisplayName"] == new_display_name, (
        f"expected DisplayName={new_display_name!r} after the AttributeOperations replace, "
        f"got {desc['DisplayName']!r}"
    )
    assert desc["UserName"] == user_name, (
        f"expected UserName to remain {user_name!r} (untargeted by the replace), "
        f"got {desc['UserName']!r}"
    )


def _get_identity_store_id(ctx):
    """Discover the account's IAM Identity Center identity store id.

    identitystore has no CreateIdentityStore API of its own -- every operation
    requires a pre-existing store. Adopt one if already enabled; otherwise
    provision it via sso-admin.create_instance (create-or-adopt).
    """
    import time as _time

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
            sso_admin.create_instance(Name=ctx.unique_name("sim2real-behav-idc-"))
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("ConflictException",):
                raise AssertionError(
                    f"no IAM Identity Center instance exists and sso-admin.create_instance "
                    f"failed ({exc}); this is expected for AWS Organizations "
                    "management/member accounts, which reject self-service instance "
                    "creation -- run against a standalone account or an emulator that "
                    "seeds a default identity store"
                ) from exc
    deadline = _time.monotonic() + 180
    while _time.monotonic() < deadline:
        instances = sso_admin.list_instances().get("Instances", [])
        found = _ready_id(instances)
        if found:
            return found
        _time.sleep(3)
    raise AssertionError(
        "no IAM Identity Center instance could be enabled in this account/region within 180s"
    )


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
