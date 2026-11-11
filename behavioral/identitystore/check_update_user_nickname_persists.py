"""update-user-nickname-persists."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-user-nickname-persists"
GROUP = "state"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """UpdateUser with an AttributePath operation mutates the targeted attribute in place."""
    identity_store_id = _get_identity_store_id(ctx)
    idc = ctx.client("identitystore")
    username = ctx.unique_name("sim2real-idstore-user-")
    user_id = idc.create_user(
        IdentityStoreId=identity_store_id,
        UserName=username,
        DisplayName=username,
        Name={"GivenName": "Sim", "FamilyName": "Parity"},
    )["UserId"]
    ctx.on_cleanup(lambda: _safe_delete_user(ctx, identity_store_id, user_id))

    before = idc.describe_user(IdentityStoreId=identity_store_id, UserId=user_id)
    assert "NickName" not in before, f"expected no NickName on a freshly-created user, got {before.get('NickName')!r}"

    idc.update_user(
        IdentityStoreId=identity_store_id,
        UserId=user_id,
        Operations=[{"AttributePath": "nickName", "AttributeValue": "Johnny"}],
    )

    after = idc.describe_user(IdentityStoreId=identity_store_id, UserId=user_id)
    assert after["NickName"] == "Johnny", f"expected NickName='Johnny' after UpdateUser, got {after.get('NickName')!r}"
    # Unrelated attributes must be untouched by the targeted update.
    assert after["UserName"] == username, f"expected UserName to be untouched at {username!r}, got {after.get('UserName')!r}"
    assert after["DisplayName"] == username, f"expected DisplayName to be untouched at {username!r}, got {after.get('DisplayName')!r}"


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
            sso_admin.create_instance(Name=ctx.unique_name("sim2real-idc-"))
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
        "no IAM Identity Center instance could be enabled in this account/region "
        "(sso-admin ListInstances returned none after attempting CreateInstance)"
    )


def _safe_delete_user(ctx, identity_store_id: str, user_id: str) -> None:
    idc = ctx.client("identitystore")
    try:
        idc.delete_user(IdentityStoreId=identity_store_id, UserId=user_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
