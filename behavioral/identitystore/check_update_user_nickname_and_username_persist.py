"""update-user-nickname-and-username-persist."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-user-nickname-and-username-persist"
GROUP = "state"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """UpdateUser with multiple AttributeOperations in one call replaces each targeted attribute."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")
    user_id = idstore.create_user(
        IdentityStoreId=store_id,
        UserName=ctx.unique_name("sim2real-behav-user-"),
        DisplayName=ctx.unique_name("sim2real-behav-user-"),
        Name={"GivenName": "Ada", "FamilyName": "Byron"},
    )["UserId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=user_id)))

    new_username = ctx.unique_name("sim2real-behav-renamed-")
    idstore.update_user(
        IdentityStoreId=store_id,
        UserId=user_id,
        Operations=[
            {"AttributePath": "nickName", "AttributeValue": "Johnny"},
            {"AttributePath": "userName", "AttributeValue": new_username},
        ],
    )

    described = idstore.describe_user(IdentityStoreId=store_id, UserId=user_id)
    assert described["NickName"] == "Johnny", (
        f"expected NickName='Johnny' after multi-op UpdateUser, got {described.get('NickName')!r}"
    )
    assert described["UserName"] == new_username, (
        f"expected UserName={new_username!r} after multi-op UpdateUser, got {described.get('UserName')!r}"
    )


from botocore.exceptions import ClientError


def _get_identity_store_id(ctx):
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


def _safe_delete(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
