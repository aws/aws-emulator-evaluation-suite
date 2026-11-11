"""create-user-defaults-enabled."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-user-defaults-enabled"
GROUP = "lifecycle"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """A freshly created user is ENABLED and DescribeUser echoes the submitted attributes."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")
    username = ctx.unique_name("sim2real-behav-user-")
    resp = idstore.create_user(
        IdentityStoreId=store_id,
        UserName=username,
        DisplayName=username,
        Name={"GivenName": "Ada", "FamilyName": "Lovelace"},
    )
    user_id = resp["UserId"]
    assert resp["IdentityStoreId"] == store_id, (
        f"CreateUser echoed IdentityStoreId={resp['IdentityStoreId']!r}, expected {store_id!r}"
    )
    ctx.on_cleanup(lambda: _safe_delete(lambda: idstore.delete_user(IdentityStoreId=store_id, UserId=user_id)))

    described = idstore.describe_user(IdentityStoreId=store_id, UserId=user_id)
    assert described["UserId"] == user_id, (
        f"DescribeUser returned UserId={described['UserId']!r}, expected {user_id!r}"
    )
    assert described["UserName"] == username, (
        f"DescribeUser returned UserName={described['UserName']!r}, expected {username!r}"
    )
    assert described["DisplayName"] == username, (
        f"DescribeUser returned DisplayName={described['DisplayName']!r}, expected {username!r}"
    )
    assert described["Name"]["GivenName"] == "Ada", (
        f"DescribeUser returned GivenName={described['Name']['GivenName']!r}, expected 'Ada'"
    )
    assert described["Name"]["FamilyName"] == "Lovelace", (
        f"DescribeUser returned FamilyName={described['Name']['FamilyName']!r}, expected 'Lovelace'"
    )
    assert described["UserStatus"] == "ENABLED", (
        f"DescribeUser returned UserStatus={described['UserStatus']!r}, expected 'ENABLED'"
    )

    idstore.delete_user(IdentityStoreId=store_id, UserId=user_id)
    deleted_err = _error(lambda: idstore.describe_user(IdentityStoreId=store_id, UserId=user_id))
    assert deleted_err == ("ResourceNotFoundException", "User not found"), (
        f"DescribeUser after DeleteUser returned {deleted_err!r}, "
        "expected ResourceNotFoundException 'User not found'"
    )


from botocore.exceptions import ClientError


def _error(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected a ClientError but the call succeeded")


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
