"""create-user-describe-reflects-fields."""
from __future__ import annotations

import time as _time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-user-describe-reflects-fields"
GROUP = "state"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """CreateUser persists profile attributes and defaults UserStatus to ENABLED."""
    identity_store_id = _get_identity_store_id(ctx)
    idc = ctx.client("identitystore")
    username = ctx.unique_name("sim2real-idstore-user-")
    resp = idc.create_user(
        IdentityStoreId=identity_store_id,
        UserName=username,
        DisplayName=f"{username}-display",
        Name={"GivenName": "Sim", "FamilyName": "Parity"},
    )
    user_id = resp["UserId"]
    ctx.on_cleanup(lambda: _safe_delete_user(ctx, identity_store_id, user_id))

    expected_display_name = f"{username}-display"
    desc = idc.describe_user(IdentityStoreId=identity_store_id, UserId=user_id)
    assert desc["UserName"] == username, f"expected UserName={username!r}, got {desc.get('UserName')!r}"
    assert desc["DisplayName"] == expected_display_name, (
        f"expected DisplayName={expected_display_name!r}, got {desc.get('DisplayName')!r}"
    )
    assert desc["Name"]["GivenName"] == "Sim", f"expected GivenName='Sim', got {desc['Name'].get('GivenName')!r}"
    assert desc["Name"]["FamilyName"] == "Parity", (
        f"expected FamilyName='Parity', got {desc['Name'].get('FamilyName')!r}"
    )
    assert desc["UserStatus"] == "ENABLED", f"expected UserStatus='ENABLED', got {desc.get('UserStatus')!r}"


# ===== self-contained helpers =====
def _get_identity_store_id(ctx) -> str:
    """Discover the account's IdentityStoreId, creating an IAM Identity Center instance if none exists."""
    sso_admin = ctx.client("sso-admin")
    instances = sso_admin.list_instances().get("Instances", [])
    if instances:
        return instances[0]["IdentityStoreId"]
    try:
        created = sso_admin.create_instance(Name=ctx.unique_name("sim2real-idc-"))
    except ClientError as exc:
        raise AssertionError(
            f"no IAM Identity Center instance exists and sso-admin.create_instance failed "
            f"({exc.response['Error']['Code']}); this is expected for AWS Organizations "
            "management/member accounts, which reject self-service instance creation -- run "
            "against a standalone account or an emulator that seeds a default identity store"
        ) from exc
    instance_arn = created["InstanceArn"]
    ctx.on_cleanup(lambda: _safe_delete_instance(sso_admin, instance_arn))
    deadline = _time.monotonic() + 30
    while _time.monotonic() < deadline:
        instances = sso_admin.list_instances().get("Instances", [])
        for inst in instances:
            if inst.get("InstanceArn") == instance_arn and inst.get("IdentityStoreId"):
                return inst["IdentityStoreId"]
        _time.sleep(1)
    raise AssertionError(
        "created an IAM Identity Center instance but its IdentityStoreId never appeared via "
        "list_instances within 30s",
    )


def _safe_delete_instance(sso_admin, instance_arn: str) -> None:
    try:
        sso_admin.delete_instance(InstanceArn=instance_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
