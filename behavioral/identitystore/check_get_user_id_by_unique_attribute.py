"""get-user-id-by-unique-attribute."""
from __future__ import annotations

import time as _time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-user-id-by-unique-attribute"
GROUP = "state"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """GetUserId resolves the created UserId from a userName UniqueAttribute lookup."""
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

    resolved = idc.get_user_id(
        IdentityStoreId=identity_store_id,
        AlternateIdentifier={"UniqueAttribute": {"AttributePath": "userName", "AttributeValue": username}},
    )["UserId"]

    assert resolved == user_id, f"GetUserId resolved UserId {resolved!r}, expected the created {user_id!r}"


# ===== helpers =====
def _get_identity_store_id(ctx) -> str:
    sso_admin = ctx.client("sso-admin")
    instances = sso_admin.list_instances().get("Instances", [])
    if instances:
        return instances[0]["IdentityStoreId"]
    try:
        created = sso_admin.create_instance(Name=ctx.unique_name("sim2real-idc-"))
    except ClientError as exc:
        raise AssertionError(
            "No IAM Identity Center instance is enabled in this account/region "
            f"(sso-admin ListInstances returned none) and create_instance failed ({exc}); this is "
            "expected for AWS Organizations management/member accounts, which reject self-service "
            "instance creation -- run against a standalone account or one with IAM Identity Center "
            "already enabled."
        ) from exc
    instance_arn = created["InstanceArn"]
    ctx.on_cleanup(lambda: _safe_delete_instance(ctx, instance_arn))
    deadline = _time.monotonic() + 30
    while _time.monotonic() < deadline:
        for inst in sso_admin.list_instances().get("Instances", []):
            if inst.get("InstanceArn") == instance_arn:
                store_id = inst.get("IdentityStoreId")
                if store_id:
                    return store_id
        _time.sleep(1)
    raise AssertionError(
        f"created an IAM Identity Center instance ({instance_arn}) but its IdentityStoreId never "
        "populated via sso-admin.list_instances within 30s"
    )


def _safe_delete_instance(ctx, instance_arn: str) -> None:
    sso_admin = ctx.client("sso-admin")
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
