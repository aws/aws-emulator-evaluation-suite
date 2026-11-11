"""get-group-id-by-unique-attribute."""
from __future__ import annotations

import time as _time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-group-id-by-unique-attribute"
GROUP = "state"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """GetGroupId resolves the created GroupId from a displayName UniqueAttribute lookup."""
    identity_store_id = _get_identity_store_id(ctx)
    idc = ctx.client("identitystore")
    display_name = ctx.unique_name("sim2real-idstore-group-")
    group_id = idc.create_group(IdentityStoreId=identity_store_id, DisplayName=display_name)["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete_group(ctx, identity_store_id, group_id))

    resp = idc.get_group_id(
        IdentityStoreId=identity_store_id,
        AlternateIdentifier={"UniqueAttribute": {"AttributePath": "displayName", "AttributeValue": display_name}},
    )

    assert resp["GroupId"] == group_id, (
        f"GetGroupId by displayName UniqueAttribute resolved {resp.get('GroupId')!r}, expected the "
        f"created group's id {group_id!r}"
    )
    assert resp["IdentityStoreId"] == identity_store_id, (
        f"GetGroupId returned IdentityStoreId {resp.get('IdentityStoreId')!r}, expected "
        f"{identity_store_id!r}"
    )


# ===== helpers =====
def _get_identity_store_id(ctx) -> str:
    sso_admin = ctx.client("sso-admin")
    try:
        resp = sso_admin.list_instances()
    except Exception as exc:
        raise AssertionError(
            f"sso-admin.list_instances is unavailable ({exc}); identitystore has no API of its "
            "own to provision an identity store, so a pre-existing (or emulator-seeded) IAM "
            "Identity Center instance is required"
        ) from exc
    instances = resp.get("Instances", [])
    if instances:
        return instances[0]["IdentityStoreId"]
    try:
        created = sso_admin.create_instance(Name=ctx.unique_name("sim2real-idc-"))
    except Exception as exc:
        raise AssertionError(
            "no IAM Identity Center instance exists and sso-admin.create_instance failed "
            f"({exc}); this is expected for AWS Organizations management/member accounts, which "
            "reject self-service instance creation -- run against a standalone account or an "
            "emulator that seeds a default identity store"
        ) from exc
    instance_arn = created["InstanceArn"]
    ctx.on_cleanup(lambda: _safe_delete_instance(ctx, instance_arn))
    deadline = _time.monotonic() + 60
    while _time.monotonic() < deadline:
        for inst in sso_admin.list_instances().get("Instances", []):
            if inst.get("InstanceArn") != instance_arn:
                continue
            status = inst.get("Status")
            if status == "CREATE_FAILED":
                raise AssertionError(
                    f"IAM Identity Center instance {instance_arn} moved to CREATE_FAILED "
                    f"({inst.get('StatusReason')!r}) instead of provisioning an identity store"
                )
            identity_store_id = inst.get("IdentityStoreId")
            if status == "ACTIVE" and identity_store_id:
                return identity_store_id
        _time.sleep(2)
    raise AssertionError(
        f"created IAM Identity Center instance {instance_arn} but it never reached ACTIVE with an "
        "IdentityStoreId via list_instances within 60s"
    )


def _safe_delete_instance(ctx, instance_arn: str) -> None:
    sso_admin = ctx.client("sso-admin")
    try:
        sso_admin.delete_instance(InstanceArn=instance_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_group(ctx, identity_store_id: str, group_id: str) -> None:
    idc = ctx.client("identitystore")
    try:
        idc.delete_group(IdentityStoreId=identity_store_id, GroupId=group_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
