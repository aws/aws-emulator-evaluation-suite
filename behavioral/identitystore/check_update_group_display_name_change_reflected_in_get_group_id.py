"""update-group-display-name-change-reflected-in-get-group-id."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-group-display-name-change-reflected-in-get-group-id"
GROUP = "state"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """Renaming a group via UpdateGroup moves the unique-attribute index: old name 404s, new name resolves."""
    identity_store_id = _get_identity_store_id(ctx)
    idc = ctx.client("identitystore")
    old_name = ctx.unique_name("sim2real-idstore-group-old-")
    group_id = idc.create_group(IdentityStoreId=identity_store_id, DisplayName=old_name)["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete_group(ctx, identity_store_id, group_id))

    resolved_old = idc.get_group_id(
        IdentityStoreId=identity_store_id,
        AlternateIdentifier={"UniqueAttribute": {"AttributePath": "displayName", "AttributeValue": old_name}},
    )["GroupId"]
    assert resolved_old == group_id, (
        f"GetGroupId(displayName={old_name!r}) resolved {resolved_old!r}, expected the just-created {group_id!r}"
    )

    new_name = ctx.unique_name("sim2real-idstore-group-new-")
    idc.update_group(
        IdentityStoreId=identity_store_id,
        GroupId=group_id,
        Operations=[{"AttributePath": "displayName", "AttributeValue": new_name}],
    )

    resolved_new = idc.get_group_id(
        IdentityStoreId=identity_store_id,
        AlternateIdentifier={"UniqueAttribute": {"AttributePath": "displayName", "AttributeValue": new_name}},
    )["GroupId"]
    assert resolved_new == group_id, (
        f"GetGroupId(displayName={new_name!r}) resolved {resolved_new!r} after UpdateGroup, expected {group_id!r}"
    )

    code, message = _client_error(
        lambda: idc.get_group_id(
            IdentityStoreId=identity_store_id,
            AlternateIdentifier={"UniqueAttribute": {"AttributePath": "displayName", "AttributeValue": old_name}},
        )
    )
    assert code == "ResourceNotFoundException", (
        f"GetGroupId(displayName={old_name!r}) after rename returned code {code!r}, expected "
        "ResourceNotFoundException now that the unique-attribute index has moved to the new name"
    )
    assert message == "GROUP not found.", (
        f"expected AWS's exact ResourceNotFoundException message, got {message!r}"
    )


def _get_identity_store_id(ctx) -> str:
    import time

    sso_admin = ctx.client("sso-admin")
    instances = sso_admin.list_instances().get("Instances", [])
    if instances:
        return instances[0]["IdentityStoreId"]

    try:
        created = sso_admin.create_instance(Name=ctx.unique_name("sim2real-idc-"))
    except ClientError as exc:
        raise AssertionError(
            "no IAM Identity Center instance exists and sso_admin.create_instance failed "
            f"({exc.response['Error']['Code']}); this is expected for AWS Organizations "
            "management/member accounts, which reject self-service instance creation -- run "
            "against a standalone account or an emulator that seeds a default identity store"
        ) from exc
    instance_arn = created["InstanceArn"]
    ctx.on_cleanup(lambda: _safe_delete_instance(ctx, instance_arn))

    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        for inst in sso_admin.list_instances().get("Instances", []):
            if inst.get("InstanceArn") == instance_arn and inst.get("IdentityStoreId"):
                return inst["IdentityStoreId"]
        time.sleep(2)
    raise AssertionError(
        f"created IAM Identity Center instance {instance_arn} but its IdentityStoreId never "
        "appeared via list_instances within 60s"
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


def _client_error(fn):
    """Run ``fn`` and return the (code, message) of the ClientError it raises; a success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
