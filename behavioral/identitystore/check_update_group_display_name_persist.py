"""update-group-display-name-persist."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-group-display-name-persist"
GROUP = "state"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """UpdateGroup on the displayName AttributePath renames the group and old alias lookups stop resolving."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")
    old_name = ctx.unique_name("sim2real-behav-group-old-")
    group_id = idstore.create_group(IdentityStoreId=store_id, DisplayName=old_name)["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=group_id)))

    # Positive control: the unique-attribute lookup resolves the old name BEFORE the rename, so
    # the post-rename 404 below proves the index moved rather than that get_group_id never worked.
    pre_resolved = idstore.get_group_id(
        IdentityStoreId=store_id,
        AlternateIdentifier={"UniqueAttribute": {"AttributePath": "displayName", "AttributeValue": old_name}},
    )
    assert pre_resolved["GroupId"] == group_id, (
        f"expected get_group_id(old_name={old_name!r}) to resolve to {group_id!r} before the "
        f"rename, got {pre_resolved.get('GroupId')!r}"
    )

    new_name = ctx.unique_name("sim2real-behav-group-new-")
    idstore.update_group(
        IdentityStoreId=store_id,
        GroupId=group_id,
        Operations=[{"AttributePath": "displayName", "AttributeValue": new_name}],
    )

    described = idstore.describe_group(IdentityStoreId=store_id, GroupId=group_id)
    assert described["DisplayName"] == new_name, (
        f"expected DescribeGroup to reflect renamed DisplayName {new_name!r}, got "
        f"{described.get('DisplayName')!r}"
    )

    # The old display name no longer resolves via the unique-attribute lookup.
    old_lookup_code, old_lookup_message = _client_error(
        lambda: idstore.get_group_id(
            IdentityStoreId=store_id,
            AlternateIdentifier={"UniqueAttribute": {"AttributePath": "displayName", "AttributeValue": old_name}},
        )
    )
    assert old_lookup_code == "ResourceNotFoundException", (
        f"expected get_group_id(old_name={old_name!r}) to fail with ResourceNotFoundException "
        f"after the rename, got {old_lookup_code!r}"
    )
    assert old_lookup_message == "GROUP not found.", (
        f"expected AWS's exact ResourceNotFoundException message, got {old_lookup_message!r}"
    )

    # The new display name resolves to the same group.
    resolved = idstore.get_group_id(
        IdentityStoreId=store_id,
        AlternateIdentifier={"UniqueAttribute": {"AttributePath": "displayName", "AttributeValue": new_name}},
    )
    assert resolved["GroupId"] == group_id, (
        f"expected get_group_id(new_name={new_name!r}) to resolve to {group_id!r} after the "
        f"rename, got {resolved.get('GroupId')!r}"
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


def _client_error(fn):
    """Run ``fn`` and return the (code, message) of the ClientError it raises; a success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe_delete(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
