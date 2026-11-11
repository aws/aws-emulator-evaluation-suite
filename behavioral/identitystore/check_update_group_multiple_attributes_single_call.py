"""update-group-multiple-attributes-single-call."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-group-multiple-attributes-single-call"
GROUP = "state"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """A single UpdateGroup call with two AttributeOperations (displayName + description) applies
    both targeted attributes atomically."""
    store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")

    group_id = idstore.create_group(
        IdentityStoreId=store_id,
        DisplayName=ctx.unique_name("sim2real-behav-multiop-group-"),
        Description="original description",
    )["GroupId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: idstore.delete_group(IdentityStoreId=store_id, GroupId=group_id)))

    new_display_name = ctx.unique_name("sim2real-behav-multiop-group-renamed-")
    new_description = "updated in the same call"
    idstore.update_group(
        IdentityStoreId=store_id,
        GroupId=group_id,
        Operations=[
            {"AttributePath": "displayName", "AttributeValue": new_display_name},
            {"AttributePath": "description", "AttributeValue": new_description},
        ],
    )

    described = idstore.describe_group(IdentityStoreId=store_id, GroupId=group_id)
    assert described["DisplayName"] == new_display_name, (
        f"expected DisplayName={new_display_name!r} after a single UpdateGroup with two "
        f"AttributeOperations, got {described['DisplayName']!r}"
    )
    assert described["Description"] == new_description, (
        f"expected Description={new_description!r} after a single UpdateGroup with two "
        f"AttributeOperations, got {described['Description']!r}"
    )

    idstore.delete_group(IdentityStoreId=store_id, GroupId=group_id)
    try:
        idstore.describe_group(IdentityStoreId=store_id, GroupId=group_id)
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException after delete_group, got "
            f"{exc.response['Error']['Code']!r}"
        )
        assert exc.response["Error"].get("Message") == "Group not found", (
            f"expected DescribeGroup after delete_group to say 'Group not found', got "
            f"{exc.response['Error'].get('Message')!r}"
        )
    else:
        raise AssertionError(
            "describe_group succeeded after delete_group; the group should be gone"
        )


from botocore.exceptions import ClientError


def _get_identity_store_id(ctx):
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
