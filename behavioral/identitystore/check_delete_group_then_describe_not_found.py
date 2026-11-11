"""delete-group-then-describe-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-group-then-describe-not-found"
GROUP = "state"
SERVICES = ["identitystore"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteGroup transitions the group from exists -> deleted; DescribeGroup then 404s."""
    identity_store_id = _get_identity_store_id(ctx)
    idc = ctx.client("identitystore")
    display_name = ctx.unique_name("sim2real-idstore-group-")
    group_id = idc.create_group(IdentityStoreId=identity_store_id, DisplayName=display_name)["GroupId"]
    ctx.on_cleanup(lambda: _safe(lambda: idc.delete_group(IdentityStoreId=identity_store_id, GroupId=group_id)))

    # Sanity: the group is visible before deletion.
    idc.describe_group(IdentityStoreId=identity_store_id, GroupId=group_id)

    idc.delete_group(IdentityStoreId=identity_store_id, GroupId=group_id)

    err = _error(lambda: idc.describe_group(IdentityStoreId=identity_store_id, GroupId=group_id))
    assert err == ("ResourceNotFoundException", "Group not found"), (
        f"expected ResourceNotFoundException 'Group not found' from DescribeGroup after delete, got {err!r}"
    )

    # The dead id is unusable for a mutation too, not just a read.
    update_err = _error(
        lambda: idc.update_group(
            IdentityStoreId=identity_store_id,
            GroupId=group_id,
            Operations=[{"AttributePath": "displayName", "AttributeValue": ctx.unique_name("sim2real-idstore-group-")}],
        )
    )
    assert update_err == ("ResourceNotFoundException", "Group not found"), (
        f"expected ResourceNotFoundException 'Group not found' from UpdateGroup on a deleted group, got {update_err!r}"
    )


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _get_identity_store_id(ctx) -> str:
    sso_admin = ctx.client("sso-admin")
    instances = sso_admin.list_instances().get("Instances", [])
    if not instances:
        raise AssertionError(
            "No IAM Identity Center instance is enabled in this account/region "
            "(sso-admin ListInstances returned none); enable IAM Identity Center "
            "to provision an identity store for identitystore checks."
        )
    return instances[0]["IdentityStoreId"]


def _error(fn):
    """Call fn(); return the ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
